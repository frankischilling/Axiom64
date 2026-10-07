// SPDX-License-Identifier: GPL-3.0-or-later
#include "task.hpp"

namespace ax {
Task tasks[max_tasks];
Task* current;
uint64_t ticks;
bool trace_syscalls,test_mode;
static int next_pid=1;

Task* new_task() {
    for(auto& t:tasks) if(t.state==State::empty) {
        memset(&t,0,sizeof(t)); t.pid=next_pid++; t.state=State::runnable; t.umask=0022;
        t.cwd[0]='/'; t.cwd[1]=0;
        t.fpu[0]=0x7f; t.fpu[1]=3;
        *reinterpret_cast<uint32_t*>(t.fpu+24)=0x1f80;
        return &t;
    }
    return nullptr;
}
int allocate_fd(Task* t,Handle* h,int start,bool cloexec) {
    if(start<0) return -22;
    for(unsigned i=start;i<max_fds;i++) if(!t->fds[i].handle) { t->fds[i]={h,cloexec}; return i; }
    return -24;
}
int fork_task(Frame* f) {
    Task* child=new_task(); if(!child) return -11;
    if(!child->memory.clone_from(current->memory)) { child->state=State::empty; return -12; }
    child->frame=*f; child->frame.rax=0;
    child->parent=current->pid; child->pgid=current->pgid;
    child->fs_base=current->fs_base; child->brk_base=current->brk_base; child->brk_end=current->brk_end;
    child->signal_mask=current->signal_mask; child->umask=current->umask;
    memcpy(child->cwd,current->cwd,sizeof(child->cwd)); memcpy(child->executable,current->executable,sizeof(child->executable));
    memcpy(child->fpu,current->fpu,sizeof(child->fpu));
    for(unsigned i=0;i<max_fds;i++) { child->fds[i]=current->fds[i]; retain(child->fds[i].handle); }
    return child->pid;
}
void exit_task(Task* t,int status) {
    t->exit_status=status; t->state=State::zombie;
    for(auto& fd:t->fds) { close_handle(fd.handle); fd={}; }
    if(t->tid_address) { uint32_t zero=0; t->memory.copy_out(t->tid_address,&zero,4); }
    for(auto& child:tasks) if(child.parent==t->pid && child.state!=State::empty) child.parent=1;
    if(t->pid==1) { if(test_mode) poweroff((status>>8)&255); panic("init exited"); }
}
static bool awaken(Task& t) {
    if(t.state!=State::blocked) return t.state==State::runnable;
    bool ready=false;
    switch(t.wait) {
        case Wait::read: case Wait::write:
            ready=t.wait_fd<0 || unsigned(t.wait_fd)>=max_fds || handle_ready(t.fds[t.wait_fd].handle,t.wait==Wait::write); break;
        case Wait::child:
            for(auto& c:tasks) if(c.parent==t.pid && c.state==State::zombie && (t.wait_pid<=0 || c.pid==t.wait_pid)) ready=true;
            break;
        case Wait::sleep: ready=ticks>=t.deadline; break;
        case Wait::poll: ready=true; break;
        default: ready=true; break;
    }
    if(ready) { t.state=State::runnable; t.wait=Wait::none; }
    return ready;
}
Frame* schedule(Frame* f,bool yield) {
    if(current && f) { current->frame=*f; asm volatile("fxsave64 %0" : "=m"(current->fpu)); }
    if(current && current->state==State::runnable && !yield) return &current->frame;
    unsigned start=current ? unsigned(current-tasks)+1 : 0;
    for(;;) {
        for(unsigned i=0;i<max_tasks;i++) {
            Task* t=&tasks[(start+i)%max_tasks];
            if(!awaken(*t)) continue;
            current=t; write_cr3(t->memory.root); arch_task(t->fs_base);
            asm volatile("fxrstor64 %0" :: "m"(t->fpu));
            return &t->frame;
        }
        // No kernel continuation is retained across a task switch.
        // Timer interrupts during this idle loop only advance the clock.
        asm volatile("sti; hlt; cli" ::: "memory");
    }
}

struct ElfHeader {
    uint8_t ident[16]; uint16_t type,machine; uint32_t version;
    uint64_t entry,phoff,shoff; uint32_t flags;
    uint16_t ehsize,phentsize,phnum,shentsize,shnum,shstrndx;
};
struct ProgramHeader { uint32_t type,flags; uint64_t offset,vaddr,paddr,filesz,memsz,align; };
struct Image { uint64_t entry,phdr,phnum,end,base; char interpreter[1024]; };
static int load_image(AddressSpace& mem,Node* file,uint64_t base,Image& image) {
    if(!file || (file->mode&0170000)!=regular_file) return -2;
    if(file->size<sizeof(ElfHeader)) return -8;
    auto h=(const ElfHeader*)file->data;
    if(memcmp(h->ident,"\177ELF\2\1\1",7) || h->machine!=62 || h->version!=1 || (h->type!=2 && h->type!=3)) return -8;
    if(h->ehsize!=sizeof(ElfHeader) || h->phentsize!=sizeof(ProgramHeader) || !h->phnum || h->phnum>128 || h->phoff>file->size || h->phnum>(file->size-h->phoff)/sizeof(ProgramHeader)) return -8;
    if(h->type==2) base=0;
    image={}; image.entry=base+h->entry; image.phnum=h->phnum; image.base=base;
    bool executable=false;
    auto ph=(const ProgramHeader*)(file->data+h->phoff);
    for(unsigned i=0;i<h->phnum;i++) {
        auto p=ph[i];
        if(p.offset>file->size || p.filesz>file->size-p.offset) return -8;
        if(p.type==3) {
            if(p.filesz<2 || p.filesz>sizeof(image.interpreter) || file->data[p.offset+p.filesz-1]) return -8;
            memcpy(image.interpreter,file->data+p.offset,p.filesz); continue;
        }
        if(p.type!=1 || !p.memsz) continue;
        if(p.filesz>p.memsz || p.vaddr>=user_limit || base>user_limit-p.vaddr) return -8;
        uint64_t va=base+p.vaddr;
        if(va<page_size || p.memsz>user_limit-va || p.memsz>256*1024*1024 || (p.align>1 && ((p.align&(p.align-1)) || (p.vaddr-p.offset)%p.align))) return -8;
        if(!mem.map(align_down(va),align_up(va+p.memsz)-align_down(va),7)) return -12;
        if(!mem.copy_out(va,file->data+p.offset,p.filesz)) return -8;
        image.end=max(image.end,va+p.memsz);
        if(h->phoff>=p.offset && h->phoff+uint64_t(h->phnum)*sizeof(ProgramHeader)<=p.offset+p.filesz) image.phdr=va+h->phoff-p.offset;
        if((p.flags&1) && image.entry>=va && image.entry<va+p.memsz) executable=true;
    }
    if(!executable || !image.phdr) return -8;
    for(unsigned i=0;i<h->phnum;i++) if(ph[i].type==1 && ph[i].memsz) {
        auto p=ph[i]; int prot=((p.flags&4) ? 1 : 0)|((p.flags&2) ? 2 : 0)|((p.flags&1) ? 4 : 0);
        if(!mem.protect(align_down(base+p.vaddr),align_up(base+p.vaddr+p.memsz)-align_down(base+p.vaddr),prot)) return -8;
    }
    return 0;
}
int exec_task(Task* t,const char* path,const char* const* argv,const char* const* envp) {
    Node* file=lookup(path); if(!file) return -2;
    AddressSpace memory; if(!memory.create()) return -12;
    Image image{},interp{};
    int error=load_image(memory,file,0x400000,image);
    if(error) { memory.destroy(); return error; }
    uint64_t entry=image.entry;
    if(image.interpreter[0]) {
        error=load_image(memory,lookup(image.interpreter),0x7000000000,interp);
        if(error || interp.interpreter[0]) { memory.destroy(); return error ? error : -8; }
        entry=interp.entry;
    }
    constexpr uint64_t stack_top=0x700000000000,stack_size=2*1024*1024;
    if(!memory.map(stack_top-stack_size,stack_size,3)) { memory.destroy(); return -12; }
    uint64_t sp=stack_top, args[128],env[128]; size_t argc=0,envc=0;
    auto push_string=[&](const char* s) -> uint64_t {
        size_t len=strlen(s)+1; if(len>sp-(stack_top-stack_size)) return 0;
        sp-=len; return memory.copy_out(sp,s,len) ? sp : 0;
    };
    for(;argv && argv[argc];argc++) {
        if(argc==127 || !(args[argc]=push_string(argv[argc]))) { memory.destroy(); return -7; }
    }
    for(;envp && envp[envc];envc++) {
        if(envc==127 || !(env[envc]=push_string(envp[envc]))) { memory.destroy(); return -7; }
    }
    uint64_t platform=push_string("x86_64"),execfn=push_string(path);
    uint8_t random[16]; uint64_t seed; asm volatile("rdtsc" : "=a"(seed) :: "rdx");
    for(auto& byte:random) { seed^=seed<<13; seed^=seed>>7; seed^=seed<<17; byte=seed; }
    sp-=16; uint64_t randptr=sp; memory.copy_out(sp,random,16);
    uint64_t aux[]={3,image.phdr,4,sizeof(ProgramHeader),5,image.phnum,6,page_size,7,interp.base,8,0,9,image.entry,11,0,12,0,13,0,14,0,15,platform,17,100,23,0,25,randptr,31,execfn,0,0};
    size_t bytes=(1+argc+1+envc+1)*8+sizeof(aux);
    sp=(sp-bytes)&~15ull;
    uint64_t cursor=sp, value=argc;
    memory.copy_out(cursor,&value,8); cursor+=8;
    for(size_t i=0;i<argc;i++) { memory.copy_out(cursor,&args[i],8); cursor+=8; }
    value=0; memory.copy_out(cursor,&value,8); cursor+=8;
    for(size_t i=0;i<envc;i++) { memory.copy_out(cursor,&env[i],8); cursor+=8; }
    memory.copy_out(cursor,&value,8); cursor+=8; memory.copy_out(cursor,aux,sizeof(aux));
    AddressSpace old=t->memory; t->memory=memory;
    if(t==current) write_cr3(memory.root);
    old.destroy();
    t->frame={}; t->frame.rip=entry; t->frame.rsp=sp; t->frame.cs=0x23; t->frame.ss=0x1b; t->frame.rflags=0x202;
    t->fs_base=0; t->brk_base=t->brk_end=align_up(image.end); t->tid_address=0;
    memcpy(t->executable,path,min(strlen(path)+1,sizeof(t->executable)));
    for(auto& fd:t->fds) if(fd.cloexec) { close_handle(fd.handle); fd={}; }
    if(t==current) arch_task(0);
    log("exec pid=%u %s (%s)\n",uint64_t(t->pid),path,image.interpreter[0] ? "dynamic musl" : "static ELF");
    return 0;
}
void start_init(const char* path) {
    Task* init=new_task(); if(!init) panic("init allocation"); init->pgid=init->pid;
    auto console=lookup("/dev/console");
    for(unsigned i=0;i<3;i++) init->fds[i].handle=open_handle(console,i ? 1 : 0);
    const char* args[]={path,nullptr};
    const char* env[]={"PATH=/bin:/usr/bin:/sbin:/usr/sbin","HOME=/root","TERM=vt100",test_mode ? "AXIOM64_TEST=1" : "AXIOM64_TEST=0",nullptr};
    if(exec_task(init,path,args,env)) panic("cannot execute init");
    enter_user(schedule(nullptr,true));
}
extern "C" Frame* handle_trap(Frame* f) {
    if(f->vector==32) {
        ticks++; out8(0x20,0x20);
        if((f->cs&3)==3 && current) return schedule(f,true);
        return f;
    }
    if(f->vector>=32) { out8(0x20,0x20); return f; }
    uint64_t cr2=0; asm volatile("mov %%cr2,%0" : "=r"(cr2));
    log("FAULT vector=%u error=%x rip=%x address=%x pid=%u\n",f->vector,f->error,f->rip,cr2,uint64_t(current ? current->pid : 0));
    if((f->cs&3)==3 && current) { exit_task(current,11); return schedule(f,true); }
    panic("kernel exception");
}
}
