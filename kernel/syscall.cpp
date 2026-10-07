// SPDX-License-Identifier: GPL-3.0-or-later
#include "task.hpp"

namespace ax {
struct LinuxStat {
    uint64_t dev,ino,nlink; uint32_t mode,uid,gid,pad;
    uint64_t rdev; int64_t size,blksize,blocks;
    uint64_t atime,atime_ns,mtime,mtime_ns,ctime,ctime_ns,reserved[3];
};
static_assert(sizeof(LinuxStat)==144);
struct Timespec { int64_t sec,nsec; };
struct Iovec { uint64_t base,length; };
struct Pollfd { int32_t fd; int16_t events,revents; };
static Handle* fd_handle(int fd) { return fd>=0 && unsigned(fd)<max_fds ? current->fds[fd].handle : nullptr; }
static int64_t copy_result(uint64_t to,const void* data,size_t size) { return current->memory.copy_out(to,data,size) ? 0 : -14; }
static bool path_at(int fd,uint64_t user,char* result) {
    char path[1024],base[1024];
    if(!current->memory.string(user,path,sizeof(path))) return false;
    if(*path=='/' || fd==-100) return normalize(current->cwd,path,result,1024);
    Handle* h=fd_handle(fd); if(!h || !h->node || (h->node->mode&0170000)!=directory) return false;
    node_path(h->node,base,sizeof(base)); return normalize(base,path,result,1024);
}
static int64_t open_file(int dirfd,uint64_t path,uint32_t flags,uint32_t mode) {
    char name[1024]; if(!path_at(dirfd,path,name)) return -14;
    auto n=lookup(name,!(flags&0400000));
    if(n && (flags&0300)==0300) return -17;
    if(!n && (flags&0100)) n=make_node(name,regular_file|((mode&0777)&~current->umask));
    if(!n) return -2;
    if((flags&0200000) && (n->mode&0170000)!=directory) return -20;
    if((n->mode&0170000)==symlink) return -40;
    if((n->mode&0170000)==directory && (flags&3)) return -21;
    if((flags&01000) && (flags&3) && (n->mode&0170000)==regular_file && !node_resize(n,0)) return -12;
    Handle* h=open_handle(n,flags); if(!h) return -23;
    int fd=allocate_fd(current,h,0,flags&02000000); if(fd<0) close_handle(h);
    return fd;
}
static int64_t stat_node(Node* n,uint64_t dst) {
    if(!n) return -2;
    LinuxStat s{}; s.dev=1; s.ino=n->inode; s.nlink=1; s.mode=n->mode; s.size=n->size; s.blksize=page_size; s.blocks=(n->size+511)/512;
    if((n->mode&0170000)==character) s.rdev=0x500;
    return copy_result(dst,&s,sizeof(s));
}
static int64_t stat_path(int dirfd,uint64_t path,uint64_t dst,bool follow) { char name[1024]; if(!path_at(dirfd,path,name)) return -14; return stat_node(lookup(name,follow),dst); }
static int64_t block(Wait why,int fd=-1,int pid=-1) { current->state=State::blocked; current->wait=why; current->wait_fd=fd; current->wait_pid=pid; return would_block; }
static int64_t io(int fd,uint64_t buf,size_t length,bool write) {
    Handle* h=fd_handle(fd); if(!h) return -9;
    if(length>0x7ffff000) length=0x7ffff000;
    if(!current->memory.valid(buf,length,!write)) return -14;
    uint8_t buffer[4096]; size_t done=0;
    while(done<length) {
        size_t n=min(length-done,sizeof(buffer));
        if(write && !current->memory.copy_in(buffer,buf+done,n)) return done ? int64_t(done) : -14;
        int64_t result=write ? write_handle(h,buffer,n) : read_handle(h,buffer,n);
        if(result<0) {
            if(done) return done;
            if(result==-11 && !(h->flags&04000)) return block(write ? Wait::write : Wait::read,fd);
            return result;
        }
        if(!write && result && !current->memory.copy_out(buf+done,buffer,result)) return -14;
        done+=result;
        if(size_t(result)<n || (!write && h->node && (h->node->mode&0170000)==character)) break;
    }
    return done;
}
static int64_t iov_io(int fd,uint64_t iov,size_t count,bool write) {
    if(count>1024) return -22;
    size_t done=0;
    for(size_t i=0;i<count;i++) {
        Iovec v; if(!current->memory.copy_in(&v,iov+i*sizeof(v),sizeof(v))) return done ? int64_t(done) : -14;
        int64_t n=io(fd,v.base,v.length,write);
        if(n<0) return done ? int64_t(done) : n;
        done+=n; if(uint64_t(n)<v.length) break;
    }
    return done;
}
static int64_t mmap_call(uint64_t addr,size_t len,int prot,int flags,int fd,uint64_t off) {
    if(!len || len>256*1024*1024 || off%page_size || !(flags&3) || (flags&3)==3 || (prot&~7)) return -22;
    len=align_up(len);
    if(flags&0x10) {
        if(addr%page_size || addr<page_size || addr>=user_limit || len>user_limit-addr) return -22;
        current->memory.unmap(addr,len);
    } else {
        addr=current->memory.next_map; current->memory.next_map+=len+page_size;
    }
    if(addr>=user_limit || len>user_limit-addr) return -12;
    Handle* h=nullptr;
    if(!(flags&0x20)) { h=fd_handle(fd); if(!h) return -9; if(!h->node || (h->node->mode&0170000)!=regular_file) return -19; }
    if(!current->memory.map(addr,len,3)) return -12;
    if(h && off<h->node->size) current->memory.copy_out(addr,h->node->data+off,min(len,h->node->size-size_t(off)));
    if(!current->memory.protect(addr,len,prot)) return -12;
    return addr;
}
static int64_t dup_fd(int old,int target,int flags=0) {
    Handle* h=fd_handle(old); if(!h) return -9;
    if(target<0 || unsigned(target)>=max_fds) return -9;
    if(target!=old) { close_handle(current->fds[target].handle); retain(h); current->fds[target]={h,bool(flags&02000000)}; }
    return target;
}
static int64_t create_pipe(uint64_t dst,int flags) {
    if(flags&~(04000|02000000)) return -22;
    if(!current->memory.valid(dst,8,true)) return -14;
    auto pipe=(Pipe*)alloc(sizeof(Pipe)); if(!pipe) return -12;
    auto reader=pipe_handle(pipe,false); auto writer=pipe_handle(pipe,true);
    if(!reader || !writer) { if(reader) close_handle(reader); if(writer) close_handle(writer); if(!reader && !writer) release(pipe); return -23; }
    reader->flags|=flags; writer->flags|=flags;
    int result[2]={allocate_fd(current,reader,0,flags&02000000),-1};
    if(result[0]>=0) result[1]=allocate_fd(current,writer,0,flags&02000000);
    if(result[0]<0 || result[1]<0) {
        if(result[0]>=0) current->fds[result[0]]={};
        close_handle(reader); close_handle(writer); return -24;
    }
    current->memory.copy_out(dst,result,sizeof(result)); return 0;
}
static int64_t wait_child(int pid,uint64_t status,int options,uint64_t usage) {
    if(status && !current->memory.valid(status,4,true)) return -14;
    bool found=false;
    for(auto& t:tasks) {
        if(t.state==State::empty || t.parent!=current->pid || (pid>0 && t.pid!=pid) || (pid==0 && t.pgid!=current->pgid) || (pid<-1 && t.pgid!=-pid)) continue;
        found=true; if(t.state!=State::zombie) continue;
        int child=t.pid;
        if(status) current->memory.copy_out(status,&t.exit_status,4);
        if(usage) { uint64_t zeros[18]{}; if(copy_result(usage,zeros,sizeof(zeros))) return -14; }
        t.memory.destroy(); t.state=State::empty; return child;
    }
    if(!found) return -10;
    if(options&1) return 0;
    return block(Wait::child,-1,pid);
}
struct ExecArgs { char path[1024],args[128][1024],env[128][1024]; const char* argv[129]; const char* envp[129]; };
static int64_t exec_user(uint64_t path,uint64_t argv,uint64_t envp,Frame* frame) {
    auto a=(ExecArgs*)alloc(sizeof(ExecArgs)); if(!a) return -12;
    int result=-14;
    if(!path_at(-100,path,a->path)) { release(a); return result; }
    auto vector=[&](uint64_t ptr,char (*strings)[1024],const char** result) -> bool {
        if(!ptr) { result[0]=nullptr; return true; }
        for(unsigned i=0;i<128;i++) {
            uint64_t p; if(!current->memory.copy_in(&p,ptr+i*8,8)) return false;
            if(!p) { result[i]=nullptr; return true; }
            if(!current->memory.string(p,strings[i],1024)) return false;
            result[i]=strings[i];
        }
        return false;
    };
    if(vector(argv,a->args,a->argv) && vector(envp,a->env,a->envp)) {
        result=exec_task(current,a->path,a->argv,a->envp);
        if(!result) *frame=current->frame;
    }
    release(a); return result;
}
static int64_t getdents(int fd,uint64_t buffer,size_t size) {
    auto h=fd_handle(fd); if(!h) return -9;
    if(!h->node || (h->node->mode&0170000)!=directory) return -20;
    size_t done=0;
    for(size_t i=h->offset;i<node_count+2;i++) {
        Node* n=i==0 ? h->node : i==1 ? (h->node->parent ? h->node->parent : h->node) : &nodes[i-2];
        if(i>=2 && (n->parent!=h->node || n->removed)) { h->offset=i+1; continue; }
        const char* name=i==0 ? "." : i==1 ? ".." : n->name;
        size_t len=strlen(name)+1,record=(19+len+7)&~size_t(7);
        if(record>size-done) return done ? int64_t(done) : -22;
        uint8_t data[160]{}; uint64_t ino=n->inode,next=i+1; uint16_t reclen=record;
        memcpy(data,&ino,8); memcpy(data+8,&next,8); memcpy(data+16,&reclen,2); data[18]=(n->mode>>12)&15; memcpy(data+19,name,len);
        if(!current->memory.copy_out(buffer+done,data,record)) return -14;
        done+=record; h->offset=i+1;
    }
    return done;
}
static int64_t ioctl_call(int fd,uint64_t request,uint64_t arg) {
    auto h=fd_handle(fd); if(!h) return -9;
    if(!h->node || (h->node->mode&0170000)!=character) return -25;
    static uint8_t termios[36]={0};
    switch(request) {
        case 0x5401: return copy_result(arg,termios,sizeof(termios));
        case 0x5402: case 0x5403: case 0x5404: return current->memory.copy_in(termios,arg,sizeof(termios)) ? 0 : -14;
        case 0x540f: return copy_result(arg,&current->pgid,4);
        case 0x5410: return current->memory.copy_in(&current->pgid,arg,4) ? 0 : -14;
        case 0x5413: { uint16_t size[]={24,80,1024,768}; return copy_result(arg,size,sizeof(size)); }
        case 0x540e: return 0; // TIOCSCTTY: the serial console is the initial controlling terminal.
        default: return -25;
    }
}
static int64_t poll_call(uint64_t pointer,size_t count,int timeout) {
    if(count>max_fds) return -22;
    int ready=0;
    for(size_t i=0;i<count;i++) {
        Pollfd p; if(!current->memory.copy_in(&p,pointer+i*sizeof(p),sizeof(p))) return -14;
        p.revents=0; auto h=fd_handle(p.fd);
        if(p.fd>=0 && !h) p.revents=32;
        else if(h) { if((p.events&1) && handle_ready(h,false)) p.revents|=1; if((p.events&4) && handle_ready(h,true)) p.revents|=4; if(h->pipe && !h->writer && !h->pipe->writers) p.revents|=16; }
        if(p.revents) ready++;
        if(copy_result(pointer+i*sizeof(p),&p,sizeof(p))) return -14;
    }
    if(ready || timeout==0) return ready;
    if(current->deadline && ticks>=current->deadline) { current->deadline=0; return 0; }
    if(timeout>0 && !current->deadline) current->deadline=ticks+(timeout+9)/10;
    return block(Wait::poll);
}
static int64_t dispatch(Frame* f) {
    uint64_t a=f->rdi,b=f->rsi,c=f->rdx,d=f->r10,e=f->r8,g=f->r9;
    switch(f->rax) {
        case 0: return io(a,b,c,false);
        case 1: return io(a,b,c,true);
        case 2: return open_file(-100,a,b,c);
        case 3: { auto h=fd_handle(a); if(!h) return -9; close_handle(h); current->fds[a]={}; return 0; }
        case 4: return stat_path(-100,a,b,true);
        case 5: { auto h=fd_handle(a); if(!h) return -9; if(h->pipe) { LinuxStat s{}; s.mode=0010600; s.nlink=1; return copy_result(b,&s,sizeof(s)); } return stat_node(h->node,b); }
        case 6: return stat_path(-100,a,b,false);
        case 7: return poll_call(a,b,c);
        case 8: {
            auto h=fd_handle(a); if(!h) return -9; if(h->pipe || !h->node || (h->node->mode&0170000)==character) return -29;
            int64_t base=c==0 ? 0 : c==1 ? int64_t(h->offset) : c==2 ? int64_t(h->node->size) : -1;
            if(base<0 || (int64_t(b)<0 && b>uint64_t(base)) || (int64_t(b)>0 && b>uint64_t(INT64_MAX-base))) return -22;
            int64_t pos=base+int64_t(b); if(pos<0) return -22; h->offset=pos; return pos;
        }
        case 9: return mmap_call(a,b,c,d,e,g);
        case 10: return current->memory.protect(a,align_up(b),c) ? 0 : -12;
        case 11: if(a%page_size || !b || a>=user_limit || b>user_limit-a) return -22; current->memory.unmap(a,align_up(b)); return 0;
        case 12:
            if(!a) return current->brk_end;
            if(a<current->brk_base || a>current->brk_base+128*1024*1024) return current->brk_end;
            if(a>current->brk_end && !current->memory.map(align_up(current->brk_end),align_up(a)-align_up(current->brk_end),3)) return current->brk_end;
            if(a<current->brk_end) current->memory.unmap(align_up(a),align_up(current->brk_end)-align_up(a));
            current->brk_end=a; return a;
        case 13:
            if(a<1 || a>64 || a==9 || a==19 || d!=8) return -22;
            if(c && copy_result(c,current->signal_actions[a-1],32)) return -14;
            if(b && !current->memory.copy_in(current->signal_actions[a-1],b,32)) return -14;
            return 0;
        case 14: {
            if(d!=8) return -22;
            if(c && copy_result(c,&current->signal_mask,8)) return -14;
            if(b) { uint64_t mask; if(!current->memory.copy_in(&mask,b,8)) return -14; mask&=~((1ull<<8)|(1ull<<18)); if(a==0) current->signal_mask|=mask; else if(a==1) current->signal_mask&=~mask; else if(a==2) current->signal_mask=mask; else return -22; }
            return 0;
        }
        case 16: return ioctl_call(a,b,c);
        case 17: case 18: {
            auto h=fd_handle(a); if(!h) return -9; uint64_t old=h->offset; h->offset=d;
            int64_t result=io(a,b,c,f->rax==18); h->offset=old; return result;
        }
        case 19: return iov_io(a,b,c,false);
        case 20: return iov_io(a,b,c,true);
        case 21: { char path[1024]; if(!path_at(-100,a,path)) return -14; auto n=lookup(path); if(!n) return -2; return (b&1) && !(n->mode&0111) ? -13 : 0; }
        case 22: return create_pipe(a,0);
        case 24: return 0;
        case 28: return current->memory.valid(a,b) ? 0 : -12;
        case 32: { auto h=fd_handle(a); if(!h) return -9; retain(h); int fd=allocate_fd(current,h); if(fd<0) close_handle(h); return fd; }
        case 33: return dup_fd(a,b);
        case 35: {
            Timespec ts; if(!current->memory.copy_in(&ts,a,sizeof(ts))) return -14;
            if(ts.sec<0 || ts.nsec<0 || ts.nsec>=1000000000) return -22;
            if(current->deadline && ticks>=current->deadline) { current->deadline=0; return 0; }
            if(!current->deadline) current->deadline=ticks+uint64_t(ts.sec)*100+(ts.nsec+9999999)/10000000;
            if(current->deadline==ticks) { current->deadline=0; return 0; }
            return block(Wait::sleep);
        }
        case 39: case 186: return current->pid;
        case 56: if((a&~uint64_t(0xff)) || b) return -38; return fork_task(f);
        case 57: case 58: return fork_task(f);
        case 59: return exec_user(a,b,c,f);
        case 60: case 231: exit_task(current,(a&255)<<8); return 0;
        case 61: return wait_child(a,b,c,d);
        case 62: {
            if(b>64) return -22;
            bool found=false;
            for(auto& t:tasks) if(t.state!=State::empty && (int(a)==t.pid || int(a)==-1 || (int(a)==0 && t.pgid==current->pgid) || (int(a)<-1 && t.pgid==-int(a)))) {
                found=true; if(b==9 || b==15) exit_task(&t,b);
                else if(b && b!=17) return -38;
            }
            return found ? 0 : -3;
        }
        case 63: { char name[6][65]{}; const char* values[]={"Axiom64","axiom64","0.1","C++ x86-64 kernel","x86_64","local"}; for(unsigned i=0;i<6;i++) memcpy(name[i],values[i],strlen(values[i])+1); return copy_result(a,name,sizeof(name)); }
        case 72: {
            auto h=fd_handle(a); if(!h) return -9;
            if(b==0 || b==1030) { retain(h); int fd=allocate_fd(current,h,c,b==1030); if(fd<0) close_handle(h); return fd; }
            if(b==1) return current->fds[a].cloexec;
            if(b==2) { current->fds[a].cloexec=c&1; return 0; }
            if(b==3) return h->flags;
            if(b==4) { h->flags=(h->flags&~uint32_t(06000))|(c&06000); return 0; }
            return -22;
        }
        case 74: case 75: return fd_handle(a) ? 0 : -9;
        case 76: { char path[1024]; if(!path_at(-100,a,path)) return -14; auto n=lookup(path); if(!n) return -2; return node_resize(n,b) ? 0 : -28; }
        case 77: { auto h=fd_handle(a); if(!h) return -9; if(!h->node || (h->flags&3)==0) return -22; return node_resize(h->node,b) ? 0 : -28; }
        case 79: { size_t n=strlen(current->cwd)+1; if(b<n) return -34; return copy_result(a,current->cwd,n) ? -14 : int64_t(n); }
        case 80: { char path[1024]; if(!path_at(-100,a,path)) return -14; auto n=lookup(path); if(!n) return -2; if((n->mode&0170000)!=directory) return -20; node_path(n,current->cwd,sizeof(current->cwd)); return 0; }
        case 81: { auto h=fd_handle(a); if(!h) return -9; if(!h->node || (h->node->mode&0170000)!=directory) return -20; node_path(h->node,current->cwd,sizeof(current->cwd)); return 0; }
        case 83: { char path[1024]; if(!path_at(-100,a,path)) return -14; if(lookup(path,false)) return -17; return make_node(path,directory|((b&0777)&~current->umask)) ? 0 : -2; }
        case 85: return open_file(-100,a,01000|0100|1,b);
        case 84: case 87: {
            char path[1024]; if(!path_at(-100,a,path)) return -14; auto n=lookup(path,false); if(!n) return -2; if(n==root_node) return -16;
            if(f->rax==84) { if((n->mode&0170000)!=directory) return -20; for(size_t i=0;i<node_count;i++) if(nodes[i].parent==n && !nodes[i].removed) return -39; }
            else if((n->mode&0170000)==directory) return -21;
            n->removed=true; return 0;
        }
        case 89: { char path[1024]; if(!path_at(-100,a,path)) return -14; auto n=lookup(path,false); if(!n) return -2; if((n->mode&0170000)!=symlink) return -22; size_t len=min(size_t(c),n->size); return copy_result(b,n->data,len) ? -14 : int64_t(len); }
        case 90: { char path[1024]; if(!path_at(-100,a,path)) return -14; auto n=lookup(path); if(!n) return -2; n->mode=(n->mode&0170000)|(b&07777); return 0; }
        case 91: { auto h=fd_handle(a); if(!h) return -9; if(!h->node) return -22; h->node->mode=(h->node->mode&0170000)|(b&07777); return 0; }
        case 95: { uint32_t old=current->umask; current->umask=a&0777; return old; }
        case 96: { uint64_t time[]={ticks/100,(ticks%100)*10000}; return a ? copy_result(a,time,sizeof(time)) : 0; }
        case 97: { uint64_t limit[]={a==7 ? max_fds : 0x7fffffffffffffffull, a==7 ? max_fds : 0x7fffffffffffffffull}; return copy_result(b,limit,sizeof(limit)); }
        case 102: case 104: case 107: case 108: return 0;
        case 109: {
            Task* target=nullptr; for(auto& t:tasks) if(t.state!=State::empty && t.pid==int(a ? a : current->pid)) target=&t;
            if(!target) return -3;
            target->pgid=b ? b : target->pid; return 0;
        }
        case 110: return current->parent;
        case 111: return current->pgid;
        case 112: current->pgid=current->pid; return current->pid;
        case 115: if(!a) return 0; return 0;
        case 121: for(auto& t:tasks) if(t.state!=State::empty && t.pid==int(a ? a : current->pid)) return t.pgid; return -3;
        case 158:
            if(a==0x1002) { if(b>=user_limit) return -1; current->fs_base=b; arch_task(b); return 0; }
            if(a==0x1003) return copy_result(b,&current->fs_base,8);
            return -22;
        case 169: if(a!=0xfee1dead || b!=672274793 || c!=0x4321fedc) return -22; poweroff(0);
        case 202: if((b&127)==1) return 0; return -38;
        case 204: { if(b<8) return -22; uint64_t cpu=1; return copy_result(c,&cpu,8) ? -14 : 8; }
        case 217: return getdents(a,b,c);
        case 218: current->tid_address=a; return current->pid;
        case 228: { if(a>7) return -22; Timespec ts{int64_t(ticks/100),int64_t(ticks%100)*10000000}; return copy_result(b,&ts,sizeof(ts)); }
        case 229: { Timespec ts{0,10000000}; return copy_result(b,&ts,sizeof(ts)); }
        case 257: return open_file(a,b,c,d);
        case 262: return stat_path(a,b,c,!(d&0x100));
        case 269: { char path[1024]; if(!path_at(a,b,path)) return -14; return lookup(path) ? 0 : -2; }
        case 273: return -38;
        case 292: if(a==b || (c&~02000000)) return -22; return dup_fd(a,b,c);
        case 293: return create_pipe(a,b);
        case 302: {
            if(a && int(a)!=current->pid) return -3;
            uint64_t limit[]={b==7 ? max_fds : 0x7fffffffffffffffull,b==7 ? max_fds : 0x7fffffffffffffffull};
            if(c) return -38;
            return d ? copy_result(d,limit,sizeof(limit)) : 0;
        }
        case 318: {
            if(c&~7) return -22;
            if(!current->memory.valid(a,b,true)) return -14;
            uint8_t bytes[256]; size_t done=0; Handle temporary{lookup("/dev/urandom"),nullptr,0,0,1,false};
            while(done<b) { size_t n=min(size_t(b-done),sizeof(bytes)); read_handle(&temporary,bytes,n); current->memory.copy_out(a+done,bytes,n); done+=n; }
            return done;
        }
        default: log("unimplemented syscall %u pid=%u\n",f->rax,uint64_t(current->pid)); return -38;
    }
}
extern "C" Frame* handle_syscall(Frame* f) {
    asm volatile("fxsave64 %0" : "=m"(current->fpu));
    uint64_t number=f->rax;
    if(trace_syscalls) log("sys pid=%u nr=%u a=%x b=%x c=%x\n",uint64_t(current->pid),number,f->rdi,f->rsi,f->rdx);
    int64_t result=dispatch(f);
    if(trace_syscalls) log("sys result=%d\n",result);
    if(result==would_block) { f->rip-=2; f->rax=number; }
    else f->rax=result;
    return schedule(f,number==24 || result==would_block || current->state!=State::runnable);
}
}
