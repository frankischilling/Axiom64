// SPDX-License-Identifier: GPL-3.0-or-later
#include "task.hpp"
#include "devices.hpp"
#include "ipc.hpp"
#include "signals.hpp"

namespace ax {
Task tasks[max_tasks];
Task* current;
uint64_t ticks;
bool trace_syscalls, test_mode;
const char* test_suite = "AXIOM64_SUITE=full";
static int next_pid = 1;

Task* new_task() {
    for (auto& t : tasks)
        if (t.state == State::empty) {
            memset(&t, 0, sizeof(t));
            t.pid = next_pid++;
            t.state = State::runnable;
            t.umask = 0022;
            t.cwd[0] = '/';
            t.cwd[1] = 0;
            t.fpu[0] = 0x7f;
            t.fpu[1] = 3;
            *reinterpret_cast<uint32_t*>(t.fpu + 24) = 0x1f80;
            return &t;
        }
    return nullptr;
}
int allocate_fd(Task* t, Handle* h, int start, bool cloexec) {
    if (start < 0)
        return -22;
    for (unsigned i = start; i < max_fds; i++)
        if (!t->fds[i].handle) {
            t->fds[i] = {h, cloexec};
            return i;
        }
    return -24;
}
int fork_task(Frame* f, bool share, uint64_t stack) {
    Task* child = new_task();
    if (!child)
        return -11;
    if (share) {
        child->memory = current->memory;
        child->memory_shared = true;
        child->vfork_parent = current->pid;
    } else if (!child->memory.clone_from(current->memory)) {
        child->state = State::empty;
        return -12;
    }
    child->frame = *f;
    child->frame.rax = 0;
    if (stack)
        child->frame.rsp = stack;
    child->parent = current->pid;
    child->pgid = current->pgid;
    child->sid = current->sid;
    child->controlling_pty = current->controlling_pty;
    child->controlling_console = current->controlling_console;
    child->fs_base = current->fs_base;
    child->brk_base = current->brk_base;
    child->brk_end = current->brk_end;
    child->signal_mask = current->signal_mask;
    child->altstack_base = current->altstack_base;
    child->altstack_size = current->altstack_size;
    child->umask = current->umask;
    memcpy(child->signal_actions, current->signal_actions, sizeof(child->signal_actions));
    memcpy(child->cwd, current->cwd, sizeof(child->cwd));
    memcpy(child->executable, current->executable, sizeof(child->executable));
    memcpy(child->fpu, current->fpu, sizeof(child->fpu));
    for (unsigned i = 0; i < max_fds; i++) {
        child->fds[i] = current->fds[i];
        retain(child->fds[i].handle);
    }
    shared_memory_fork(child, current);
    if (share) {
        current->state = State::blocked;
        current->wait = Wait::vfork;
        current->wait_pid = child->pid;
    }
    return child->pid;
}
void exit_task(Task* t, int status) {
    t->exit_status = status;
    terminal_exit(t);
    shared_memory_release(t);
    t->state = State::zombie;
    for (auto& fd : t->fds) {
        close_handle(fd.handle);
        fd = {};
    }
    if (t->tid_address) {
        uint32_t zero = 0;
        t->memory.copy_out(t->tid_address, &zero, 4);
    }
    for (auto& child : tasks)
        if (child.parent == t->pid && child.state != State::empty)
            child.parent = 1;
    t->vfork_parent = 0;
    for (auto& parent : tasks)
        if (parent.pid == t->parent && parent.state != State::empty)
            queue_signal(&parent, 17, t->pid, (status & 127) ? 2 : 1,
                         (status & 127) ? status & 127 : status >> 8);
    if (t->pid == 1) {
        if (test_mode)
            poweroff((status & 127) ? 128 + (status & 127) : (status >> 8) & 255);
        panic("init exited");
    }
}
static bool awaken(Task& t) {
    if (t.state != State::blocked)
        return t.state == State::runnable;
    if (signal_wakes(t)) {
        signal_interrupt(t);
        return true;
    }
    bool ready = false;
    switch (t.wait) {
    case Wait::read:
    case Wait::write:
        ready = t.wait_fd < 0 || unsigned(t.wait_fd) >= max_fds ||
                handle_ready(t.fds[t.wait_fd].handle, t.wait == Wait::write);
        break;
    case Wait::child:
        for (auto& c : tasks)
            if (c.parent == t.pid &&
                (c.state == State::zombie ||
                 (c.state == State::stopped && !c.stop_reported && (t.frame.rdx & 2)) ||
                 (c.continued && (t.frame.rdx & 8))) &&
                (t.wait_pid > 0    ? c.pid == t.wait_pid
                 : t.wait_pid == 0 ? c.pgid == t.pgid
                 : t.wait_pid < -1 ? c.pgid == -t.wait_pid
                                   : true))
                ready = true;
        break;
    case Wait::sleep:
        ready = ticks >= t.deadline;
        break;
    case Wait::poll:
        ready = poll_task_ready(t);
        break;
    case Wait::vfork:
        ready = true;
        for (auto& c : tasks)
            if (c.pid == t.wait_pid && c.vfork_parent == t.pid)
                ready = false;
        break;
    case Wait::signal:
        break;
    default:
        ready = true;
        break;
    }
    if (ready) {
        t.state = State::runnable;
        t.wait = Wait::none;
    }
    return ready;
}
Frame* schedule(Frame* f, bool yield) {
    if (current && f) {
        current->frame = *f;
        asm volatile("fxsave64 %0" : "=m"(current->fpu));
    }
    if (current && current->state == State::runnable && !yield && signal_deliver(*current))
        return &current->frame;
    unsigned start = current ? unsigned(current - tasks) + 1 : 0;
    for (;;) {
        for (unsigned i = 0; i < max_tasks; i++) {
            Task* t = &tasks[(start + i) % max_tasks];
            if (!awaken(*t))
                continue;
            if (!signal_deliver(*t))
                continue;
            current = t;
            write_cr3(t->memory.root);
            arch_task(t->fs_base);
            asm volatile("fxrstor64 %0" ::"m"(t->fpu));
            return &t->frame;
        }
        // No kernel continuation is retained across a task switch.
        // Timer interrupts during this idle loop only advance the clock.
        asm volatile("sti; hlt; cli" ::: "memory");
    }
}

struct ElfHeader {
    uint8_t ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};
struct ProgramHeader {
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
};
struct Image {
    uint64_t entry, phdr, phnum, end, base;
    char interpreter[1024];
};
static int load_image(AddressSpace& mem, Node* file, uint64_t base, Image& image) {
    if (!file || (file->mode & 0170000) != regular_file)
        return -2;
    if (file->size < sizeof(ElfHeader))
        return -8;
    auto h = (const ElfHeader*)file->data;
    if (memcmp(h->ident, "\177ELF\2\1\1", 7) || h->machine != 62 || h->version != 1 ||
        (h->type != 2 && h->type != 3))
        return -8;
    if (h->ehsize != sizeof(ElfHeader) || h->phentsize != sizeof(ProgramHeader) || !h->phnum ||
        h->phnum > 128 || h->phoff > file->size ||
        h->phnum > (file->size - h->phoff) / sizeof(ProgramHeader))
        return -8;
    if (h->type == 2)
        base = 0;
    image = {};
    image.entry = base + h->entry;
    image.phnum = h->phnum;
    image.base = base;
    bool executable = false;
    auto ph = (const ProgramHeader*)(file->data + h->phoff);
    for (unsigned i = 0; i < h->phnum; i++) {
        auto p = ph[i];
        if (p.offset > file->size || p.filesz > file->size - p.offset)
            return -8;
        if (p.type == 3) {
            if (p.filesz < 2 || p.filesz > sizeof(image.interpreter) ||
                file->data[p.offset + p.filesz - 1])
                return -8;
            memcpy(image.interpreter, file->data + p.offset, p.filesz);
            continue;
        }
        if (p.type != 1 || !p.memsz)
            continue;
        if (p.filesz > p.memsz || p.vaddr >= user_limit || base > user_limit - p.vaddr)
            return -8;
        uint64_t va = base + p.vaddr;
        if (va < page_size || p.memsz > user_limit - va || p.memsz > 256 * 1024 * 1024 ||
            (p.align > 1 && ((p.align & (p.align - 1)) || (p.vaddr - p.offset) % p.align)))
            return -8;
        if (!mem.map(align_down(va), align_up(va + p.memsz) - align_down(va), 7))
            return -12;
        if (!mem.copy_out(va, file->data + p.offset, p.filesz))
            return -8;
        image.end = max(image.end, va + p.memsz);
        if (h->phoff >= p.offset &&
            h->phoff + uint64_t(h->phnum) * sizeof(ProgramHeader) <= p.offset + p.filesz)
            image.phdr = va + h->phoff - p.offset;
        if ((p.flags & 1) && image.entry >= va && image.entry < va + p.memsz)
            executable = true;
    }
    if (!executable || !image.phdr)
        return -8;
    for (unsigned i = 0; i < h->phnum; i++)
        if (ph[i].type == 1 && ph[i].memsz) {
            auto p = ph[i];
            int prot = ((p.flags & 4) ? 1 : 0) | ((p.flags & 2) ? 2 : 0) | ((p.flags & 1) ? 4 : 0);
            if (!mem.protect(align_down(base + p.vaddr),
                             align_up(base + p.vaddr + p.memsz) - align_down(base + p.vaddr), prot))
                return -8;
        }
    return 0;
}
int exec_task(Task* t, const char* path, const char* const* argv, const char* const* envp) {
    Node* file = file_node(lookup(path));
    if (!file)
        return -2;
    AddressSpace memory;
    if (!memory.create())
        return -12;
    Image image{}, interp{};
    int error = load_image(memory, file, 0x400000, image);
    if (error) {
        memory.destroy();
        return error;
    }
    uint64_t entry = image.entry;
    if (image.interpreter[0]) {
        error = load_image(memory, file_node(lookup(image.interpreter)), 0x7000000000, interp);
        if (error || interp.interpreter[0]) {
            memory.destroy();
            return error ? error : -8;
        }
        entry = interp.entry;
    }
    constexpr uint64_t stack_top = 0x700000000000, stack_size = 2 * 1024 * 1024;
    if (!memory.map(stack_top - stack_size, stack_size, 3)) {
        memory.destroy();
        return -12;
    }
    const uint8_t trampoline[] = {0x48, 0xc7, 0xc0, 15, 0, 0, 0, 0x0f, 0x05};
    if (!memory.map(signal_trampoline, page_size, 3) ||
        !memory.copy_out(signal_trampoline, trampoline, sizeof(trampoline)) ||
        !memory.protect(signal_trampoline, page_size, 5)) {
        memory.destroy();
        return -12;
    }
    uint64_t sp = stack_top, args[128], env[128];
    size_t argc = 0, envc = 0;
    auto push_string = [&](const char* s) -> uint64_t {
        size_t len = strlen(s) + 1;
        if (len > sp - (stack_top - stack_size))
            return 0;
        sp -= len;
        return memory.copy_out(sp, s, len) ? sp : 0;
    };
    for (; argv && argv[argc]; argc++) {
        if (argc == 127 || !(args[argc] = push_string(argv[argc]))) {
            memory.destroy();
            return -7;
        }
    }
    for (; envp && envp[envc]; envc++) {
        if (envc == 127 || !(env[envc] = push_string(envp[envc]))) {
            memory.destroy();
            return -7;
        }
    }
    uint64_t platform = push_string("x86_64"), execfn = push_string(path);
    uint8_t random[16];
    uint64_t seed;
    asm volatile("rdtsc" : "=a"(seed)::"rdx");
    for (auto& byte : random) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        byte = seed;
    }
    sp -= 16;
    uint64_t randptr = sp;
    memory.copy_out(sp, random, 16);
    uint64_t aux[] = {3,  image.phdr,
                      4,  sizeof(ProgramHeader),
                      5,  image.phnum,
                      6,  page_size,
                      7,  interp.base,
                      8,  0,
                      9,  image.entry,
                      11, 0,
                      12, 0,
                      13, 0,
                      14, 0,
                      15, platform,
                      17, 100,
                      23, 0,
                      25, randptr,
                      31, execfn,
                      0,  0};
    size_t bytes = (1 + argc + 1 + envc + 1) * 8 + sizeof(aux);
    sp = (sp - bytes) & ~15ull;
    uint64_t cursor = sp, value = argc;
    memory.copy_out(cursor, &value, 8);
    cursor += 8;
    for (size_t i = 0; i < argc; i++) {
        memory.copy_out(cursor, &args[i], 8);
        cursor += 8;
    }
    value = 0;
    memory.copy_out(cursor, &value, 8);
    cursor += 8;
    for (size_t i = 0; i < envc; i++) {
        memory.copy_out(cursor, &env[i], 8);
        cursor += 8;
    }
    memory.copy_out(cursor, &value, 8);
    cursor += 8;
    memory.copy_out(cursor, aux, sizeof(aux));
    AddressSpace old = t->memory;
    if (!t->memory_shared)
        shared_memory_release(t);
    t->memory = memory;
    if (t == current)
        write_cr3(memory.root);
    if (!t->memory_shared)
        old.destroy();
    t->memory_shared = false;
    t->vfork_parent = 0;
    t->frame = {};
    t->frame.rip = entry;
    t->frame.rsp = sp;
    t->frame.cs = 0x23;
    t->frame.ss = 0x1b;
    t->frame.rflags = 0x202;
    t->fs_base = 0;
    t->brk_base = t->brk_end = align_up(image.end);
    t->tid_address = 0;
    t->altstack_base = t->altstack_size = 0;
    for (auto& action : t->signal_actions)
        if (action[0] != 1)
            memset(action, 0, sizeof(action));
    memcpy(t->executable, path, min(strlen(path) + 1, sizeof(t->executable)));
    for (auto& fd : t->fds)
        if (fd.cloexec) {
            close_handle(fd.handle);
            fd = {};
        }
    if (t == current)
        arch_task(0);
    log("exec pid=%u %s (%s)\n", uint64_t(t->pid), path,
        image.interpreter[0] ? "dynamic musl" : "static ELF");
    return 0;
}
void start_init(const char* path) {
    Task* init = new_task();
    if (!init)
        panic("init allocation");
    init->pgid = init->pid;
    init->sid = init->pid;
    init->controlling_console = true;
    auto console = lookup("/dev/console");
    for (unsigned i = 0; i < 3; i++)
        init->fds[i].handle = open_handle(console, i ? 1 : 0);
    const char* args[] = {path, nullptr};
    const char* env[] = {"PATH=/bin:/usr/bin:/sbin:/usr/sbin",
                         "HOME=/root",
                         "TERM=vt100",
                         test_mode ? "AXIOM64_TEST=1" : "AXIOM64_TEST=0",
                         test_suite,
                         nullptr};
    if (exec_task(init, path, args, env))
        panic("cannot execute init");
    enter_user(schedule(nullptr, true));
}
extern "C" Frame* handle_trap(Frame* f) {
    if (f->vector == 32) {
        ticks++;
        devices_poll();
        epoll_notify();
        signal_tick();
        out8(0x20, 0x20);
        if ((f->cs & 3) == 3 && current)
            return schedule(f, true);
        return f;
    }
    if (f->vector >= 32) {
        out8(0x20, 0x20);
        return f;
    }
    uint64_t cr2 = 0;
    asm volatile("mov %%cr2,%0" : "=r"(cr2));
    if ((f->cs & 3) == 3 && current) {
        int signal = f->vector == 0 || f->vector == 16 || f->vector == 19 ? 8
                     : f->vector == 6                                     ? 4
                     : f->vector == 1 || f->vector == 3                   ? 5
                                                                          : 11;
        log("User exception: vector=%u rip=%x address=%x pid=%u signal=%u\n", f->vector, f->rip,
            cr2, uint64_t(current->pid), uint64_t(signal));
        if (current->signal_mask & (1ull << (signal - 1)) ||
            current->signal_actions[signal - 1][0] == 1)
            exit_task(current, signal);
        else
            queue_signal(current, signal, 0, f->vector == 14 ? (f->error & 1) ? 2 : 1 : 1, 0,
                         f->vector == 14 ? cr2 : f->rip);
        return schedule(f, true);
    }
    log("FAULT vector=%u error=%x rip=%x address=%x pid=%u\n", f->vector, f->error, f->rip, cr2,
        uint64_t(current ? current->pid : 0));
    panic("kernel exception");
}
} // namespace ax
