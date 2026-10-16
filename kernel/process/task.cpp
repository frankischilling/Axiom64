// SPDX-License-Identifier: GPL-3.0-or-later
#include "process/task.hpp"
#include "process/exec_arguments.hpp"
#include "fs/record_lock.hpp"
#include "process/waitid.hpp"
#include "fs/descriptor.hpp"
#include "drivers/platform/devices.hpp"
#include "ipc/ipc.hpp"
#include "process/signals.hpp"
#include "process/futex.hpp"
#include "io/io.hpp"
#include "net/ethernet.hpp"
#include "core/time.hpp"
#include "core/random.hpp"
#include "core/random/primitives.hpp"
#include "fs/xattr.hpp"
#include "security/file_capabilities.hpp"

namespace ax {
Task tasks[max_tasks];
Task* current;
bool trace_syscalls, test_mode;
const char* test_suite = "AXIOM64_SUITE=full";
const char* test_phase = "AXIOM64_PHASE=none";
static int next_pid = 1;

template <class T> static T* make_resource() {
    auto result = static_cast<T*>(alloc(sizeof(T)));
    if (result)
        *result = T{};
    return result;
}

static void release_memory(Task* t) {
    auto memory = t->memory;
    if (!memory)
        return;
    if (memory->references == 1) {
        shared_memory_release(t);
        if (memory->space.root && read_cr3() == memory->space.root)
            activate_kernel_memory();
        memory->space.destroy();
    }
    if (!--memory->references)
        release(memory);
    t->memory = nullptr;
}

static void release_files(FileTable* table) {
    if (table && !--table->references) {
        record_lock_release(*table);
        for (auto& fd : table->entries)
            close_handle(fd.handle);
        release(table);
    }
}

static FileTable* copy_files(const FileTable* source) {
    auto table = make_resource<FileTable>();
    if (table)
        for (unsigned i = 0; i < max_fds; i++) {
            table->entries[i] = source->entries[i].handle ? source->entries[i] : Descriptor{};
            retain(table->entries[i].handle);
        }
    return table;
}

static void release_resources(Task* t) {
    credential_release(t->credentials);
    io_discard(*t);
    futex_discard(*t);
    release_memory(t);
    release_files(t->files);
    t->files = nullptr;
    if (t->fs && !--t->fs->references)
        release(t->fs);
    t->fs = nullptr;
    if (t->handlers && !--t->handlers->references)
        release(t->handlers);
    t->handlers = nullptr;
}

Task* new_task() {
    if (next_pid == INT32_MAX)
        return nullptr;
    for (auto& t : tasks)
        if (t.state == State::empty) {
            memset(&t, 0, sizeof(t));
            t.credentials = Credentials{};
            t.process = make_resource<Process>();
            t.memory = make_resource<MemoryContext>();
            t.files = make_resource<FileTable>();
            t.fs = make_resource<FsContext>();
            t.handlers = make_resource<SignalHandlers>();
            if (!t.process || !t.memory || !t.files || !t.fs || !t.handlers) {
                release_resources(&t);
                release(t.process);
                t.process = nullptr;
                return nullptr;
            }
            t.pid = next_pid++;
            t.start_ticks = ticks;
            t.process->pid = t.pid;
            t.process->start_ticks = t.start_ticks;
            t.process->leader = &t;
            t.state = State::runnable;
            t.fs->cwd[0] = '/';
            t.fs->cwd_node = root_node;
            t.fs->root_node = root_node;
            t.fpu[0] = 0x7f;
            t.fpu[1] = 3;
            *reinterpret_cast<uint32_t*>(t.fpu + 24) = 0x1f80;
            return &t;
        }
    return nullptr;
}

static constexpr uint64_t clone_vm = 0x100, clone_fs = 0x200, clone_files = 0x400,
                          clone_sighand = 0x800, clone_vfork = 0x4000, clone_thread = 0x10000,
                          clone_sysvsem = 0x40000, clone_settls = 0x80000,
                          clone_parent_settid = 0x100000, clone_child_cleartid = 0x200000,
                          clone_detached = 0x400000, clone_child_settid = 0x1000000;

int clone_task(Frame* f, uint64_t flags, uint64_t stack, uint64_t parent_tid, uint64_t child_tid,
               uint64_t tls) {
    constexpr uint64_t supported = 0xff | clone_vm | clone_fs | clone_files | clone_sighand |
                                   clone_vfork | clone_thread | clone_sysvsem | clone_settls |
                                   clone_parent_settid | clone_child_cleartid | clone_detached |
                                   clone_child_settid;
    if (flags & ~supported)
        return -38;
    bool thread = flags & clone_thread, vm = flags & clone_vm;
    if (!thread && (flags & 0xff) != 17)
        return -38; // This slice supports SIGCHLD process children and thread groups.
    if (((flags & clone_sighand) && !vm) ||
        (thread && (!(flags & clone_sighand) || (flags & (0xff | clone_vfork)))) ||
        ((flags & clone_vfork) && !vm) || ((flags & 0xff) != 0 && (flags & 0xff) != 17) ||
        (vm && !(flags & clone_vfork) && !stack))
        return -22;
    if (stack && (stack < 8 || !current->memory->space.valid(stack - 8, 8, true)))
        return -14;
    if ((flags & clone_settls) && tls >= user_limit)
        return -22;
    if ((flags & clone_parent_settid) && !current->memory->space.valid(parent_tid, 4, true))
        return -14;
    if ((flags & (clone_child_settid | clone_child_cleartid)) && child_tid &&
        !current->memory->space.valid(child_tid, 4, true))
        return -14;
    if ((flags & clone_child_settid) && !child_tid)
        return -14;
    Task* child = new_task();
    if (!child)
        return -11;
    credential_inherit(child->credentials, current->credentials);
    if (vm) {
        release_memory(child);
        child->memory = current->memory;
        child->memory->references++;
    } else {
        if (!child->memory->space.clone_from(current->memory->space)) {
            release_resources(child);
            release(child->process);
            child->process = nullptr;
            child->state = State::empty;
            return -12;
        }
        child->memory->brk_base = current->memory->brk_base;
        child->memory->brk_end = current->memory->brk_end;
        child->memory->dumpable = current->memory->dumpable;
        shared_memory_fork(child, current);
    }
    if (flags & clone_files) {
        release_files(child->files);
        child->files = current->files;
        child->files->references++;
    } else
        for (unsigned i = 0; i < max_fds; i++) {
            child->files->entries[i] =
                current->files->entries[i].handle ? current->files->entries[i] : Descriptor{};
            retain(child->files->entries[i].handle);
        }
    if (flags & clone_fs) {
        release(child->fs);
        child->fs = current->fs;
        child->fs->references++;
    } else {
        *child->fs = *current->fs;
        child->fs->references = 1;
    }
    if (flags & clone_sighand) {
        release(child->handlers);
        child->handlers = current->handlers;
        child->handlers->references++;
    } else
        memcpy(child->handlers->signal_actions, current->handlers->signal_actions,
               sizeof(child->handlers->signal_actions));
    if (thread) {
        release(child->process);
        child->process = current->process;
        child->process->live_threads++;
    } else {
        child->process->parent = current->process->pid;
        child->process->pgid = current->process->pgid;
        child->process->sid = current->process->sid;
        child->process->controlling_pty = current->process->controlling_pty;
        child->process->controlling_console = current->process->controlling_console;
        memcpy(child->process->executable, current->process->executable,
               sizeof(child->process->executable));
    }
    child->frame = *f;
    // A new thread has the group's real parent. A new process belongs to the
    // thread that created it, even while that thread's group remains alive.
    child->real_parent_tid = thread ? current->real_parent_tid : current->pid;
    child->frame.rax = 0;
    if (stack)
        child->frame.rsp = stack;
    child->fs_base = (flags & clone_settls) ? tls : current->fs_base;
    child->signal_mask = current->signal_mask;
    if (!vm || (flags & clone_vfork)) {
        child->altstack_base = current->altstack_base;
        child->altstack_size = current->altstack_size;
    }
    memcpy(child->fpu, current->fpu, sizeof(child->fpu));
    uint32_t tid = child->pid;
    if (flags & clone_parent_settid)
        current->memory->space.copy_out(parent_tid, &tid, 4);
    if (flags & clone_child_settid)
        child->memory->space.copy_out(child_tid, &tid, 4);
    if (flags & clone_child_cleartid)
        child->tid_address = child_tid;
    if (flags & clone_vfork) {
        child->vfork_parent = current->pid;
        current->state = State::blocked;
        current->wait = Wait::vfork;
        current->wait_pid = child->pid;
    }
    return child->pid;
}

int fork_task(Frame* frame, bool share, uint64_t stack) {
    return clone_task(frame, 17 | (share ? clone_vm | clone_vfork : 0), stack, 0, 0, 0);
}

static void finish_process(Task* last) {
    auto process = last->process;
    process->stopped = false;
    terminal_exit(last);
    process->leader->state = State::zombie;
    for (auto& child : tasks)
        if (child.state != State::empty && child.process->parent == process->pid)
            child.process->parent = 1;
    for (auto& parent : tasks)
        if (parent.state != State::empty && parent.process->leader == &parent &&
            parent.process->pid == process->parent)
            queue_process_signal(parent.process, 17, process->pid,
                                 (process->exit_status & 127) ? 2 : 1,
                                 (process->exit_status & 127) ? process->exit_status & 127
                                                              : process->exit_status >> 8);
    if (process->pid == 1) {
        if (test_mode)
            poweroff((process->exit_status & 127) ? 128 + (process->exit_status & 127)
                                                  : (process->exit_status >> 8) & 255);
        panic("init exited");
    }
}

static void clear_tid(Task* t) {
    if (t->tid_address) {
        uint32_t zero = 0;
        if (t->memory->space.copy_out(t->tid_address, &zero, 4))
            futex_wake(t, t->tid_address, 1, false);
    }
    t->tid_address = 0;
}

static void parent_departed(Task* parent) {
    int reaper = 1;
    for (const auto& task : tasks)
        if (&task != parent && task.state != State::empty && task.state != State::zombie &&
            task.process == parent->process) {
            reaper = task.pid;
            break;
        }
    for (auto& child : tasks)
        if (child.state != State::empty && child.state != State::zombie &&
            child.real_parent_tid == parent->pid) {
            child.real_parent_tid = reaper;
            if (child.parent_death_signal)
                queue_process_signal(child.process, child.parent_death_signal,
                                     parent->process->pid);
        }
}

void exit_thread(Task* t, int status) {
    if (t->state == State::empty || t->state == State::zombie)
        return;
    auto process = t->process;
    parent_departed(t);
    clear_tid(t);
    t->vfork_parent = 0;
    t->wait = Wait::none;
    t->state = State::zombie;
    release_resources(t);
    if (process->leader == t || process->live_threads == 1)
        process->exit_status = status;
    if (!--process->live_threads)
        finish_process(t);
    if (process->leader != t) {
        t->state = State::empty;
        t->process = nullptr;
    }
}

void exit_task(Task* t, int status) {
    auto process = t->process;
    for (auto& member : tasks)
        if (&member != t && member.state != State::empty && member.state != State::zombie &&
            member.process == process)
            exit_thread(&member, status);
    // Last-thread notification and init's test exit must use the group status.
    process->exit_status = status;
    exit_thread(t, status);
}

void reap_task(Task* t) {
    if (t->state != State::zombie || t->process->live_threads || t->process->leader != t)
        panic("invalid process reap");
    release(t->process);
    t->process = nullptr;
    t->state = State::empty;
}

static bool awaken(Task& t) {
    if (t.state != State::blocked)
        return t.state == State::runnable;
    if (t.wait == Wait::signal_queue && signal_wait_resume(t))
        return true;
    if (signal_wakes(t)) {
        signal_interrupt(t);
        return true;
    }
    bool ready = false;
    switch (t.wait) {
    case Wait::read:
    case Wait::write:
    case Wait::file_lock:
        return io_resume(t);
    case Wait::child:
        if (t.frame.rax == 247) {
            ready = wait_information_ready(t);
            break;
        }
        for (auto& c : tasks)
            if (c.state != State::empty && c.process->leader == &c &&
                c.process->parent == t.process->pid &&
                ((c.state == State::zombie && !c.process->live_threads) ||
                 (c.process->stopped && !c.process->stop_reported && (t.frame.rdx & 2)) ||
                 (c.process->continued && (t.frame.rdx & 8))) &&
                (t.wait_pid > 0    ? c.process->pid == t.wait_pid
                 : t.wait_pid == 0 ? c.process->pgid == t.process->pgid
                 : t.wait_pid < -1 ? c.process->pgid == -t.wait_pid
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
    case Wait::signal_queue:
        break;
    case Wait::random:
        ready = random_ready();
        break;
    case Wait::futex:
        ready = futex_ready(t);
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
        random_refresh(ticks);
        net_poll();
        epoll_notify();
        for (unsigned i = 0; i < max_tasks; i++) {
            Task* t = &tasks[(start + i) % max_tasks];
            if (!awaken(*t))
                continue;
            if (!signal_deliver(*t))
                continue;
            current = t;
            write_cr3(t->memory->space.root);
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
    ElfHeader header;
    int64_t result = node_read(file, 0, &header, sizeof(header));
    if (result != sizeof(header))
        return result < 0 ? result : -8;
    auto h = &header;
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
    ProgramHeader ph[128];
    result = node_read(file, h->phoff, ph, h->phnum * sizeof(ProgramHeader));
    if (result != int64_t(h->phnum * sizeof(ProgramHeader)))
        return result < 0 ? result : -8;
    for (unsigned i = 0; i < h->phnum; i++) {
        auto p = ph[i];
        if (p.offset > file->size || p.filesz > file->size - p.offset)
            return -8;
        if (p.type == 3) {
            if (p.filesz < 2 || p.filesz > sizeof(image.interpreter))
                return -8;
            result = node_read(file, p.offset, image.interpreter, p.filesz);
            if (result != int64_t(p.filesz))
                return result < 0 ? result : -8;
            if (image.interpreter[p.filesz - 1])
                return -8;
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
        uint8_t buffer[4096];
        for (uint64_t done = 0; done < p.filesz;) {
            result = node_read(file, p.offset + done, buffer,
                               min(size_t(p.filesz - done), sizeof(buffer)));
            if (result <= 0)
                return result < 0 ? result : -8;
            if (!mem.copy_out(va + done, buffer, result))
                return -8;
            done += result;
        }
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

int exec_task(Task* t, const ExecArguments& arguments) {
    const char* path = arguments.path();
    Path name;
    name.base = t->fs->cwd_node;
    if (strlen(path) >= sizeof(name.text))
        return -36;
    memcpy(name.text, path, strlen(path) + 1);
    Node* file = nullptr;
    int lookup_error = resolve_path(name, file);
    if (lookup_error)
        return lookup_error;
    file = file_node(file);
    if (!file)
        return -2;
    if ((file->mode & 0170000) != regular_file)
        return -13;
    int access_error = credential_access(t->credentials, file->uid, file->gid, file->mode, 1);
    if (access_error)
        return access_error;
    if (file->mount->noexec)
        return -13;
    FileCapabilities capabilities;
    if (!file->mount->nosuid && file->mount->ops->getxattr) {
        uint8_t value[24];
        XattrName key{6, "capability"};
        int64_t length = file->mount->ops->getxattr(file, key, value, sizeof(value));
        if (length >= 0) {
            int error = file_capabilities_decode(value, length, capabilities);
            if (error)
                return error;
        } else if (length != -61 && length != -95)
            return length;
    }
    auto candidate = credential_exec_file(t->credentials, file->uid, file->gid, file->mode,
                                          file->mount->nosuid, capabilities);
    if (candidate.error)
        return candidate.error;
    auto credentials = candidate.value;
    bool secure = candidate.secure;
    bool dumpable = candidate.dumpable &&
                    !credential_access(t->credentials, file->uid, file->gid, file->mode, 4);
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
        Path interpreter_path;
        interpreter_path.base = t->fs->cwd_node;
        memcpy(interpreter_path.text, image.interpreter, strlen(image.interpreter) + 1);
        Node* interpreter = nullptr;
        error = resolve_path(interpreter_path, interpreter);
        if (!error) {
            interpreter = file_node(interpreter);
            error = (interpreter->mode & 0170000) != regular_file || interpreter->mount->noexec
                        ? -13
                        : credential_access(t->credentials, interpreter->uid, interpreter->gid,
                                            interpreter->mode, 1);
        }
        if (!error)
            error = load_image(memory, interpreter, 0x7000000000, interp);
        if (!error && credential_access(t->credentials, interpreter->uid, interpreter->gid,
                                        interpreter->mode, 4))
            dumpable = false;
        if (error || interp.interpreter[0]) {
            memory.destroy();
            return error ? error : -8;
        }
        entry = interp.entry;
    }
    constexpr uint64_t stack_top = 0x700000000000;
    constexpr size_t auxiliary_size = 34 * sizeof(uint64_t);
    ExecStack stack{};
    int stack_error = arguments.layout(stack_top, auxiliary_size, stack);
    if (stack_error || !memory.map(stack.bottom, stack.mapping_size, 3)) {
        memory.destroy();
        return stack_error ? stack_error : -12;
    }
    const uint8_t trampoline[] = {0x48, 0xc7, 0xc0, 15, 0, 0, 0, 0x0f, 0x05};
    if (!memory.map(signal_trampoline, page_size, 3) ||
        !memory.copy_out(signal_trampoline, trampoline, sizeof(trampoline)) ||
        !memory.protect(signal_trampoline, page_size, 5)) {
        memory.destroy();
        return -12;
    }
    uint8_t random[16]{};
    // Like early Linux exec, AT_RANDOM must not prevent init from bootstrapping entropy.
    // Before readiness these bytes have the same explicit limitation as GRND_INSECURE.
    int random_error = random_read(random, sizeof(random), true);
    if (random_error) {
        ax::random::erase(random, sizeof(random));
        memory.destroy();
        return random_error;
    }
    uint64_t aux[] = {3,  image.phdr,
                      4,  sizeof(ProgramHeader),
                      5,  image.phnum,
                      6,  page_size,
                      7,  interp.base,
                      8,  0,
                      9,  image.entry,
                      11, credentials.user.real,
                      12, credentials.user.effective,
                      13, credentials.group.real,
                      14, credentials.group.effective,
                      15, stack.platform,
                      17, 100,
                      23, uint64_t(secure),
                      25, stack.random,
                      31, stack.filename,
                      0,  0};
    static_assert(sizeof(aux) == auxiliary_size);
    auto write = [](void* context, uint64_t address, const void* input, size_t size) {
        return static_cast<AddressSpace*>(context)->copy_out(address, input, size);
    };
    stack_error = arguments.write_stack(stack, write, &memory, random, aux, sizeof(aux));
    ax::random::erase(random, sizeof(random));
    if (stack_error) {
        memory.destroy();
        return stack_error;
    }
    auto replacement = make_resource<MemoryContext>();
    bool private_files = t->files->references > 1, private_handlers = t->handlers->references > 1;
    auto files = private_files ? copy_files(t->files) : nullptr;
    auto handlers = private_handlers ? make_resource<SignalHandlers>() : nullptr;
    if (!replacement || (private_files && !files) || (private_handlers && !handlers)) {
        release(replacement);
        release_files(files);
        release(handlers);
        memory.destroy();
        return -12;
    }
    if (handlers) {
        *handlers = *t->handlers;
        handlers->references = 1;
    }
    auto process = t->process;
    for (auto& member : tasks)
        if (&member != t && member.state != State::empty && member.state != State::zombie &&
            member.process == process)
            exit_thread(&member, 0);
    // Sibling exit can leave this file table exclusively owned. Keep it in that
    // case: POSIX record locks belong to the table and must survive exec. A
    // table still shared with a different process requires the prepared copy.
    if (files && t->files->references == 1) {
        release_files(files);
        files = nullptr;
    }
    if (process->leader != t) {
        process->leader->state = State::empty;
        process->leader->process = nullptr;
        process->leader = t;
        int previous_tid = t->pid;
        t->pid = process->pid;
        t->start_ticks = process->start_ticks;
        for (auto& child : tasks)
            if (child.state != State::empty && child.state != State::zombie &&
                child.real_parent_tid == previous_tid)
                child.real_parent_tid = t->pid;
    }
    replacement->space = memory;
    clear_tid(t);
    io_discard(*t);
    if (t == current)
        write_cr3(memory.root);
    release_memory(t);
    t->memory = replacement;
    t->memory->dumpable = dumpable;
    const auto& old_credentials = t->credentials;
    if (secure || old_credentials.user.effective != credentials.user.effective ||
        old_credentials.user.filesystem != credentials.user.filesystem ||
        old_credentials.group.effective != credentials.group.effective ||
        old_credentials.group.filesystem != credentials.group.filesystem ||
        (credentials.permitted & ~old_credentials.permitted))
        t->parent_death_signal = 0;
    t->credentials = credentials;
    process->executed = true;
    if (files) {
        release_files(t->files);
        t->files = files;
    }
    if (handlers) {
        if (!--t->handlers->references)
            release(t->handlers);
        t->handlers = handlers;
    }
    futex_discard(*t);
    t->vfork_parent = 0;
    t->frame = {};
    t->frame.rip = entry;
    t->frame.rsp = stack.pointer;
    t->frame.cs = 0x23;
    t->frame.ss = 0x1b;
    t->frame.rflags = 0x202;
    t->fs_base = 0;
    t->memory->brk_base = t->memory->brk_end = align_up(image.end);
    t->tid_address = 0;
    t->altstack_base = t->altstack_size = 0;
    for (auto& action : t->handlers->signal_actions)
        if (action[0] != 1)
            memset(action, 0, sizeof(action));
    memcpy(t->process->executable, path, min(strlen(path) + 1, sizeof(t->process->executable)));
    for (unsigned fd = 0; fd < max_fds; fd++)
        if (t->files->entries[fd].cloexec)
            close_descriptor(*t->files, int(fd));
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
    init->process->pgid = init->pid;
    init->process->sid = init->pid;
    init->process->controlling_console = true;
    auto console = lookup("/dev/console");
    for (unsigned i = 0; i < 3; i++)
        init->files->entries[i].handle = open_handle(console, i ? 1 : 0);
    const char* args[] = {path, nullptr};
    const char* env[] = {"PATH=/bin:/usr/bin:/sbin:/usr/sbin",
                         "HOME=/root",
                         "TERM=vt100",
                         test_mode ? "AXIOM64_TEST=1" : "AXIOM64_TEST=0",
                         test_suite,
                         test_phase,
                         nullptr};
    ExecArguments arguments;
    if (arguments.capture_kernel(path, args, env) || exec_task(init, arguments))
        panic("cannot execute init");
    enter_user(schedule(nullptr, true));
}

extern "C" Frame* handle_trap(Frame* f) {
    if (f->vector == 32) {
        clock_refresh(true);
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
            current->handlers->signal_actions[signal - 1][0] == 1)
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
