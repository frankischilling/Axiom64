// SPDX-License-Identifier: GPL-3.0-or-later
#include "drivers/platform/devices.hpp"
#include "drivers/block/block.hpp"
#include "ipc/ipc.hpp"
#include "process/signals.hpp"
#include "process/task.hpp"
#include "process/futex.hpp"
#include "io/io.hpp"
#include "net/packet.hpp"
#include "net/inet.hpp"
#include "net/netlink.hpp"
#include "core/time.hpp"
#include "core/random.hpp"
#include "core/random/primitives.hpp"
#include "abi/linux/credentials.hpp"

namespace ax {
struct LinuxStat {
    uint64_t dev, ino, nlink;
    uint32_t mode, uid, gid, pad;
    uint64_t rdev;
    int64_t size, blksize, blocks;
    uint64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns, reserved[3];
};

static_assert(sizeof(LinuxStat) == 144);

struct Timespec {
    int64_t sec, nsec;
};

struct Timeval {
    int64_t sec, usec;
};

struct Pollfd {
    int32_t fd;
    int16_t events, revents;
};

static Handle* fd_handle(int fd) {
    return fd >= 0 && unsigned(fd) < max_fds ? current->files->entries[fd].handle : nullptr;
}

static int64_t copy_result(uint64_t to, const void* data, size_t size) {
    return current->memory->space.copy_out(to, data, size) ? 0 : -14;
}

static bool path_at(int fd, uint64_t user, Path& path) {
    if (!current->memory->space.string(user, path.text, sizeof(path.text)))
        return false;
    if (!path.text[0]) {
        path.error = -2;
        return false;
    }
    path.base = current->fs->root_node;
    if (path.text[0] != '/') {
        if (fd == -100)
            path.base = current->fs->cwd_node;
        else {
            auto h = fd_handle(fd);
            if (!h || !h->node) {
                path.error = -9;
                return false;
            }
            if ((h->node->mode & 0170000) != directory) {
                path.error = -20;
                return false;
            }
            path.base = h->node;
        }
    }
    path.error = 0;
    return true;
}

static int64_t open_file(int dirfd, uint64_t path, uint32_t flags, uint32_t mode) {
    Path name;
    if (!path_at(dirfd, path, name))
        return name.error;
    Node* n = nullptr;
    bool created = false;
    int error = resolve_path(name, n, !(flags & 0400000) && !((flags & 0300) == 0300));
    if (!error && (flags & 0300) == 0300)
        return -17;
    if (error == -2 && (flags & 0100)) {
        error = create_node(name, regular_file | ((mode & 07777) & ~current->fs->umask), n);
        created = !error;
    }
    if (error)
        return error;
    if ((flags & 0200000) && (n->mode & 0170000) != directory)
        return -20;
    if ((n->mode & 0170000) == symlink)
        return -40;
    if ((n->mode & 0170000) == directory && (flags & 3))
        return -21;
    n = file_node(n);
    unsigned mask = (flags & 3) == 0 ? 4 : (flags & 3) == 1 ? 2 : 6;
    if ((flags & 01000) && (n->mode & 0170000) == regular_file)
        mask |= 2;
    if (!created && (error = node_access(n, mask)))
        return error;
    if (n->mount->nodev &&
        ((n->mode & 0170000) == character || (n->mode & 0170000) == block_device))
        return -13;
    if (((flags & 3) || (flags & 01000)) && (n->mode & 0170000) == regular_file && node_readonly(n))
        return -30;
    if (n->device == Device::block && (flags & 3) && block_info(n->device_id)->readonly)
        return -30;
    if (n->device == Device::block && (flags & 3) && block_claimed(n->device_id))
        return -16;
    if (n->device == Device::block && (flags & 040000)) // O_DIRECT needs alignment semantics.
        return -22;
    if (n->device == Device::tty && !current->process->controlling_pty &&
        !current->process->controlling_console)
        return -6;
    if ((flags & 01000) && (n->mode & 0170000) == regular_file) {
        error = node_truncate(n, 0);
        if (error)
            return error;
    }
    Handle* h = open_handle(n, flags);
    if (!h)
        return -23;
    int fd = allocate_fd(current, h, 0, flags & 02000000);
    if (fd < 0)
        close_handle(h);
    return fd;
}

static int path_node_at(int fd, uint64_t user, uint64_t flags, Node*& node, bool real = false) {
    if (flags & ~uint64_t(0x100 | 0x200 | 0x1000))
        return -22;
    Path path;
    if (flags & 0x1000) {
        if (!current->memory->space.string(user, path.text, sizeof(path.text)))
            return -14;
        if (!path.text[0]) {
            auto handle = fd_handle(fd);
            node = fd == -100 ? current->fs->cwd_node : handle ? handle->node : nullptr;
            return node ? 0 : -9;
        }
    }
    if (!path_at(fd, user, path))
        return path.error;
    path.real_access = real;
    return resolve_path(path, node, !(flags & 0x100));
}

static int access_file(int fd, uint64_t user, uint32_t mask, uint64_t flags) {
    if (mask & ~7u)
        return -22;
    Node* node = nullptr;
    bool real = !(flags & 0x200);
    int error = path_node_at(fd, user, flags, node, real);
    if (error)
        return error;
    if ((mask & 2) && node_readonly(node))
        return -30;
    if ((mask & 1) && (node->mode & 0170000) == regular_file && node->mount->noexec)
        return -13;
    return node_access(node, mask, real);
}

static int64_t stat_node(Node* n, uint64_t dst) {
    if (!n)
        return -2;
    n = file_node(n);
    LinuxStat s{};
    s.dev = n->mount->id;
    s.ino = n->inode;
    s.nlink = n->links;
    s.mode = n->mode;
    s.size = n->size;
    s.blksize = page_size;
    s.blocks = n->allocated_blocks;
    s.uid = n->uid;
    s.gid = n->gid;
    s.atime = n->atime.sec;
    s.atime_ns = n->atime.nsec;
    s.mtime = n->mtime.sec;
    s.mtime_ns = n->mtime.nsec;
    s.ctime = n->ctime.sec;
    s.ctime_ns = n->ctime.nsec;
    if ((n->mode & 0170000) == character || (n->mode & 0170000) == block_device)
        s.rdev = device_number(n);
    if ((n->mode & 0170000) == block_device)
        s.size = s.blocks = 0;
    return copy_result(dst, &s, sizeof(s));
}

static int64_t stat_path(int dirfd, uint64_t path, uint64_t dst, bool follow) {
    Path name;
    if (!path_at(dirfd, path, name))
        return name.error;
    Node* node = nullptr;
    int error = resolve_path(name, node, follow);
    return error ? error : stat_node(node, dst);
}

static int64_t block(Wait why, int fd = -1, int pid = -1) {
    current->state = State::blocked;
    current->wait = why;
    current->wait_fd = fd;
    current->wait_pid = pid;
    return would_block;
}

static int64_t mmap_call(uint64_t addr, size_t len, int prot, int flags, int fd, uint64_t off) {
    if (!len || len > 256 * 1024 * 1024 || off % page_size || !(flags & 3) || (flags & 3) == 3 ||
        (prot & ~7))
        return -22;
    len = align_up(len);
    if (flags & 0x10) {
        if (addr % page_size || addr < page_size || addr >= user_limit || len > user_limit - addr)
            return -22;
        current->memory->space.unmap(addr, len);
    } else {
        addr = current->memory->space.next_map;
        current->memory->space.next_map += len + page_size;
    }
    if (addr >= user_limit || len > user_limit - addr)
        return -12;
    Handle* h = nullptr;
    if (!(flags & 0x20)) {
        h = fd_handle(fd);
        if (!h)
            return -9;
        if (h->node && h->node->device == Device::framebuffer)
            return framebuffer_map(current->memory->space, addr, len, prot, off);
        if (!h->node || (h->node->mode & 0170000) != regular_file)
            return -19;
        if ((h->flags & 3) == 1)
            return -13;
        if ((prot & 4) && h->node->mount->noexec)
            return -1;
    }
    if (h && (flags & 1)) {
        if ((prot & 2) && (h->flags & 3) != 2)
            return -13;
        uint64_t backing;
        int error = node_map_shared(h->node, off, len, prot & 2, backing);
        if (error)
            return error;
        if (!current->memory->space.map_physical(addr, backing, len, prot))
            return -12;
        if ((h->flags & 3) != 2 || node_readonly(h->node))
            for (uint64_t page = addr; page < addr + len; page += page_size)
                *current->memory->space.entry(page) |=
                    0x800; // Shared mapping may never gain write access.
        if (h->node->mount->noexec)
            for (uint64_t page = addr; page < addr + len; page += page_size)
                *current->memory->space.entry(page) |= page_no_execute;
        return addr;
    }
    if (!current->memory->space.map(addr, len, 3))
        return -12;
    if ((flags & 0x21) == 0x21)
        for (uint64_t page = addr; page < addr + len; page += page_size)
            *current->memory->space.entry(page) |= 0x400;
    if (h && off < h->node->size) {
        uint8_t buffer[4096];
        size_t count = min(len, h->node->size - size_t(off));
        for (size_t done = 0; done < count;) {
            int64_t result =
                node_read(h->node, off + done, buffer, min(sizeof(buffer), count - done));
            if (result <= 0 ||
                !current->memory->space.copy_out(addr + done, buffer, size_t(result))) {
                current->memory->space.unmap(addr, len);
                return result < 0 ? result : -5;
            }
            done += result;
        }
    }
    if (h && h->node->mount->noexec)
        for (uint64_t page = addr; page < addr + len; page += page_size)
            *current->memory->space.entry(page) |= page_no_execute;
    if (!current->memory->space.protect(addr, len, prot))
        return -12;
    return addr;
}

static int64_t dup_fd(int old, int target, int flags = 0) {
    Handle* h = fd_handle(old);
    if (!h)
        return -9;
    if (target < 0 || unsigned(target) >= max_fds)
        return -9;
    if (current->files->entries[target].reserved)
        return -16;
    if (target != old) {
        close_handle(current->files->entries[target].handle);
        retain(h);
        current->files->entries[target] = {h, bool(flags & 02000000)};
    }
    return target;
}

static int64_t create_pipe(uint64_t dst, int flags) {
    if (flags & ~(04000 | 02000000))
        return -22;
    if (!current->memory->space.valid(dst, 8, true))
        return -14;
    auto pipe = (Pipe*)alloc(sizeof(Pipe));
    if (!pipe)
        return -12;
    auto reader = pipe_handle(pipe, false);
    auto writer = pipe_handle(pipe, true);
    if (!reader || !writer) {
        if (reader)
            close_handle(reader);
        if (writer)
            close_handle(writer);
        if (!reader && !writer)
            release(pipe);
        return -23;
    }
    reader->flags |= flags;
    writer->flags |= flags;
    int result[2] = {allocate_fd(current, reader, 0, flags & 02000000), -1};
    if (result[0] >= 0)
        result[1] = allocate_fd(current, writer, 0, flags & 02000000);
    if (result[0] < 0 || result[1] < 0) {
        if (result[0] >= 0)
            current->files->entries[result[0]] = {};
        close_handle(reader);
        close_handle(writer);
        return -24;
    }
    current->memory->space.copy_out(dst, result, sizeof(result));
    return 0;
}

static int64_t wait_child(int pid, uint64_t status, int options, uint64_t usage) {
    if (options & ~11)
        return -22;
    if (status && !current->memory->space.valid(status, 4, true))
        return -14;
    bool found = false;
    for (auto& t : tasks) {
        if (t.state == State::empty || t.process->leader != &t ||
            t.process->parent != current->process->pid || (pid > 0 && t.process->pid != pid) ||
            (pid == 0 && t.process->pgid != current->process->pgid) ||
            (pid < -1 && t.process->pgid != -pid))
            continue;
        found = true;
        bool stopped = t.process->stopped && !t.process->stop_reported && (options & 2);
        bool continued = t.process->continued && (options & 8);
        if ((t.state != State::zombie || t.process->live_threads) && !stopped && !continued)
            continue;
        int child = t.process->pid;
        int child_status = !t.process->live_threads ? t.process->exit_status
                           : continued              ? 0xffff
                                                    : (t.process->stop_signal << 8) | 0x7f;
        if (status)
            current->memory->space.copy_out(status, &child_status, 4);
        if (usage) {
            uint64_t zeros[18]{};
            if (copy_result(usage, zeros, sizeof(zeros)))
                return -14;
        }
        if (t.state == State::zombie && !t.process->live_threads)
            reap_task(&t);
        else if (continued)
            t.process->continued = false;
        else
            t.process->stop_reported = true;
        return child;
    }
    if (!found)
        return -10;
    if (options & 1)
        return 0;
    return block(Wait::child, -1, pid);
}

struct ExecArgs {
    char path[1024], args[128][1024], env[128][1024];
    const char* argv[129];
    const char* envp[129];
};

static int64_t exec_user(uint64_t path, uint64_t argv, uint64_t envp, Frame* frame) {
    auto a = (ExecArgs*)alloc(sizeof(ExecArgs));
    if (!a)
        return -12;
    int result = -14;
    if (!current->memory->space.string(path, a->path, sizeof(a->path))) {
        release(a);
        return result;
    }
    auto vector = [&](uint64_t ptr, char (*strings)[1024], const char** result) -> bool {
        if (!ptr) {
            result[0] = nullptr;
            return true;
        }
        for (unsigned i = 0; i < 128; i++) {
            uint64_t p;
            if (!current->memory->space.copy_in(&p, ptr + i * 8, 8))
                return false;
            if (!p) {
                result[i] = nullptr;
                return true;
            }
            if (!current->memory->space.string(p, strings[i], 1024))
                return false;
            result[i] = strings[i];
        }
        return false;
    };
    if (vector(argv, a->args, a->argv) && vector(envp, a->env, a->envp)) {
        result = exec_task(current, a->path, a->argv, a->envp);
        if (!result)
            *frame = current->frame;
    }
    release(a);
    return result;
}

static int64_t getdents(int fd, uint64_t buffer, size_t size) {
    auto h = fd_handle(fd);
    if (!h)
        return -9;
    if (!h->node || (h->node->mode & 0170000) != directory)
        return -20;
    size_t done = 0;
    while (true) {
        DirectoryEntry entry{};
        int result = node_readdir(h->node, h->offset, entry);
        if (result <= 0)
            return done ? int64_t(done) : result;
        size_t len = strlen(entry.name) + 1, record = (19 + len + 7) & ~size_t(7);
        if (record > size - done)
            return done ? int64_t(done) : -22;
        uint8_t data[280]{};
        uint16_t reclen = record;
        memcpy(data, &entry.inode, 8);
        memcpy(data + 8, &entry.next, 8);
        memcpy(data + 16, &reclen, 2);
        data[18] = (entry.mode >> 12) & 15;
        memcpy(data + 19, entry.name, len);
        if (!current->memory->space.copy_out(buffer + done, data, record))
            return -14;
        done += record;
        h->offset = entry.next;
    }
}

struct LinuxStatfs {
    uint64_t type, bsize, blocks, bfree, bavail, files, ffree;
    uint32_t fsid[2];
    uint64_t namelen, frsize, flags, spare[4];
};

static_assert(sizeof(LinuxStatfs) == 120);

static int64_t statfs_node(Node* node, uint64_t dst) {
    if (!node)
        return -2;
    FilesystemStats stats;
    int error = node_stats(node, stats);
    if (error)
        return error;
    LinuxStatfs result{};
    result.type = stats.type;
    result.bsize = result.frsize = stats.block_size;
    result.blocks = stats.blocks;
    result.bfree = result.bavail = stats.free_blocks;
    result.files = stats.files;
    result.ffree = stats.free_files;
    result.fsid[0] = node->mount->id;
    result.namelen = 255;
    result.flags = node_readonly(node) ? 1 : 0;
    return copy_result(dst, &result, sizeof(result));
}

static int64_t readlink_path(int fd, uint64_t path, uint64_t buffer, size_t capacity) {
    if (!capacity)
        return -22;
    Path name;
    if (!path_at(fd, path, name))
        return name.error;
    Node* node = nullptr;
    int error = resolve_path(name, node, false);
    if (error)
        return error;
    node = file_node(node);
    if ((node->mode & 0170000) != symlink)
        return -22;
    uint8_t data[1024];
    size_t count = min(capacity, node->size), done = 0;
    while (done < count) {
        int64_t result = node_read(node, done, data, min(sizeof(data), count - done));
        if (result <= 0)
            return result < 0 ? result : -5;
        if (copy_result(buffer + done, data, result))
            return -14;
        done += result;
    }
    return done;
}

static int64_t ioctl_call(int fd, uint64_t request, uint64_t arg) {
    request = uint32_t(request);
    auto h = fd_handle(fd);
    if (!h)
        return -9;
    if (request == 0x5421) {
        int nonblock;
        if (!current->memory->space.copy_in(&nonblock, arg, 4))
            return -14;
        h->flags = nonblock ? h->flags | 04000 : h->flags & ~04000u;
        return 0;
    }
    if (request == 0x5451 || request == 0x5450) {
        current->files->entries[fd].cloexec = request == 0x5451;
        return 0;
    }
    if (request == 0x541b && (h->socket || h->pipe)) {
        int size = h->socket ? h->socket->size : h->pipe->size;
        return copy_result(arg, &size, 4);
    }
    if (request == 0x541b && h->packet) {
        int size = packet_available(h->packet);
        return copy_result(arg, &size, 4);
    }
    if (request == 0x541b && h->inet) {
        int size = inet_available(h->inet);
        return copy_result(arg, &size, sizeof(size));
    }
    if ((h->socket || h->packet || h->inet || h->netlink) && request >= 0x890b && request <= 0x89ff)
        return net_ioctl(*current, request, arg);
    if (!h->node ||
        ((h->node->mode & 0170000) != character && (h->node->mode & 0170000) != block_device))
        return -25;
    return device_ioctl(h, request, arg);
}

static int64_t poll_call(uint64_t pointer, size_t count, int timeout) {
    if (count > max_fds)
        return -22;
    int ready = 0;
    for (size_t i = 0; i < count; i++) {
        Pollfd p;
        if (!current->memory->space.copy_in(&p, pointer + i * sizeof(p), sizeof(p)))
            return -14;
        p.revents = 0;
        auto h = fd_handle(p.fd);
        if (p.fd >= 0 && !h)
            p.revents = 32;
        else if (h)
            p.revents = readiness(h) & (p.events | 8 | 16);
        if (p.revents)
            ready++;
        if (copy_result(pointer + i * sizeof(p), &p, sizeof(p)))
            return -14;
    }
    if (ready || timeout == 0) {
        current->deadline = 0;
        return ready;
    }
    if (current->deadline && ticks >= current->deadline) {
        current->deadline = 0;
        return 0;
    }
    if (timeout > 0 && !current->deadline)
        current->deadline = ticks + (timeout + 9) / 10;
    return block(Wait::poll);
}

static int64_t dispatch(Frame* f) {
    uint64_t a = f->rdi, b = f->rsi, c = f->rdx, d = f->r10, e = f->r8, g = f->r9;
    switch (f->rax) {
    case 0:
    case 1:
    case 17:
    case 18:
    case 19:
    case 20:
    case 43:
    case 44:
    case 45:
    case 46:
    case 47:
    case 73:
    case 288:
        return io_syscall(*current, *f);
    case 2:
        return open_file(-100, a, b, c);
    case 3: {
        auto h = fd_handle(a);
        if (!h)
            return -9;
        close_handle(h);
        current->files->entries[a] = {};
        return 0;
    }
    case 4:
        return stat_path(-100, a, b, true);
    case 5: {
        auto h = fd_handle(a);
        if (!h)
            return -9;
        if (h->pipe || h->socket || h->packet || h->inet || h->netlink || h->epoll) {
            LinuxStat s{};
            s.mode = h->socket || h->packet || h->inet || h->netlink ? 0140777 : 0010600;
            s.nlink = 1;
            return copy_result(b, &s, sizeof(s));
        }
        return stat_node(h->node, b);
    }
    case 6:
        return stat_path(-100, a, b, false);
    case 7:
        return poll_call(a, b, c);
    case 8: {
        auto h = fd_handle(a);
        if (!h)
            return -9;
        if (h->pipe || !h->node || (h->node->mode & 0170000) == character)
            return -29;
        int64_t base = c == 0   ? 0
                       : c == 1 ? int64_t(h->offset)
                       : c == 2 ? int64_t(h->node->size)
                                : -1;
        if (base < 0 || (int64_t(b) < 0 && int64_t(b) < -base) ||
            (int64_t(b) > 0 && b > uint64_t(INT64_MAX - base)))
            return -22;
        int64_t pos = base + int64_t(b);
        if (pos < 0)
            return -22;
        h->offset = pos;
        return pos;
    }
    case 9:
        return mmap_call(a, b, c, d, e, g);
    case 10:
        if (c & (2 | 4)) {
            if (a >= user_limit || b > user_limit - a)
                return -22;
            for (uint64_t p = a; p < a + b; p += page_size) {
                auto entry = current->memory->space.entry(p);
                if (entry &&
                    (((c & 2) && (*entry & 0x800)) || ((c & 4) && (*entry & page_no_execute))))
                    return -13;
            }
        }
        return current->memory->space.protect(a, align_up(b), c) ? 0 : -12;
    case 11:
        if (a % page_size || !b || a >= user_limit || b > user_limit - a)
            return -22;
        current->memory->space.unmap(a, align_up(b));
        return 0;
    case 12:
        if (!a)
            return current->memory->brk_end;
        if (a < current->memory->brk_base || a > current->memory->brk_base + 128 * 1024 * 1024)
            return current->memory->brk_end;
        if (a > current->memory->brk_end &&
            !current->memory->space.map(align_up(current->memory->brk_end),
                                        align_up(a) - align_up(current->memory->brk_end), 3))
            return current->memory->brk_end;
        if (a < current->memory->brk_end)
            current->memory->space.unmap(align_up(a),
                                         align_up(current->memory->brk_end) - align_up(a));
        current->memory->brk_end = a;
        return a;
    case 13:
        if (a < 1 || a > 64 || a == 9 || a == 19 || d != 8)
            return -22;
        if (c && copy_result(c, current->handlers->signal_actions[a - 1], 32))
            return -14;
        if (b && !current->memory->space.copy_in(current->handlers->signal_actions[a - 1], b, 32))
            return -14;
        return 0;
    case 14: {
        if (d != 8)
            return -22;
        if (c && copy_result(c, &current->signal_mask, 8))
            return -14;
        if (b) {
            uint64_t mask;
            if (!current->memory->space.copy_in(&mask, b, 8))
                return -14;
            mask &= ~((1ull << 8) | (1ull << 18));
            if (a == 0)
                current->signal_mask |= mask;
            else if (a == 1)
                current->signal_mask &= ~mask;
            else if (a == 2)
                current->signal_mask = mask;
            else
                return -22;
        }
        return 0;
    }
    case 16:
        return ioctl_call(a, b, c);
    case 15:
    case 34:
    case 36:
    case 37:
    case 38:
    case 62:
    case 127:
    case 130:
    case 131:
    case 200:
    case 234:
        return signal_syscall(f);
    case 21: {
        return access_file(-100, a, b, 0);
    }
    case 22:
        return create_pipe(a, 0);
    case 23:
    case 270: {
        bool pselect = f->rax == 270;
        auto restore_mask = [] {
            if (current->suspend_mask) {
                current->signal_mask = current->suspend_saved_mask;
                current->suspend_mask = false;
            }
        };
        if (pselect && f->r9 && !current->suspend_mask) {
            uint64_t arguments[2], mask;
            if (!current->memory->space.copy_in(arguments, f->r9, sizeof(arguments)))
                return -14;
            if (arguments[0]) {
                if (arguments[1] != 8)
                    return -22;
                if (!current->memory->space.copy_in(&mask, arguments[0], sizeof(mask)))
                    return -14;
                current->suspend_saved_mask = current->signal_mask;
                current->suspend_mask = true;
                current->signal_mask = mask & ~((1ull << 8) | (1ull << 18));
            }
        }
        int ready = select_events(*current, *f, false);
        if (ready < 0) {
            restore_mask();
            current->deadline = 0;
            return ready;
        }
        int64_t timeout[2]{};
        uint64_t delay = 0;
        if (e) {
            if (!current->memory->space.copy_in(timeout, e, sizeof(timeout))) {
                restore_mask();
                current->deadline = 0;
                return -14;
            }
            int64_t scale = pselect ? 1000000000 : 1000000;
            if (timeout[0] < 0 || timeout[0] > INT64_MAX / 100 || timeout[1] < 0 ||
                timeout[1] >= scale) {
                restore_mask();
                current->deadline = 0;
                return -22;
            }
            delay = uint64_t(timeout[0]) * 100 + (timeout[1] + scale / 100 - 1) / (scale / 100);
        }
        if (ready || (e && !delay) || (current->deadline && ticks >= current->deadline)) {
            ready = select_events(*current, *f, true);
            if (e && !pselect) {
                uint64_t left = current->deadline
                                    ? current->deadline > ticks ? current->deadline - ticks : 0
                                    : delay;
                Timeval remaining{int64_t(left / 100), int64_t(left % 100) * 10000};
                if (copy_result(e, &remaining, sizeof(remaining)))
                    ready = -14;
            }
            current->deadline = 0;
            restore_mask();
            return ready;
        }
        if (e && !current->deadline)
            current->deadline = ticks + delay;
        return block(Wait::poll);
    }
    case 24:
        return 0;
    case 26:
        if (a % page_size || (c & ~7) || (c & 5) == 5)
            return -22;
        return current->memory->space.valid(a, b) ? 0 : -12;
    case 28:
        return current->memory->space.valid(a, b) ? 0 : -12;
    case 29:
    case 30:
    case 31:
    case 67:
        return shared_memory_syscall(f);
    case 32: {
        auto h = fd_handle(a);
        if (!h)
            return -9;
        retain(h);
        int fd = allocate_fd(current, h);
        if (fd < 0)
            close_handle(h);
        return fd;
    }
    case 33:
        return dup_fd(a, b);
    case 35: {
        Timespec ts;
        if (!current->memory->space.copy_in(&ts, a, sizeof(ts)))
            return -14;
        if (ts.sec < 0 || ts.nsec < 0 || ts.nsec >= 1000000000)
            return -22;
        if (current->deadline && ticks >= current->deadline) {
            current->deadline = 0;
            return 0;
        }
        if (!current->deadline)
            current->deadline = ticks + uint64_t(ts.sec) * 100 + (ts.nsec + 9999999) / 10000000;
        if (current->deadline == ticks) {
            current->deadline = 0;
            return 0;
        }
        return block(Wait::sleep);
    }
    case 39:
        return current->process->pid;
    case 186:
        return current->pid;
    case 41:
    case 42:
    case 48:
    case 49:
    case 50:
    case 51:
    case 52:
    case 53:
    case 54:
    case 55:
    case 213:
    case 232:
    case 233:
    case 281:
    case 291:
        return ipc_syscall(f);
    case 56:
        return clone_task(f, a, b, c, d, e);
    case 57:
        return fork_task(f);
    case 58:
        return fork_task(f, true);
    case 59:
        return exec_user(a, b, c, f);
    case 60:
        exit_thread(current, (a & 255) << 8);
        return 0;
    case 231:
        exit_task(current, (a & 255) << 8);
        return 0;
    case 61:
        return wait_child(a, b, c, d);
    case 63: {
        char name[6][65]{};
        const char* values[] = {"Axiom64",           "axiom64", "0.1",
                                "C++ x86-64 kernel", "x86_64",  "local"};
        for (unsigned i = 0; i < 6; i++)
            memcpy(name[i], values[i], strlen(values[i]) + 1);
        return copy_result(a, name, sizeof(name));
    }
    case 72: {
        auto h = fd_handle(a);
        if (!h)
            return -9;
        if (b == 0 || b == 1030) {
            retain(h);
            int fd = allocate_fd(current, h, c, b == 1030);
            if (fd < 0)
                close_handle(h);
            return fd;
        }
        if (b == 1)
            return current->files->entries[a].cloexec;
        if (b == 2) {
            current->files->entries[a].cloexec = c & 1;
            return 0;
        }
        if (b == 3)
            return h->flags;
        if (b == 4) {
            h->flags = (h->flags & ~uint32_t(06000)) | (c & 06000);
            return 0;
        }
        return -22;
    }
    case 74:
    case 75: {
        auto h = fd_handle(a);
        if (!h)
            return -9;
        return node_sync(h->node, f->rax == 75);
    }
    case 76: {
        Path path;
        if (!path_at(-100, a, path))
            return path.error;
        Node* n = nullptr;
        int error = resolve_path(path, n);
        if (error)
            return error;
        if ((error = node_access(n, 2)))
            return error;
        if ((n->mode & 0170000) == block_device)
            return -22;
        return node_truncate(n, b);
    }
    case 77: {
        auto h = fd_handle(a);
        if (!h)
            return -9;
        if (!h->node || (h->flags & 3) == 0 || (h->node->mode & 0170000) == block_device)
            return -22;
        return node_truncate(h->node, b);
    }
    case 79: {
        node_path(current->fs->cwd_node, current->fs->cwd, sizeof(current->fs->cwd));
        if (!current->fs->cwd[0])
            return -2;
        size_t n = strlen(current->fs->cwd) + 1;
        if (b < n)
            return -34;
        return copy_result(a, current->fs->cwd, n) ? -14 : int64_t(n);
    }
    case 80: {
        Path path;
        if (!path_at(-100, a, path))
            return path.error;
        Node* n = nullptr;
        int error = resolve_path(path, n);
        if (error)
            return error;
        if ((n->mode & 0170000) != directory)
            return -20;
        if ((error = node_access(n, 1)))
            return error;
        current->fs->cwd_node = n;
        node_path(n, current->fs->cwd, sizeof(current->fs->cwd));
        return 0;
    }
    case 81: {
        auto h = fd_handle(a);
        if (!h)
            return -9;
        if (!h->node || (h->node->mode & 0170000) != directory)
            return -20;
        int error = node_access(h->node, 1);
        if (error)
            return error;
        current->fs->cwd_node = h->node;
        node_path(h->node, current->fs->cwd, sizeof(current->fs->cwd));
        return 0;
    }
    case 83:
    case 258: {
        Path path;
        if (!path_at(f->rax == 83 ? -100 : int(a), f->rax == 83 ? a : b, path))
            return path.error;
        Node* node = nullptr;
        return create_node(
            path, directory | (((f->rax == 83 ? b : c) & 07777) & ~current->fs->umask), node);
    }
    case 85:
        return open_file(-100, a, 01000 | 0100 | 1, b);
    case 86:
    case 265: {
        Path old_path, new_path;
        if (f->rax == 265 && (e & ~0x400ull))
            return -22;
        if (!path_at(f->rax == 86 ? -100 : int(a), f->rax == 86 ? a : b, old_path))
            return old_path.error;
        if (!path_at(f->rax == 86 ? -100 : int(c), f->rax == 86 ? b : d, new_path))
            return new_path.error;
        return link_node(old_path, new_path, f->rax == 265 && (e & 0x400));
    }
    case 82:
    case 264: {
        Path old_path, new_path;
        if (!path_at(f->rax == 82 ? -100 : int(a), f->rax == 82 ? a : b, old_path))
            return old_path.error;
        if (!path_at(f->rax == 82 ? -100 : int(c), f->rax == 82 ? b : d, new_path))
            return new_path.error;
        return rename_node(old_path, new_path);
    }
    case 84:
    case 87:
    case 263: {
        if (f->rax == 263 && (c & ~0x200ull))
            return -22;
        Path path;
        if (!path_at(f->rax == 263 ? int(a) : -100, f->rax == 263 ? b : a, path))
            return path.error;
        return remove_node(path, f->rax == 84 || (f->rax == 263 && (c & 0x200)));
    }
    case 88:
    case 266: {
        char target[1024];
        if (!current->memory->space.string(a, target, sizeof(target)))
            return -14;
        Path path;
        if (!path_at(f->rax == 88 ? -100 : int(b), f->rax == 88 ? b : c, path))
            return path.error;
        Node* node = nullptr;
        return create_node(path, symlink | 0777, node, target);
    }
    case 89:
        return readlink_path(-100, a, b, c);
    case 267:
        return readlink_path(a, b, c, d);
    case 90:
    case 268: {
        Path path;
        if (!path_at(f->rax == 90 ? -100 : int(a), f->rax == 90 ? a : b, path))
            return path.error;
        Node* node = nullptr;
        int error = resolve_path(path, node);
        if (error)
            return error;
        node = file_node(node);
        uint32_t mode = f->rax == 90 ? b : c;
        return node_chmod(node, mode);
    }
    case 91: {
        auto h = fd_handle(a);
        if (!h)
            return -9;
        if (!h->node)
            return -22;
        auto node = h->node;
        return node_chmod(node, b);
    }
    case 95: {
        uint32_t old = current->fs->umask;
        current->fs->umask = a & 0777;
        return old;
    }
    case 92:
    case 93:
    case 94: {
        if (f->rax == 93) {
            auto h = fd_handle(a);
            return !h ? -9 : node_chown(h->node, b, c);
        }
        Path path;
        if (!path_at(-100, a, path))
            return path.error;
        Node* node = nullptr;
        int error = resolve_path(path, node, f->rax == 92);
        return error ? error : node_chown(node, b, c);
    }
    case 260: {
        if (e & ~uint64_t(0x100 | 0x1000))
            return -22;
        Node* node = nullptr;
        int error = path_node_at(a, b, e, node);
        return error ? error : node_chown(node, c, d);
    }
    case 96: {
        uint64_t time[] = {ticks / 100, (ticks % 100) * 10000};
        return a ? copy_result(a, time, sizeof(time)) : 0;
    }
    case 97: {
        uint64_t limit[] = {a == 7 ? max_fds : 0x7fffffffffffffffull,
                            a == 7 ? max_fds : 0x7fffffffffffffffull};
        return copy_result(b, limit, sizeof(limit));
    }
    case 101: {
        if (!a)
            return -38;
        Task* target = nullptr;
        for (auto& task : tasks)
            if (task.state != State::empty && task.state != State::zombie && task.pid == int(b))
                target = &task;
        if (!target)
            return -3;
        const auto& from = current->credentials;
        const auto& to = target->credentials;
        if (target->process != current->process && !capable(from, Capability::sys_ptrace) &&
            (from.user.real != to.user.real || from.user.real != to.user.effective ||
             from.user.real != to.user.saved || from.group.real != to.group.real ||
             from.group.real != to.group.effective || from.group.real != to.group.saved ||
             !target->memory->dumpable || (to.permitted & ~from.permitted)))
            return -1;
        return -38; // Tracing requests remain unimplemented; permissions precede any future access.
    }
    case 102:
    case 104:
    case 107:
    case 108:
    case 105:
    case 106:
    case 113:
    case 114:
    case 117:
    case 119:
    case 118:
    case 120:
    case 122:
    case 123:
    case 115:
    case 116:
    case 125:
    case 126:
    case 157:
        return credential_syscall(f);
    case 109: {
        if (int32_t(b) < 0)
            return -22;
        Task* target = nullptr;
        for (auto& t : tasks)
            if (t.state != State::empty && t.process->leader == &t &&
                t.process->pid == int(a ? a : current->process->pid))
                target = &t;
        if (!target)
            return -3;
        auto process = target->process;
        if (process != current->process) {
            if (process->parent != current->process->pid)
                return -3;
            if (process->sid != current->process->sid)
                return -1;
            if (process->executed)
                return -13;
        }
        if (process->sid == process->pid)
            return -1;
        int group = b ? b : process->pid;
        if (group != process->pid) {
            bool found = false;
            for (const auto& task : tasks)
                if (task.state != State::empty && task.process->pgid == group &&
                    task.process->sid == current->process->sid)
                    found = true;
            if (!found)
                return -1;
        }
        process->pgid = group;
        return 0;
    }
    case 110:
        return current->process->parent;
    case 111:
        return current->process->pgid;
    case 112:
        if (current->process->pgid == current->process->pid)
            return -1;
        current->process->sid = current->process->pgid = current->process->pid;
        current->process->controlling_pty = nullptr;
        current->process->controlling_console = false;
        return current->process->pid;
    case 124:
        for (auto& t : tasks)
            if (t.state != State::empty && t.process->leader == &t &&
                t.process->pid == int(a ? a : current->process->pid))
                return t.process->sid;
        return -3;
    case 121:
        for (auto& t : tasks)
            if (t.state != State::empty && t.process->leader == &t &&
                t.process->pid == int(a ? a : current->process->pid))
                return t.process->pgid;
        return -3;
    case 158:
        if (a == 0x1002) {
            if (b >= user_limit)
                return -1;
            current->fs_base = b;
            arch_task(b);
            return 0;
        }
        if (a == 0x1003)
            return copy_result(b, &current->fs_base, 8);
        return -22;
    case 169:
        if (!capable(current->credentials, Capability::sys_boot))
            return -1;
        if (a != 0xfee1dead || b != 672274793 || c != 0x4321fedc)
            return -22;
        poweroff(0);
    case 202:
        return futex_syscall(f);
    case 204: {
        if (b < 8)
            return -22;
        uint64_t cpu = 1;
        return copy_result(c, &cpu, 8) ? -14 : 8;
    }
    case 217:
        return getdents(a, b, c);
    case 218:
        current->tid_address = a;
        return current->pid;
    case 228: {
        if (a > 7)
            return -22;
        Timespec ts{int64_t(ticks / 100), int64_t(ticks % 100) * 10000000};
        return copy_result(b, &ts, sizeof(ts));
    }
    case 229: {
        Timespec ts{0, 10000000};
        return copy_result(b, &ts, sizeof(ts));
    }
    case 137: {
        Path path;
        if (!path_at(-100, a, path))
            return path.error;
        Node* node = nullptr;
        int error = resolve_path(path, node);
        return error ? error : statfs_node(node, b);
    }
    case 138: {
        auto h = fd_handle(a);
        return !h ? -9 : !h->node ? -22 : statfs_node(h->node, b);
    }
    case 162:
        return sync_filesystems();
    case 165: {
        Path path;
        if (!path_at(-100, b, path))
            return path.error;
        char type[64]{};
        if (c && !current->memory->space.string(c, type, sizeof(type)))
            return -14;
        if (e) {
            char options[1024];
            if (!current->memory->space.string(e, options, sizeof(options)))
                return -14;
            if (options[0])
                return -22;
        }
        Path source;
        if (!(d & 32) && !strcmp(type, "ext2") && !path_at(-100, a, source))
            return source.error;
        return mount_filesystem(path, source, type, d);
    }
    case 166: {
        Path path;
        if (!path_at(-100, a, path))
            return path.error;
        return unmount(path, b);
    }
    case 257:
        return open_file(a, b, c, d);
    case 262:
        return stat_path(a, b, c, !(d & 0x100));
    case 269:
    case 439: {
        return access_file(a, b, c, f->rax == 439 ? d : 0);
    }
    case 161: {
        if (!capable(current->credentials, Capability::sys_chroot))
            return -1;
        Node* node = nullptr;
        int error = path_node_at(-100, a, 0, node);
        if (error)
            return error;
        if ((node->mode & 0170000) != directory)
            return -20;
        if ((error = node_access(node, 1)))
            return error;
        current->fs->root_node = node;
        return 0;
    }
    case 273:
        return -38;
    case 280: {
        if (d & ~uint64_t(0x100))
            return -22;
        Node* node;
        if (b) {
            Path path;
            if (!path_at(a, b, path))
                return path.error;
            int error = resolve_path(path, node, !(d & 0x100));
            if (error)
                return error;
        } else {
            auto h = fd_handle(a);
            if (!h || !h->node)
                return -9;
            node = h->node;
        }
        node = file_node(node);
        Timestamp update[] = {node->atime, node->mtime};
        Timespec input[2];
        if (c && !current->memory->space.copy_in(input, c, sizeof(input)))
            return -14;
        bool changed = false;
        for (unsigned i = 0; i < 2; i++) {
            if (c && input[i].nsec == 1073741822)
                continue;
            changed = true;
            if (!c || input[i].nsec == 1073741823)
                update[i] = node_now();
            else {
                if (input[i].nsec < 0 || input[i].nsec >= 1000000000)
                    return -22;
                update[i] = {input[i].sec, uint64_t(input[i].nsec)};
            }
        }
        if (changed && current->credentials.user.filesystem != node->uid &&
            !capable(current->credentials, Capability::fowner)) {
            bool now = !c || (input[0].nsec == 1073741823 && input[1].nsec == 1073741823);
            if (!now)
                return -1;
            int error = node_access(node, 2);
            if (error)
                return error;
        }
        return changed ? node_setattr(node, node->mode, update[0], update[1]) : 0;
    }
    case 292:
        if (a == b || (c & ~02000000))
            return -22;
        return dup_fd(a, b, c);
    case 293:
        return create_pipe(a, b);
    case 302: {
        if (a && int(a) != current->process->pid && int(a) != current->pid)
            return -3;
        uint64_t limit[] = {b == 7 ? max_fds : 0x7fffffffffffffffull,
                            b == 7 ? max_fds : 0x7fffffffffffffffull};
        if (c)
            return -38;
        return d ? copy_result(d, limit, sizeof(limit)) : 0;
    }
    case 318: {
        unsigned flags = c;
        if ((flags & ~7u) || (flags & 6u) == 6u)
            return -22;
        if (!random_ready() && !(flags & 4u))
            return flags & 1u ? -11 : block(Wait::random);
        uint64_t length = min(b, uint64_t(0x7ffff000)); // Linux MAX_RW_COUNT.
        if (a >= user_limit || length > user_limit - a)
            return -14;
        // Small ready reads complete atomically. Large reads may return a short result.
        if (b > 256 && signal_wakes(*current))
            return -4;
        uint8_t bytes[256];
        size_t done = 0;
        size_t wanted = min(size_t(length), size_t(4096));
        while (done < wanted) {
            size_t n = min(wanted - done, sizeof(bytes));
            if (!current->memory->space.valid(a + done, n, true))
                return done ? int64_t(done) : -14;
            int error = random_read(bytes, n, flags & 4u);
            if (error)
                return done ? int64_t(done) : error;
            bool copied = current->memory->space.copy_out(a + done, bytes, n);
            random::erase(bytes, sizeof(bytes));
            if (!copied)
                return done ? int64_t(done) : -14;
            done += n;
        }
        return done;
    }
    default:
        log("unimplemented syscall %u pid=%u\n", f->rax, uint64_t(current->pid));
        return -38;
    }
}

extern "C" Frame* handle_syscall(Frame* f) {
    asm volatile("fxsave64 %0" : "=m"(current->fpu));
    clock_refresh();
    uint64_t number = f->rax;
    if (trace_syscalls)
        log("sys pid=%u nr=%u a=%x b=%x c=%x\n", uint64_t(current->pid), number, f->rdi, f->rsi,
            f->rdx);
    int64_t result = dispatch(f);
    clock_refresh();
    epoll_notify();
    if (trace_syscalls)
        log("sys result=%d\n", result);
    if (result == would_block) {
        f->rip -= 2;
        f->rax = number;
    } else if (number != 15)
        f->rax = result;
    return schedule(f, number == 24 || result == would_block || current->state != State::runnable);
}
} // namespace ax
