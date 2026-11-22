// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/proc.cpp
 * @brief   Process and system information filesystem.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Presents process information and routes writable kernel settings through
 * procfs file operations.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "fs/proc.hpp"
#include "fs/descriptor_inode.hpp"
#include "fs/ext2/ext2.hpp"
#include "fs/inotify.hpp"
#include "fs/memfd.hpp"
#include "fs/pipe.hpp"
#include "fs/proc/integer.hpp"
#include "fs/proc/ipv6.hpp"
#include "fs/proc/ipv4.hpp"
#include "drivers/block/block.hpp"
#include "net/ethernet.hpp"
#include "ipc/eventfd.hpp"
#include "ipc/ipc.hpp"
#include "ipc/posix_message_queues.hpp"
#include "ipc/signal_descriptor.hpp"
#include "ipc/timerfd.hpp"
#include "process/task.hpp"
#include "process/cpu.hpp"
#include "core/random.hpp"
#include "core/random/primitives.hpp"
#include "core/time.hpp"

namespace ax {
namespace {
enum class Kind {
    root,
    self,
    thread_self,
    process,
    task_list,
    thread,
    fd_directory,
    fd_link,
    exe_link,
    fdinfo_directory,
    fdinfo,
    status,
    stat,
    comm,
    cmdline,
    cpuinfo,
    meminfo,
    system_stat,
    uptime,
    mounts_link,
    mounts,
    filesystem_types,
    sys,
    fs,
    pipe_limit,
    kernel,
    random,
    boot_id,
    net,
    ipv4,
    source_limit,
    ipv4_forward,
    ipv6,
    conf,
    network_scope,
    network_property
};

// Kernel execution serializes generation. Every proc mount observes this same boot.
char boot_identifier[37]{};
constexpr const char* sys_directories[] = {"kernel", "net", "fs"};
constexpr const char* root_names[] = {"self", "thread-self", "sys",    "cpuinfo",    "meminfo",
                                      "stat", "uptime",      "mounts", "filesystems"};
constexpr Kind root_kinds[] = {Kind::self,    Kind::thread_self, Kind::sys,
                               Kind::cpuinfo, Kind::meminfo,     Kind::system_stat,
                               Kind::uptime,  Kind::mounts_link, Kind::filesystem_types};
constexpr size_t root_children = sizeof(root_names) / sizeof(root_names[0]);
static_assert(root_children == sizeof(root_kinds) / sizeof(root_kinds[0]));
constexpr const char* pipe_limit_names[] = {"pipe-max-size", "pipe-user-pages-hard",
                                            "pipe-user-pages-soft"};

static bool is_control(Kind kind) {
    return kind == Kind::network_property || kind == Kind::source_limit ||
           kind == Kind::ipv4_forward || kind == Kind::pipe_limit;
}

static bool descriptor_directory(Kind kind) {
    return kind == Kind::fd_directory || kind == Kind::fdinfo_directory;
}

static bool snapshot_file(Kind kind) {
    return kind == Kind::status || kind == Kind::stat || kind == Kind::comm ||
           kind == Kind::fdinfo || kind == Kind::cpuinfo || kind == Kind::meminfo ||
           kind == Kind::system_stat || kind == Kind::uptime || kind == Kind::mounts ||
           kind == Kind::filesystem_types;
}

struct Entry {
    Node node{};
    Entry* next = nullptr;
    Kind kind;
    int pid, tgid;
    unsigned descriptor = 0;
    unsigned network_index = 0, property = 0;
    uint64_t network_generation = 0;
    bool ipv4_configuration = false;
};

struct Proc {
    Entry* entries = nullptr;
    size_t count = 0;
    uint64_t next_inode = 1;
};

struct Snapshot {
    char* bytes;
    size_t length;
};

struct Text {
    char* bytes;
    size_t length = 0, capacity;
    bool failed = false;

    void character(char value) {
        if (length < capacity)
            bytes[length++] = value;
        else
            failed = true;
    }

    void string(const char* value) {
        while (*value)
            character(*value++);
    }

    void number(uint64_t value, unsigned base = 10, unsigned width = 0, char padding = ' ') {
        char digits[22];
        size_t count = 0;
        do {
            digits[count++] = "0123456789abcdef"[value % base];
            value /= base;
        } while (value);
        while (width > count) {
            character(padding);
            --width;
        }
        while (count)
            character(digits[--count]);
    }

    void hexadecimal(uint64_t value) {
        number(value, 16, 16, '0');
    }

    void field(const char* name, uint64_t value) {
        string(name);
        string(":\t");
        number(value);
        character('\n');
    }

    void identity(const char* name, const Identity& value) {
        string(name);
        string(":\t");
        number(value.real);
        character('\t');
        number(value.effective);
        character('\t');
        number(value.saved);
        character('\t');
        number(value.filesystem);
        character('\n');
    }

    void bits(const char* name, uint64_t value) {
        string(name);
        string(":\t");
        hexadecimal(value);
        character('\n');
    }
};

static Entry* entry(Node* node) {
    return static_cast<Entry*>(node->filesystem_data);
}

static Task* task(int pid) {
    for (auto& candidate : tasks)
        if (candidate.state != State::empty && candidate.process && candidate.pid == pid)
            return &candidate;
    return nullptr;
}

static void decimal(int value, char output[16]) {
    Text text{output, 0, 15};
    text.number(unsigned(value));
    output[text.length] = 0;
}

static int pid(const char* name) {
    if (!*name || *name == '0')
        return 0;
    unsigned result = 0;
    for (; *name; name++) {
        if (*name < '0' || *name > '9' || result > unsigned(INT32_MAX) / 10)
            return 0;
        result = result * 10 + unsigned(*name - '0');
        if (result > INT32_MAX)
            return 0;
    }
    return int(result);
}

static Handle* descriptor(const Entry& item) {
    auto owner = task(item.pid);
    return owner && owner->files ? owner->files->entries[item.descriptor].handle : nullptr;
}

static bool descriptor_access(const Task& owner) {
    if (!current)
        return false;
    const auto& caller = current->credentials;
    const auto& target = owner.credentials;
    return current->process == owner.process || capable(caller, Capability::sys_ptrace) ||
           (owner.memory && owner.memory->dumpable && caller.user.filesystem == target.user.real &&
            caller.user.filesystem == target.user.effective &&
            caller.user.filesystem == target.user.saved &&
            caller.group.filesystem == target.group.real &&
            caller.group.filesystem == target.group.effective &&
            caller.group.filesystem == target.group.saved &&
            !(target.permitted & ~caller.effective));
}

static int link_descriptor(const Entry& item, Handle*& handle) {
    auto owner = task(item.pid);
    if (!owner || !(handle = descriptor(item)))
        return -2;
    return descriptor_access(*owner) ? 0 : -13;
}

static int link_executable(const Entry& item, Node*& target) {
    auto owner = task(item.pid);
    if (!owner || !owner->memory || !(target = owner->memory->exec_dentry))
        return -2;
    return descriptor_access(*owner) ? 0 : -13;
}

static int follow_link(Node* node, Node*& target) {
    auto item = entry(node);
    if (item->kind == Kind::exe_link) {
        int error = link_executable(*item, target);
        return error ? error : 1;
    }
    if (item->kind != Kind::fd_link)
        return 0;
    Handle* handle = nullptr;
    if (int error = link_descriptor(*item, handle))
        return error;
    if (int error = descriptor_inode(*handle, target))
        return error;
    if (handle->opened_dentry)
        target = handle->opened_dentry;
    return 1;
}

static int access_override(Node* node, unsigned mask) {
    auto item = entry(node);
    if (item->kind == Kind::fdinfo_directory || item->kind == Kind::fdinfo) {
        auto owner = task(item->pid);
        if (!owner)
            return -3;
        return descriptor_access(*owner) ? 0 : -13;
    }
    if (item->kind == Kind::comm && entry(node->parent)->kind == Kind::thread) {
        auto owner = task(item->pid);
        if (!owner)
            return -3;
        if (current && owner->process == current->process && !(mask & 1))
            return 1;
    }
    auto owner = item->kind == Kind::fd_directory ? task(item->pid) : nullptr;
    return owner && current && owner->process == current->process && !(mask & 2) ? 1 : 0;
}

static size_t link_target(Kind kind, char output[40]) {
    if (!current)
        return 0;
    Text text{output, 0, 40};
    text.number(unsigned(current->process->pid));
    if (kind == Kind::thread_self) {
        text.string("/task/");
        text.number(unsigned(current->pid));
    }
    return text.length;
}

static void refresh(Node* node) {
    auto item = entry(node);
    if (item->kind == Kind::mounts_link) {
        node->size = sizeof("self/mounts") - 1;
        return;
    }
    if (item->kind == Kind::self || item->kind == Kind::thread_self) {
        char target[40];
        node->size = link_target(item->kind, target);
        return;
    }
    if (auto owner = task(item->pid)) {
        bool user_owned = owner->memory && owner->memory->dumpable;
        node->uid = user_owned ? owner->credentials.user.effective : 0;
        node->gid = user_owned ? owner->credentials.group.effective : 0;
    }
}

static void refresh_fd_link(Entry& item) {
    auto handle = descriptor(item);
    item.node.mode = symlink;
    if (handle && !(handle->flags & 010000000)) {
        unsigned access = handle->flags & 3;
        if (access != 1)
            item.node.mode |= 0500;
        if (access != 0)
            item.node.mode |= 0300;
    }
}

static bool within(Node* node, Node* ancestor) {
    for (; node; node = node->parent)
        if (node == ancestor)
            return true;
    return false;
}

static int validate(Node* node) {
    auto item = entry(node);
    if (item->kind != Kind::network_scope && item->kind != Kind::network_property)
        return 0;
    uint64_t generation = item->ipv4_configuration ? proc4::scope_generation(item->network_index)
                                                   : proc6::scope_generation(item->network_index);
    return generation && generation == item->network_generation ? 0 : -2;
}

static void collect(Proc* state) {
    // Retained descriptions/cwd pin the entire ancestor chain. A TID subtree
    // can retire independently while its thread group continues to live.
    for (;;) {
        Entry* dead = nullptr;
        for (auto item = state->entries; item; item = item->next)
            if ((((item->kind == Kind::process || item->kind == Kind::thread) &&
                  !task(item->pid)) ||
                 (item->kind == Kind::network_scope && validate(&item->node)) ||
                 ((item->kind == Kind::fd_link || item->kind == Kind::fdinfo) &&
                  !descriptor(*item))) &&
                !node_referenced(&item->node)) {
                dead = item;
                break;
            }
        if (!dead)
            return;
        auto parent = dead->node.parent;
        auto link = &parent->first_child;
        while (*link && *link != &dead->node)
            link = &(*link)->next_sibling;
        if (*link)
            *link = dead->node.next_sibling;
        // Descendants must be released before their ancestor is dereferenced.
        for (;;) {
            Entry** selected = nullptr;
            for (auto cursor = &state->entries; *cursor; cursor = &(*cursor)->next)
                if (within(&(*cursor)->node, &dead->node) && !(*cursor)->node.first_child) {
                    selected = cursor;
                    break;
                }
            if (!selected)
                break;
            auto item = *selected;
            *selected = item->next;
            if (item != dead) {
                auto child = &item->node.parent->first_child;
                while (*child && *child != &item->node)
                    child = &(*child)->next_sibling;
                if (*child)
                    *child = item->node.next_sibling;
            }
            bool final = item == dead;
            release(item);
            state->count--;
            if (final)
                break;
        }
    }
}

static Entry* make(Proc* state, Mount* mount, Node* parent, const char* name, Kind kind, int owner,
                   int group) {
    if (state->count == 4096)
        return nullptr;
    auto item = static_cast<Entry*>(alloc(sizeof(Entry)));
    if (!item)
        return nullptr;
    *item = {};
    item->kind = kind;
    item->pid = owner;
    item->tgid = group;
    auto node = &item->node;
    node->inode = state->next_inode++;
    node->parent = parent;
    node->mount = mount;
    node->filesystem_data = item;
    node->mode = kind == Kind::comm ? regular_file | 0644
                 : snapshot_file(kind) || kind == Kind::cmdline || kind == Kind::boot_id
                     ? regular_file | 0444
                 : kind == Kind::self || kind == Kind::thread_self || kind == Kind::fd_link ||
                         kind == Kind::exe_link || kind == Kind::mounts_link
                     ? symlink | 0777
                 : kind == Kind::fd_directory ? directory | 0500
                                              : directory | 0555;
    node->links = (node->mode & 0170000) == directory ? 2 : 1;
    memcpy(node->name, name, strlen(name) + 1);
    node->atime = node->mtime = node->ctime = node_now();
    if (parent) {
        node->next_sibling = parent->first_child;
        parent->first_child = node;
    }
    item->next = state->entries;
    state->entries = item;
    state->count++;
    refresh(node);
    return item;
}

static int lookup(Node* parent, const char* name, Node*& output) {
    if (int error = validate(parent))
        return error;
    auto context = entry(parent);
    auto owner = context->pid ? task(context->pid) : nullptr;
    if (context->pid && !owner)
        return -2;
    Kind kind;
    int selected_pid = context->pid, group = context->tgid;
    unsigned network_index = context->network_index, property = 0, fd = 0;
    uint64_t network_generation = context->network_generation;
    bool ipv4_configuration = context->ipv4_configuration || context->kind == Kind::ipv4;
    if (context->kind == Kind::root) {
        size_t index = 0;
        while (index != root_children && strcmp(name, root_names[index]))
            ++index;
        if (index != root_children)
            kind = root_kinds[index];
        else {
            selected_pid = pid(name);
            auto selected = task(selected_pid);
            if (!selected)
                return -2;
            group = selected->process->pid;
            kind = Kind::process;
        }
    } else if (context->kind == Kind::sys && !strcmp(name, "kernel"))
        kind = Kind::kernel;
    else if (context->kind == Kind::sys && !strcmp(name, "net"))
        kind = Kind::net;
    else if (context->kind == Kind::sys && !strcmp(name, "fs"))
        kind = Kind::fs;
    else if (context->kind == Kind::fs) {
        while (property < 3 && strcmp(name, pipe_limit_names[property]))
            property++;
        if (property == 3)
            return -2;
        kind = Kind::pipe_limit;
    } else if (context->kind == Kind::net && !strcmp(name, "ipv6"))
        kind = Kind::ipv6;
    else if (context->kind == Kind::net && !strcmp(name, "ipv4"))
        kind = Kind::ipv4;
    else if (context->kind == Kind::ipv4 && !strcmp(name, "igmp_max_msf"))
        kind = Kind::source_limit;
    else if (context->kind == Kind::ipv4 && !strcmp(name, "ip_forward")) {
        kind = Kind::ipv4_forward;
        network_index = 0;
        property = proc4::forwarding_property;
    } else if ((context->kind == Kind::ipv6 || context->kind == Kind::ipv4) &&
               !strcmp(name, "conf"))
        kind = Kind::conf;
    else if (context->kind == Kind::conf) {
        if (!(ipv4_configuration ? proc4::scope_index(name, network_index)
                                 : proc6::scope_index(name, network_index)))
            return -2;
        network_generation = ipv4_configuration ? proc4::scope_generation(network_index)
                                                : proc6::scope_generation(network_index);
        kind = Kind::network_scope;
    } else if (context->kind == Kind::network_scope) {
        unsigned count = ipv4_configuration ? proc4::property_count : proc6::property_count;
        while (property < count &&
               strcmp(name, ipv4_configuration ? proc4::property_name(property)
                                               : proc6::property_name(property)))
            property++;
        if (property == count)
            return -2;
        kind = Kind::network_property;
    } else if (context->kind == Kind::kernel && !strcmp(name, "random"))
        kind = Kind::random;
    else if (context->kind == Kind::random && !strcmp(name, "boot_id"))
        kind = Kind::boot_id;
    else if ((context->kind == Kind::process || context->kind == Kind::thread) &&
             !strcmp(name, "status"))
        kind = Kind::status;
    else if ((context->kind == Kind::process || context->kind == Kind::thread) &&
             !strcmp(name, "stat"))
        kind = Kind::stat;
    else if ((context->kind == Kind::process || context->kind == Kind::thread) &&
             !strcmp(name, "comm"))
        kind = Kind::comm;
    else if ((context->kind == Kind::process || context->kind == Kind::thread) &&
             !strcmp(name, "cmdline"))
        kind = Kind::cmdline;
    else if (context->kind == Kind::process && !strcmp(name, "task"))
        kind = Kind::task_list;
    else if ((context->kind == Kind::process || context->kind == Kind::thread) &&
             !strcmp(name, "fd"))
        kind = Kind::fd_directory;
    else if ((context->kind == Kind::process || context->kind == Kind::thread) &&
             !strcmp(name, "fdinfo"))
        kind = Kind::fdinfo_directory;
    else if ((context->kind == Kind::process || context->kind == Kind::thread) &&
             !strcmp(name, "exe"))
        kind = Kind::exe_link;
    else if ((context->kind == Kind::process || context->kind == Kind::thread) &&
             !strcmp(name, "mounts"))
        kind = Kind::mounts;
    else if (descriptor_directory(context->kind)) {
        if (!descriptor_access(*owner))
            return -13;
        fd = unsigned(pid(name));
        if ((!fd && strcmp(name, "0")) || fd >= max_fds || !owner->files)
            return -2;
        auto handle = owner->files->entries[fd].handle;
        if (!handle)
            return -2;
        kind = context->kind == Kind::fd_directory ? Kind::fd_link : Kind::fdinfo;
    } else if (context->kind == Kind::task_list) {
        selected_pid = pid(name);
        auto selected = task(selected_pid);
        if (!selected || selected->process->pid != group)
            return -2;
        kind = Kind::thread;
    } else
        return -2;
    auto state = static_cast<Proc*>(parent->mount->data);
    collect(state);
    for (auto child = parent->first_child; child; child = child->next_sibling)
        if (!strcmp(child->name, name) && !validate(child)) {
            refresh(child);
            if (kind == Kind::fd_link)
                refresh_fd_link(*entry(child));
            output = child;
            return 0;
        }
    auto result = make(state, parent->mount, parent, name, kind, selected_pid, group);
    if (!result)
        return -12;
    result->network_index = network_index;
    result->property = property;
    result->network_generation = network_generation;
    result->ipv4_configuration = ipv4_configuration;
    result->descriptor = fd;
    if (kind == Kind::fd_link) {
        result->node.size = 64;
        refresh_fd_link(*result);
    }
    if (is_control(kind)) {
        result->node.mode = regular_file | (kind == Kind::network_property && !ipv4_configuration &&
                                                    property == proc6::secret_property
                                                ? 0600
                                                : 0644);
        result->node.links = 1;
    }
    output = &result->node;
    return 0;
}

static int status(Node* node, Snapshot& snapshot) {
    auto owner = task(entry(node)->pid);
    if (!owner)
        return -3;
    auto groups = owner->credentials.groups;
    size_t capacity = 2048 + (groups ? size_t(groups->count) * 11 : 0);
    auto bytes = static_cast<char*>(alloc(capacity));
    if (!bytes)
        return -12;
    Text text{bytes, 0, capacity};
    text.string("Name:\t");
    const char* name = owner->name;
    for (size_t i = 0; name[i]; i++) {
        if (name[i] == '\n')
            text.string("\\n");
        else if (name[i] == '\\')
            text.string("\\\\");
        else
            text.character(name[i]);
    }
    text.string("\nUmask:\t");
    unsigned mask = owner->fs ? owner->fs->umask : 0;
    for (int shift = 9; shift >= 0; shift -= 3)
        text.character(char('0' + ((mask >> shift) & 7)));
    text.string("\nState:\t");
    text.string(owner->state == State::zombie    ? "Z (zombie)"
                : owner->state == State::stopped ? "T (stopped)"
                : owner->state == State::blocked ? "S (sleeping)"
                                                 : "R (running)");
    text.character('\n');
    text.field("Tgid", unsigned(owner->process->pid));
    text.field("Pid", unsigned(owner->pid));
    text.field("PPid", unsigned(owner->process->parent));
    text.field("TracerPid", 0);
    text.identity("Uid", owner->credentials.user);
    text.identity("Gid", owner->credentials.group);
    text.field("FDSize", max_fds);
    text.string("Groups:\t");
    if (groups)
        for (unsigned i = 0; i < groups->count; i++) {
            text.number(groups->ids[i]);
            text.character(' ');
        }
    text.character('\n');
    text.field("Threads", owner->process->live_threads ? owner->process->live_threads : 1);
    text.bits("SigPnd", owner->pending_signals.mask());
    text.bits("ShdPnd", owner->process->pending_signals.mask());
    text.bits("SigBlk", owner->signal_mask);
    text.bits("CapInh", owner->credentials.inheritable);
    text.bits("CapPrm", owner->credentials.permitted);
    text.bits("CapEff", owner->credentials.effective);
    text.bits("CapBnd", owner->credentials.bounding);
    text.bits("CapAmb", owner->credentials.ambient);
    text.field("NoNewPrivs", owner->credentials.no_new_privileges);
    if (text.failed) {
        release(bytes);
        return -75;
    }
    snapshot = {bytes, text.length};
    return 0;
}

static int stat(Node* node, Snapshot& snapshot) {
    auto owner = task(entry(node)->pid);
    if (!owner)
        return -3;
    constexpr size_t capacity = 2048;
    auto bytes = static_cast<char*>(alloc(capacity));
    if (!bytes)
        return -12;
    Text text{bytes, 0, capacity};
    text.number(unsigned(owner->pid));
    text.string(" (");
    text.string(owner->name);
    text.string(") ");
    text.character(owner->state == State::zombie    ? 'Z'
                   : owner->state == State::stopped ? 'T'
                   : owner->state == State::blocked ? 'S'
                                                    : 'R');
    // Keep the Linux field positions through exit_code (52). Accounting and
    // address-layout fields not yet collected by the kernel are zero.
    for (unsigned field = 4; field <= 52; field++) {
        text.character(' ');
        uint64_t value = 0;
        switch (field) {
        case 4:
            value = unsigned(owner->process->parent);
            break;
        case 5:
            value = unsigned(owner->process->pgid);
            break;
        case 6:
            value = unsigned(owner->process->sid);
            break;
        case 8:
            text.string("-1");
            continue;
        case 18:
            value = 20;
            break;
        case 20:
            value = owner->process->live_threads ? owner->process->live_threads : 1;
            break;
        case 22:
            value = owner->pid == owner->process->pid ? owner->process->start_ticks
                                                      : owner->start_ticks;
            break;
        case 31:
            value = owner->pending_signals.mask() & 0x7fffffff;
            break;
        case 32:
            value = owner->signal_mask & 0x7fffffff;
            break;
        case 33:
        case 34:
            if (owner->handlers)
                for (unsigned signal = 0; signal < 31; signal++) {
                    uint64_t handler = owner->handlers->signal_actions[signal][0];
                    if (field == 33 ? handler == 1 : handler > 1)
                        value |= 1ull << signal;
                }
            break;
        case 38:
            value = owner->pid == owner->process->pid ? 17 : 0;
            break;
        case 52:
            value = unsigned(owner->process->exit_status);
            break;
        }
        text.number(value);
    }
    text.character('\n');
    if (text.failed) {
        release(bytes);
        return -75;
    }
    snapshot = {bytes, text.length};
    return 0;
}

static int boot_id() {
    if (boot_identifier[0])
        return 0;
    uint8_t identifier[16]{};
    int error = random_read(identifier, sizeof(identifier));
    if (error) {
        random::erase(identifier, sizeof(identifier));
        return error;
    }
    identifier[6] = (identifier[6] & 15) | 0x40;
    identifier[8] = (identifier[8] & 63) | 0x80;
    Text text{boot_identifier, 0, sizeof(boot_identifier)};
    for (unsigned i = 0; i < sizeof(identifier); i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            text.character('-');
        text.character("0123456789abcdef"[identifier[i] >> 4]);
        text.character("0123456789abcdef"[identifier[i] & 15]);
    }
    text.character('\n');
    random::erase(identifier, sizeof(identifier));
    return 0;
}

static int epoll_fdinfo(Text& text, const Epoll& epoll) {
    for (const auto& item : epoll.items) {
        if (!item.live())
            continue;
        Node* inode;
        if (int error = descriptor_inode(*item.handle, inode))
            return error;
        text.string("tfd: ");
        text.number(item.fd, 10, 8);
        text.string(" events: ");
        text.number(item.enabled ? item.event.events | 0x18 : item.event.events & 0xf0000000, 16,
                    8);
        text.string(" data: ");
        text.number(item.event.data, 16, 16);
        text.string("  pos:");
        text.number(item.handle->offset);
        text.string(" ino:");
        text.number(inode->inode, 16);
        text.string(" sdev:");
        text.number(inode->mount->id, 16);
        text.character('\n');
    }
    return 0;
}

static void timespec(Text& text, const char* field, uint64_t ns) {
    text.string(field);
    text.string(": (");
    text.number(ns / 1000000000);
    text.string(", ");
    text.number(ns % 1000000000);
    text.string(")\n");
}

static int fdinfo(const Entry& item, Snapshot& output) {
    auto owner = task(item.pid);
    if (!owner || !owner->files)
        return -2;
    const auto& slot = owner->files->entries[item.descriptor];
    auto handle = slot.handle;
    if (!handle)
        return -2;
    Node* inode;
    if (int error = descriptor_inode(*handle, inode))
        return error;
    size_t capacity = 512;
    if (handle->epoll)
        for (const auto& watch : handle->epoll->items)
            if (watch.live())
                capacity += 144;
    if (handle->inotify)
        capacity += size_t(inotify_watch_count(*handle->inotify)) * 128;
    auto bytes = static_cast<char*>(alloc(capacity));
    if (!bytes)
        return -12;
    Text text{bytes, 0, capacity};
    text.field("pos", handle->offset);
    text.string("flags:\t0");
    text.number(file_status_flags(*handle) | (slot.cloexec ? 02000000 : 0), 8);
    text.character('\n');
    text.field("mnt_id", inode->mount->id);
    text.field("ino", inode->inode);

    int error = 0;
    if (handle->event) {
        auto event = eventfd_info(*handle->event);
        text.string("eventfd-count: ");
        text.number(event.count, 16, 16);
        text.string("\neventfd-id: ");
        text.number(handle->generation);
        text.string("\neventfd-semaphore: ");
        text.number(event.semaphore);
        text.character('\n');
    } else if (handle->signal_descriptor) {
        text.bits("sigmask", handle->signal_descriptor->mask);
    } else if (handle->timer) {
        auto timer = timerfd_info(*handle->timer);
        text.string("clockid: ");
        text.number(unsigned(timer.clock));
        text.string("\nticks: ");
        text.number(timer.pending);
        text.string("\nsettime flags: 0");
        text.number(timer.flags, 8);
        text.character('\n');
        timespec(text, "it_value", timer.setting.value);
        timespec(text, "it_interval", timer.setting.interval);
    } else if (handle->epoll) {
        error = epoll_fdinfo(text, *handle->epoll);
    } else if (handle->inotify) {
        inotify_visit_watches(
            *handle->inotify, &text,
            [](void* context, int wd, uint64_t inode, uint64_t mount, uint32_t mask) {
                auto& out = *static_cast<Text*>(context);
                out.string("inotify wd:");
                out.number(wd, 16);
                out.string(" ino:");
                out.number(inode, 16);
                out.string(" sdev:");
                out.number(mount, 16);
                out.string(" mask:");
                out.number(mask & ~inotify_unmount, 16);
                out.string(" ignored_mask:0 \n");
            });
    }
    if (error || text.failed) {
        release(bytes);
        return error ? error : -75;
    }
    output = {bytes, text.length};
    return 0;
}

static void cpuid(uint32_t leaf, uint32_t (&result)[4]) {
    uint32_t subleaf = 0;
    asm volatile("cpuid" : "+a"(leaf), "=b"(result[1]), "+c"(subleaf), "=d"(result[3]));
    result[0] = leaf;
    result[2] = subleaf;
}

static void cpu_info_number(Text& text, const char* field, unsigned value) {
    text.string(field);
    text.string("\t: ");
    text.number(value);
    text.character('\n');
}

static void cpu_information(Text& text) {
    uint32_t registers[4];
    cpuid(0, registers);
    const uint32_t maximum = registers[0];
    char vendor[13]{};
    memcpy(vendor, &registers[1], 4);
    memcpy(vendor + 4, &registers[3], 4);
    memcpy(vendor + 8, &registers[2], 4);
    cpu_info_number(text, "processor", 0);
    text.string("vendor_id\t: ");
    text.string(vendor);
    text.character('\n');
    if (maximum >= 1) {
        cpuid(1, registers);
        uint32_t signature = registers[0];
        unsigned family = (signature >> 8) & 15, model = (signature >> 4) & 15;
        if (family == 6 || family == 15)
            model |= (signature >> 12) & 0xf0;
        if (family == 15)
            family += (signature >> 20) & 255;
        cpu_info_number(text, "cpu family", family);
        cpu_info_number(text, "model", model);
        cpu_info_number(text, "stepping", signature & 15);
    }
    cpuid(0x80000000, registers);
    if (registers[0] >= 0x80000004) {
        char brand[49]{};
        for (unsigned part = 0; part < 3; ++part) {
            cpuid(0x80000002 + part, registers);
            memcpy(brand + part * sizeof(registers), registers, sizeof(registers));
        }
        const char* name = brand;
        while (*name == ' ')
            ++name;
        text.string("model name\t: ");
        text.string(name);
        text.character('\n');
    }
    text.character('\n');
}

static void mem_kib(Text& text, const char* label, uint64_t bytes) {
    text.string(label);
    text.string(": ");
    text.number(bytes / 1024, 10, 8);
    text.string(" kB\n");
}

static void cpu_stat_line(Text& text, const char* label, const CpuTotals& totals) {
    text.string(label);
    text.number(totals.user_ticks);
    text.string(" 0 ");
    text.number(totals.system_ticks);
    text.character(' ');
    text.number(totals.idle_ticks);
    text.string(" 0 0 0 0 0 0\n");
}

static void uptime_seconds(Text& text, uint64_t value) {
    text.number(value / 100);
    text.character('.');
    text.number(value % 100, 10, 2, '0');
}

static int system_snapshot(Kind kind, Snapshot& output) {
    constexpr size_t capacity = 1024;
    auto bytes = static_cast<char*>(alloc(capacity));
    if (!bytes)
        return -12;
    Text text{bytes, 0, capacity};
    if (kind == Kind::cpuinfo)
        cpu_information(text);
    else if (kind == Kind::meminfo) {
        auto ram = physical_memory_stats();
        mem_kib(text, "MemTotal", ram.total);
        mem_kib(text, "MemFree", ram.free);
        mem_kib(text, "MemAvailable", ram.free);
        mem_kib(text, "Buffers", block_buffer_bytes());
        mem_kib(text, "SwapTotal", 0);
        mem_kib(text, "SwapFree", 0);
    } else {
        auto totals = cpu_totals();
        if (kind == Kind::uptime) {
            uptime_seconds(text, ticks);
            text.character(' ');
            uptime_seconds(text, totals.idle_ticks);
            text.character('\n');
        } else {
            cpu_stat_line(text, "cpu  ", totals);
            cpu_stat_line(text, "cpu0 ", totals);
            const auto realtime = clock_realtime_ticks();
            text.string("btime ");
            text.number(realtime > ticks ? (realtime - ticks) / 100 : 0);
            text.character('\n');
        }
    }
    if (text.failed) {
        release(bytes);
        return -75;
    }
    output = {bytes, text.length};
    return 0;
}

static const char* filesystem_name(const Mount& mount) {
    if (mount.ops == &ext2_ops)
        return "ext2";
    if (mount.ops == &ramfs_ops)
        return "ramfs";
    if (mount.ops == &procfs_ops)
        return "proc";
    if (mount.ops == &posix_queue_filesystem())
        return "mqueue";
    return nullptr;
}

static void mount_path(Text& text, const char* path) {
    for (; *path; ++path) {
        if (*path == ' ' || *path == '\t' || *path == '\n' || *path == '\\') {
            text.character('\\');
            text.number(static_cast<unsigned char>(*path), 8, 3, '0');
        } else
            text.character(*path);
    }
}

static int mounts_snapshot(const Entry& item, Snapshot& output) {
    auto owner = task(item.pid);
    if (!owner || !owner->fs)
        return -2;
    auto boundary = owner->fs->root_node;
    constexpr size_t capacity = mount_table_limit * (4 * sizeof(Path::text) + 128);
    auto bytes = static_cast<char*>(alloc(capacity));
    if (!bytes)
        return -12;
    Text text{bytes, 0, capacity};
    unsigned cursor = 0;
    while (auto mount = next_mount(cursor)) {
        const char* type = filesystem_name(*mount);
        if (!type)
            continue;
        char path[sizeof(Path::text)];
        node_path(mount->root, path, sizeof(path), false, boundary);
        if (!path[0])
            continue;
        char device[block_name_size];
        if (mount->ops == &ext2_ops) {
            block_device_name(ext2_mount_device(*mount), device);
            text.string(device);
        } else
            text.string(type);
        text.character(' ');
        mount_path(text, path);
        text.character(' ');
        text.string(type);
        text.string(mount->readonly ? " ro" : " rw");
        if (mount->nosuid)
            text.string(",nosuid");
        if (mount->nodev)
            text.string(",nodev");
        if (mount->noexec)
            text.string(",noexec");
        text.string(" 0 0\n");
    }
    if (text.failed) {
        release(bytes);
        return -75;
    }
    output = {bytes, text.length};
    return 0;
}

static int make_snapshot(Node* node, Snapshot& output) {
    auto item = entry(node);
    if (item->kind == Kind::fdinfo)
        return fdinfo(*item, output);
    if (item->kind == Kind::mounts)
        return mounts_snapshot(*item, output);
    if (item->kind == Kind::comm) {
        auto owner = task(item->pid);
        if (!owner)
            return -3;
        size_t length = strlen(owner->name);
        auto bytes = static_cast<char*>(alloc(length + 1));
        if (!bytes)
            return -12;
        memcpy(bytes, owner->name, length);
        bytes[length] = '\n';
        output = {bytes, length + 1};
        return 0;
    }
    if (item->kind == Kind::filesystem_types) {
        constexpr char types[] =
            "nodev\tramfs\nnodev\tproc\nnodev\tmqueue\n\text2\n\text3\n\text4\n";
        auto bytes = static_cast<char*>(alloc(sizeof(types)));
        if (!bytes)
            return -12;
        memcpy(bytes, types, sizeof(types));
        output = {bytes, sizeof(types) - 1};
        return 0;
    }
    if (item->kind == Kind::cpuinfo || item->kind == Kind::meminfo ||
        item->kind == Kind::system_stat || item->kind == Kind::uptime)
        return system_snapshot(item->kind, output);
    return item->kind == Kind::stat ? stat(node, output) : status(node, output);
}

static int64_t copy(const char* bytes, size_t size, uint64_t offset, void* output, size_t length) {
    if (offset >= size)
        return 0;
    size_t count = min(size - size_t(offset), length);
    memcpy(output, bytes + offset, count);
    return int64_t(count);
}

static int64_t file_link(Node* dentry, bool anonymous, uint64_t offset, void* output,
                         size_t length) {
    char target[2048]{};
    if (anonymous) {
        target[0] = '/';
        memcpy(target + 1, dentry->name, strlen(dentry->name) + 1);
    } else {
        node_path(dentry, target, sizeof(target), true);
        if (!target[0])
            return -2;
    }
    if (dentry->removed || anonymous) {
        constexpr char deleted[] = " (deleted)";
        size_t end = strlen(target);
        if (sizeof(deleted) > sizeof(target) - end)
            return -36;
        memcpy(target + end, deleted, sizeof(deleted));
    }
    return copy(target, strlen(target), offset, output, length);
}

static size_t read_arguments(AddressSpace& space, uint64_t address, void* output, size_t length) {
    auto bytes = static_cast<char*>(output);
    size_t copied = 0;
    while (copied < length) {
        size_t count = min(length - copied, page_size - (address % page_size));
        auto entry = space.entry(address);
        if (!entry || (*entry & page_file) || !(*entry & (page_stack | page_anonymous)) ||
            !space.copy_in(bytes + copied, address, count))
            break;
        copied += count;
        address += count;
    }
    return copied;
}

static int64_t read_cmdline(const Entry& item, uint64_t offset, void* output, size_t length) {
    auto owner = task(item.pid);
    if (!owner)
        return -3;
    auto memory = owner->memory;
    if (!memory || owner->state == State::zombie)
        return 0;
    auto bounds = memory->arguments;
    if (bounds.begin >= bounds.end || offset >= bounds.environment_end - bounds.begin || !length)
        return 0;
    auto& space = memory->space;
    char last;
    if (read_arguments(space, bounds.end - 1, &last, 1) && last) {
        // A rewritten process title can extend into contiguous environment storage.
        size_t size = min(size_t(bounds.environment_end - bounds.begin), page_size);
        if (offset >= size)
            return 0;
        auto title = static_cast<char*>(alloc(size));
        if (!title)
            return -12;
        size_t available = read_arguments(space, bounds.begin, title, size);
        size_t used = 0;
        while (used < available && title[used])
            ++used;
        if (used < available)
            ++used;
        int64_t result = copy(title, used, offset, output, length);
        release(title);
        return result;
    }
    size_t size = bounds.end - bounds.begin;
    if (offset >= size)
        return 0;
    return read_arguments(space, bounds.begin + offset, output, min(length, size - offset));
}

static int64_t read(Node* node, uint64_t offset, void* output, size_t length) {
    auto kind = entry(node)->kind;
    if (kind == Kind::cmdline)
        return read_cmdline(*entry(node), offset, output, length);
    if (kind == Kind::self || kind == Kind::thread_self) {
        char target[40];
        size_t size = link_target(kind, target);
        return copy(target, size, offset, output, length);
    }
    if (kind == Kind::mounts_link)
        return copy("self/mounts", sizeof("self/mounts") - 1, offset, output, length);
    if (kind == Kind::exe_link) {
        Node* target = nullptr;
        int error = link_executable(*entry(node), target);
        return error ? error
                     : file_link(target, is_memfd(file_node(target)), offset, output, length);
    }
    if (kind == Kind::fd_link) {
        Handle* handle = nullptr;
        if (int error = link_descriptor(*entry(node), handle))
            return error;
        Node* inode;
        if (int error = descriptor_inode(*handle, inode))
            return error;
        if (auto name = descriptor_inode_name(inode))
            return copy(name, strlen(name), offset, output, length);
        auto dentry = handle->opened_dentry ? handle->opened_dentry : inode;
        return file_link(dentry, is_memfd(handle->node), offset, output, length);
    }
    if (kind == Kind::boot_id) {
        int error = boot_id();
        return error ? error
                     : copy(boot_identifier, sizeof(boot_identifier), offset, output, length);
    }
    if (!snapshot_file(kind))
        return -21;
    Snapshot snapshot{};
    int error = make_snapshot(node, snapshot);
    if (error)
        return error;
    int64_t count = copy(snapshot.bytes, snapshot.length, offset, output, length);
    release(snapshot.bytes);
    return count;
}

static int64_t read_description(Handle* handle, uint64_t offset, void* output, size_t length) {
    auto kind = entry(handle->node)->kind;
    if (!snapshot_file(kind))
        return read(handle->node, offset, output, length);
    auto snapshot = static_cast<Snapshot*>(handle->filesystem_data);
    if (!snapshot) {
        snapshot = static_cast<Snapshot*>(alloc(sizeof(Snapshot)));
        if (!snapshot)
            return -12;
        *snapshot = {};
        handle->filesystem_data = snapshot;
    }
    if (!snapshot->bytes || !offset) {
        Snapshot next{};
        int error = make_snapshot(handle->node, next);
        if (error)
            return error;
        release(snapshot->bytes);
        *snapshot = next;
    }
    return copy(snapshot->bytes, snapshot->length, offset, output, length);
}

static void close_description(Handle* handle) {
    auto snapshot = static_cast<Snapshot*>(handle->filesystem_data);
    if (snapshot) {
        release(snapshot->bytes);
        release(snapshot);
        handle->filesystem_data = nullptr;
    }
}

static int control_access(Node* node, unsigned mask, bool real) {
    if (mask & 1)
        return -13;
    const Credentials boot{};
    const auto& credentials = current ? current->credentials : boot;
    uint64_t capabilities = credentials.effective;
    // access(2) substitutes the real user's capability set unless securebits
    // disable the normal setuid fixups. sysctl ownership still uses euid/egid.
    if (real && !(credentials.securebits & 4))
        capabilities = credentials.user.real ? 0 : credentials.permitted;
    bool administrator = entry(node)->kind != Kind::pipe_limit &&
                         (capabilities & (1ull << unsigned(Capability::net_admin)));
    bool group = !credentials.group.effective;
    if (credentials.groups)
        for (unsigned at = 0; at < credentials.groups->count; at++)
            group |= !credentials.groups->ids[at];
    unsigned mode = node->mode & 0777;
    unsigned allowed = administrator || !credentials.user.effective ? mode >> 6
                       : group                                      ? mode >> 3
                                                                    : mode;
    return mask & ~allowed & 7 ? -13 : 0;
}

static int64_t control_read(Handle* handle, void* output, size_t length) {
    if (int error = validate(handle->node))
        return error;
    auto item = entry(handle->node);
    if (item->kind == Kind::pipe_limit)
        return proc::read_unsigned_long(pipe_limit(PipeLimit(item->property)), handle->offset,
                                        output, length);
    if (item->kind == Kind::source_limit)
        return proc4::source_limit_read(handle->offset, output, length);
    if (item->ipv4_configuration)
        return proc4::read(item->network_index, item->property, handle->offset, output, length);
    return proc6::read(item->network_index, item->property, handle->offset, output, length);
}

static int64_t pipe_limit_write(PipeLimit limit, uint64_t& offset, const void* input,
                                size_t length) {
    if (!length)
        return 0;
    if (offset) {
        offset += length;
        return int64_t(length);
    }
    uint64_t value;
    size_t consumed, parsed = min(length, size_t(4095));
    if (!proc::parse_unsigned_long(static_cast<const char*>(input), parsed, value, consumed))
        return -22;
    if (int error = set_pipe_limit(limit, value))
        return error;
    if (limit == PipeLimit::max_size)
        consumed = parsed;
    consumed += length - parsed;
    offset += consumed;
    return int64_t(consumed);
}

static int64_t control_write(Handle* handle, const void* input, size_t length) {
    if (int error = validate(handle->node))
        return error;
    auto item = entry(handle->node);
    if (item->kind == Kind::pipe_limit)
        return pipe_limit_write(PipeLimit(item->property), handle->offset, input, length);
    if (item->kind == Kind::source_limit)
        return proc4::source_limit_write(handle->offset, input, length);
    if (item->ipv4_configuration) {
        // A transferred description does not retain its opener's sysctl rights.
        if (control_access(handle->node, 2, false))
            return -1;
        if (item->property == proc4::forwarding_property && current &&
            !(current->credentials.effective & (1ull << unsigned(Capability::net_admin))))
            return -1;
        return proc4::write(item->network_index, item->property, handle->offset, input, length);
    }
    return proc6::write(item->network_index, item->property, handle->offset, input, length);
}

static int control_truncate(Node*, size_t) {
    return 0;
}

static const ControlFileOps* control(Node* node) {
    static const ControlFileOps ops{control_access, control_read, control_write, control_truncate};
    return is_control(entry(node)->kind) ? &ops : nullptr;
}

static int readdir(Node* node, uint64_t cookie, DirectoryEntry& result) {
    if (int error = validate(node))
        return error;
    auto context = entry(node);
    auto owner = context->pid ? task(context->pid) : nullptr;
    if (context->pid && !owner)
        return -2;
    if (descriptor_directory(context->kind) && !descriptor_access(*owner))
        return -13;
    if (cookie < 2) {
        auto selected = cookie ? directory_parent(node) : node;
        result.inode = selected->inode;
        result.next = cookie + 1;
        result.mode = directory;
        memcpy(result.name, cookie ? ".." : ".", cookie ? 3 : 2);
        return 1;
    }
    char name[256];
    if (context->kind == Kind::root && cookie < root_children + 2) {
        const char* link = root_names[cookie - 2];
        Node* selected = nullptr;
        int error = lookup(node, link, selected);
        if (error)
            return error;
        result.inode = selected->inode;
        result.next = cookie + 1;
        result.mode = selected->mode;
        memcpy(result.name, link, strlen(link) + 1);
        return 1;
    }
    if (context->kind == Kind::root || context->kind == Kind::task_list) {
        uint64_t bias = context->kind == Kind::root ? root_children + 2 : 2;
        int selected_pid = 0;
        for (auto& candidate : tasks) {
            if (candidate.state == State::empty || !candidate.process ||
                uint64_t(candidate.pid) + bias <= cookie)
                continue;
            if (context->kind == Kind::root ? candidate.pid != candidate.process->pid
                                            : candidate.process->pid != context->tgid)
                continue;
            if (!selected_pid || candidate.pid < selected_pid)
                selected_pid = candidate.pid;
        }
        if (!selected_pid)
            return 0;
        decimal(selected_pid, name);
        result.next = uint64_t(selected_pid) + bias;
    } else if (context->kind == Kind::process || context->kind == Kind::thread) {
        if (cookie == 2) {
            memcpy(name, "status", 7);
            result.next = 3;
        } else if (cookie == 3) {
            memcpy(name, "stat", 5);
            result.next = 4;
        } else if (cookie == 4) {
            memcpy(name, "fd", 3);
            result.next = 5;
        } else if (cookie == 5) {
            memcpy(name, "fdinfo", 7);
            result.next = 6;
        } else if (cookie == 6) {
            memcpy(name, "exe", 4);
            result.next = 7;
        } else if (cookie == 7) {
            memcpy(name, "mounts", 7);
            result.next = 8;
        } else if (cookie == 8) {
            memcpy(name, "comm", 5);
            result.next = 9;
        } else if (cookie == 9) {
            memcpy(name, "cmdline", 8);
            result.next = 10;
        } else if (cookie == 10 && context->kind == Kind::process) {
            memcpy(name, "task", 5);
            result.next = 11;
        } else
            return 0;
    } else if (descriptor_directory(context->kind)) {
        if (!owner->files)
            return 0;
        for (; cookie - 2 < max_fds; cookie++) {
            auto handle = owner->files->entries[cookie - 2].handle;
            if (handle)
                break;
        }
        if (cookie - 2 >= max_fds)
            return 0;
        decimal(int(cookie - 2), name);
        result.next = cookie + 1;
    } else if (context->kind == Kind::sys || context->kind == Kind::fs) {
        if (cookie - 2 >= 3)
            return 0;
        auto names = context->kind == Kind::sys ? sys_directories : pipe_limit_names;
        const char* child = names[cookie - 2];
        memcpy(name, child, strlen(child) + 1);
        result.next = cookie + 1;
    } else if (context->kind == Kind::kernel || context->kind == Kind::random ||
               context->kind == Kind::net || context->kind == Kind::ipv6 ||
               context->kind == Kind::ipv4) {
        unsigned last = context->kind == Kind::ipv4 ? 4u : context->kind == Kind::net ? 3u : 2u;
        if (cookie > last)
            return 0;
        const char* child = context->kind == Kind::kernel ? "random"
                            : context->kind == Kind::net  ? (cookie == 2 ? "ipv6" : "ipv4")
                            : context->kind == Kind::ipv4 ? (cookie == 2   ? "igmp_max_msf"
                                                             : cookie == 3 ? "conf"
                                                                           : "ip_forward")
                            : context->kind == Kind::ipv6 ? "conf"
                                                          : "boot_id";
        memcpy(name, child, strlen(child) + 1);
        result.next = cookie + 1;
    } else if (context->kind == Kind::conf) {
        const char* selected = nullptr;
        for (; cookie - 2 < max_net_devices + 3; cookie++)
            if ((selected = context->ipv4_configuration ? proc4::scope_name(unsigned(cookie - 2))
                                                        : proc6::scope_name(unsigned(cookie - 2))))
                break;
        if (!selected)
            return 0;
        memcpy(name, selected, strlen(selected) + 1);
        result.next = cookie + 1;
    } else if (context->kind == Kind::network_scope) {
        if (cookie - 2 >=
            (context->ipv4_configuration ? proc4::property_count : proc6::property_count))
            return 0;
        auto selected = context->ipv4_configuration ? proc4::property_name(unsigned(cookie - 2))
                                                    : proc6::property_name(unsigned(cookie - 2));
        memcpy(name, selected, strlen(selected) + 1);
        result.next = cookie + 1;
    } else
        return -20;
    Node* selected = nullptr;
    int error = lookup(node, name, selected);
    if (error)
        return error;
    result.inode = selected->inode;
    result.mode = selected->mode;
    memcpy(result.name, name, strlen(name) + 1);
    return 1;
}

static int create(Node*, const char*, uint32_t, const char*, Node*&) {
    return -30;
}

static int link(Node*, Node*, const char*) {
    return -30;
}

static int remove(Node*) {
    return -30;
}

static int rename(Node*, Node*, const char*, Node*) {
    return -30;
}

static int64_t write(Node* node, uint64_t, const void* input, size_t length) {
    auto item = entry(node);
    if (item->kind != Kind::comm)
        return -22;
    auto owner = task(item->pid);
    if (!owner)
        return -3;
    if (!current || owner->process != current->process)
        return -22;
    owner->set_name(static_cast<const char*>(input), length);
    return int64_t(length);
}

static int truncate(Node* node, size_t) {
    return entry(node)->kind == Kind::comm ? 0 : -30;
}

static int setattr(Node* node, uint32_t, Timestamp, Timestamp, uint32_t, uint32_t) {
    return is_control(entry(node)->kind) ? -1 : -30;
}

static int sync(Mount*, Node*, bool) {
    return 0;
}

static int map_shared(Node*, uint64_t, size_t, uint64_t&) {
    return -19;
}

static int stats(Mount* mount, FilesystemStats& result) {
    auto state = static_cast<Proc*>(mount->data);
    result = {0x9fa0, 4096, 0, 0, state->count, 4096 - state->count};
    return 0;
}

static void destroy(Mount* mount) {
    auto state = static_cast<Proc*>(mount->data);
    while (state->entries) {
        auto item = state->entries;
        state->entries = item->next;
        release(item);
    }
    release(state);
}
} // namespace

const FilesystemOps procfs_ops = {lookup,
                                  create,
                                  link,
                                  remove,
                                  rename,
                                  read,
                                  write,
                                  truncate,
                                  setattr,
                                  readdir,
                                  sync,
                                  map_shared,
                                  stats,
                                  destroy,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  refresh,
                                  read_description,
                                  close_description,
                                  control,
                                  validate,
                                  follow_link,
                                  access_override};

bool procfs_has_poll(const Node& node) {
    auto kind = static_cast<const Entry*>(node.filesystem_data)->kind;
    return kind == Kind::boot_id || is_control(kind);
}

Node* procfs_root(Mount* mount) {
    auto state = static_cast<Proc*>(alloc(sizeof(Proc)));
    if (!state)
        return nullptr;
    *state = {};
    mount->data = state;
    auto root = make(state, mount, nullptr, "", Kind::root, 0, 0);
    if (!root) {
        release(state);
        mount->data = nullptr;
        return nullptr;
    }
    return &root->node;
}
} // namespace ax
