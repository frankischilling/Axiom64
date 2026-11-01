// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/proc.hpp"
#include "fs/proc/ipv6.hpp"
#include "fs/proc/ipv4.hpp"
#include "net/ethernet.hpp"
#include "process/task.hpp"
#include "core/random.hpp"
#include "core/random/primitives.hpp"

namespace ax {
namespace {
enum class Kind {
    root,
    self,
    thread_self,
    process,
    task_list,
    thread,
    status,
    stat,
    sys,
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

struct Entry {
    Node node{};
    Entry* next = nullptr;
    Kind kind;
    int pid, tgid;
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

    void number(uint64_t value) {
        char digits[20];
        size_t count = 0;
        do {
            digits[count++] = char('0' + value % 10);
            value /= 10;
        } while (value);
        while (count)
            character(digits[--count]);
    }

    void hexadecimal(uint64_t value) {
        for (int shift = 60; shift >= 0; shift -= 4)
            character("0123456789abcdef"[(value >> shift) & 15]);
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
                 (item->kind == Kind::network_scope && validate(&item->node))) &&
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
    node->mode = kind == Kind::status || kind == Kind::stat || kind == Kind::boot_id
                     ? regular_file | 0444
                 : kind == Kind::self || kind == Kind::thread_self ? symlink | 0777
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
    unsigned network_index = context->network_index, property = 0;
    uint64_t network_generation = context->network_generation;
    bool ipv4_configuration = context->ipv4_configuration || context->kind == Kind::ipv4;
    if (context->kind == Kind::root && !strcmp(name, "self"))
        kind = Kind::self;
    else if (context->kind == Kind::root && !strcmp(name, "thread-self"))
        kind = Kind::thread_self;
    else if (context->kind == Kind::root && !strcmp(name, "sys"))
        kind = Kind::sys;
    else if (context->kind == Kind::sys && !strcmp(name, "kernel"))
        kind = Kind::kernel;
    else if (context->kind == Kind::sys && !strcmp(name, "net"))
        kind = Kind::net;
    else if (context->kind == Kind::net && !strcmp(name, "ipv6"))
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
    else if (context->kind == Kind::root) {
        selected_pid = pid(name);
        auto selected = task(selected_pid);
        if (!selected)
            return -2;
        group = selected->process->pid;
        kind = Kind::process;
    } else if ((context->kind == Kind::process || context->kind == Kind::thread) &&
               !strcmp(name, "status"))
        kind = Kind::status;
    else if ((context->kind == Kind::process || context->kind == Kind::thread) &&
             !strcmp(name, "stat"))
        kind = Kind::stat;
    else if (context->kind == Kind::process && !strcmp(name, "task"))
        kind = Kind::task_list;
    else if (context->kind == Kind::task_list) {
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
    if (kind == Kind::network_property || kind == Kind::source_limit ||
        kind == Kind::ipv4_forward) {
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
    const char* name = owner->process->executable;
    for (auto cursor = name; *cursor; cursor++)
        if (*cursor == '/')
            name = cursor + 1;
    for (size_t i = 0; name[i] && i < 15; i++) {
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
    text.bits("SigPnd", owner->pending_signals);
    text.bits("ShdPnd", owner->process->pending_signals);
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
    const char* name = owner->process->executable;
    for (auto cursor = name; *cursor; cursor++)
        if (*cursor == '/')
            name = cursor + 1;
    for (size_t i = 0; name[i] && i < 15; i++)
        text.character(name[i]);
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
            value = owner->pending_signals & 0x7fffffff;
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

static int make_snapshot(Node* node, Snapshot& output) {
    return entry(node)->kind == Kind::stat ? stat(node, output) : status(node, output);
}

static int64_t copy(const char* bytes, size_t size, uint64_t offset, void* output, size_t length) {
    if (offset >= size)
        return 0;
    size_t count = min(size - size_t(offset), length);
    memcpy(output, bytes + offset, count);
    return int64_t(count);
}

static int64_t read(Node* node, uint64_t offset, void* output, size_t length) {
    auto kind = entry(node)->kind;
    if (kind == Kind::self || kind == Kind::thread_self) {
        char target[40];
        size_t size = link_target(kind, target);
        return copy(target, size, offset, output, length);
    }
    if (kind == Kind::boot_id) {
        int error = boot_id();
        return error ? error
                     : copy(boot_identifier, sizeof(boot_identifier), offset, output, length);
    }
    if (kind != Kind::status && kind != Kind::stat)
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
    if (kind != Kind::status && kind != Kind::stat)
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
    bool administrator = capabilities & (1ull << unsigned(Capability::net_admin));
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
    if (item->kind == Kind::source_limit)
        return proc4::source_limit_read(handle->offset, output, length);
    if (item->ipv4_configuration)
        return proc4::read(item->network_index, item->property, handle->offset, output, length);
    return proc6::read(item->network_index, item->property, handle->offset, output, length);
}

static int64_t control_write(Handle* handle, const void* input, size_t length) {
    if (int error = validate(handle->node))
        return error;
    auto item = entry(handle->node);
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
    auto kind = entry(node)->kind;
    return kind == Kind::network_property || kind == Kind::source_limit ||
                   kind == Kind::ipv4_forward
               ? &ops
               : nullptr;
}

static int readdir(Node* node, uint64_t cookie, DirectoryEntry& result) {
    if (int error = validate(node))
        return error;
    auto context = entry(node);
    if (context->pid && !task(context->pid))
        return -2;
    if (cookie < 2) {
        auto selected = cookie ? directory_parent(node) : node;
        result.inode = selected->inode;
        result.next = cookie + 1;
        result.mode = directory;
        memcpy(result.name, cookie ? ".." : ".", cookie ? 3 : 2);
        return 1;
    }
    char name[256];
    if (context->kind == Kind::root && cookie < 5) {
        const char* link = cookie == 2 ? "self" : cookie == 3 ? "thread-self" : "sys";
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
        uint64_t bias = context->kind == Kind::root ? 5 : 2;
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
        } else if (cookie == 4 && context->kind == Kind::process) {
            memcpy(name, "task", 5);
            result.next = 5;
        } else
            return 0;
    } else if (context->kind == Kind::sys || context->kind == Kind::kernel ||
               context->kind == Kind::random || context->kind == Kind::net ||
               context->kind == Kind::ipv6 || context->kind == Kind::ipv4) {
        unsigned last = context->kind == Kind::ipv4                                ? 4u
                        : context->kind == Kind::sys || context->kind == Kind::net ? 3u
                                                                                   : 2u;
        if (cookie > last)
            return 0;
        const char* child = context->kind == Kind::sys      ? (cookie == 2 ? "kernel" : "net")
                            : context->kind == Kind::kernel ? "random"
                            : context->kind == Kind::net    ? (cookie == 2 ? "ipv6" : "ipv4")
                            : context->kind == Kind::ipv4   ? (cookie == 2   ? "igmp_max_msf"
                                                               : cookie == 3 ? "conf"
                                                                             : "ip_forward")
                            : context->kind == Kind::ipv6   ? "conf"
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

static int64_t write(Node*, uint64_t, const void*, size_t) {
    return -22;
}

static int truncate(Node*, size_t) {
    return -30;
}

static int setattr(Node* node, uint32_t, Timestamp, Timestamp, uint32_t, uint32_t) {
    auto kind = entry(node)->kind;
    return kind == Kind::network_property || kind == Kind::source_limit ||
                   kind == Kind::ipv4_forward
               ? -1
               : -30;
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
                                  validate};

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
