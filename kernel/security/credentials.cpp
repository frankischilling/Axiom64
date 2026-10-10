// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/credentials.hpp"
#include "core/base.hpp"

namespace ax {
namespace {
constexpr uint32_t unchanged = UINT32_MAX;
constexpr uint32_t noroot = 1, no_setuid_fixup = 4, keep_caps = 16, no_ambient_raise = 64;
constexpr uint64_t filesystem_caps = (1ull << 0) | (1ull << 1) | (1ull << 2) | (1ull << 3) |
                                     (1ull << 4) | (1ull << 9) | (1ull << 32);

void user_transition(Credentials& next, const Identity& old) {
    if (next.securebits & no_setuid_fixup)
        return;
    const auto& id = next.user;
    if ((!old.real || !old.effective || !old.saved) && id.real && id.effective && id.saved) {
        if (!(next.securebits & keep_caps))
            next.permitted = next.effective = 0;
        next.ambient = 0;
    }
    if (!old.effective && id.effective)
        next.effective = 0;
    else if (old.effective && !id.effective)
        next.effective = next.permitted;
}

bool existing(const Identity& id, uint32_t value) {
    return value == id.real || value == id.effective || value == id.saved;
}

void sift(uint32_t* ids, unsigned root, unsigned count) {
    while (root < count / 2) {
        unsigned child = root * 2 + 1;
        if (child + 1 < count && ids[child] < ids[child + 1])
            child++;
        if (ids[root] >= ids[child])
            return;
        uint32_t value = ids[root];
        ids[root] = ids[child];
        ids[child] = value;
        root = child;
    }
}
} // namespace

bool capable(const Credentials& cred, Capability capability) {
    return cred.effective & (1ull << unsigned(capability));
}

bool credential_group(const Credentials& cred, uint32_t id, bool real) {
    if (id == (real ? cred.group.real : cred.group.filesystem))
        return true;
    if (!cred.groups)
        return false;
    unsigned begin = 0, end = cred.groups->count;
    while (begin < end) {
        unsigned middle = begin + (end - begin) / 2;
        uint32_t value = cred.groups->ids[middle];
        if (value == id)
            return true;
        if (value < id)
            begin = middle + 1;
        else
            end = middle;
    }
    return false;
}

GroupList* groups_allocate(unsigned count) {
    if (count > maximum_groups)
        return nullptr;
    auto list =
        static_cast<GroupList*>(alloc(sizeof(GroupList) + size_t(count) * sizeof(uint32_t)));
    if (list) {
        list->references = 1;
        list->count = count;
    }
    return list;
}

void groups_release(GroupList* list) {
    if (list && !--list->references)
        release(list);
}

void credential_release(Credentials& cred) {
    groups_release(cred.groups);
    cred.groups = nullptr;
}

void credential_inherit(Credentials& target, const Credentials& source) {
    if (&target == &source)
        return;
    if (source.groups)
        source.groups->references++;
    credential_release(target);
    target = source;
}

int credential_groups(Credentials& cred, GroupList* list) {
    if (!capable(cred, Capability::setgid))
        return -1;
    if (!list || list->count > maximum_groups || list->references != 1)
        return -22;
    for (unsigned at = 0; at < list->count; at++)
        if (list->ids[at] == unchanged)
            return -22;
    for (unsigned at = list->count / 2; at; at--)
        sift(list->ids, at - 1, list->count);
    for (unsigned end = list->count; end > 1; end--) {
        uint32_t value = list->ids[0];
        list->ids[0] = list->ids[end - 1];
        list->ids[end - 1] = value;
        sift(list->ids, 0, end - 1);
    }
    list->references++;
    groups_release(cred.groups);
    cred.groups = list;
    return 0;
}

int credential_identity(Credentials& cred, bool group, IdentityChange change, uint32_t real,
                        uint32_t effective, uint32_t saved) {
    const Identity old = group ? cred.group : cred.user;
    Identity next = old;
    bool privilege = capable(cred, group ? Capability::setgid : Capability::setuid);
    if (change == IdentityChange::single) {
        if (real == unchanged)
            return -22;
        if (privilege)
            next.real = next.effective = next.saved = next.filesystem = real;
        else {
            if (real != old.real && real != old.saved)
                return -1;
            next.effective = next.filesystem = real;
        }
    } else if (change == IdentityChange::real_effective) {
        if (!privilege && ((real != unchanged && real != old.real && real != old.effective) ||
                           (effective != unchanged && !existing(old, effective))))
            return -1;
        if (real != unchanged)
            next.real = real;
        if (effective != unchanged)
            next.effective = effective;
        if (real != unchanged || (effective != unchanged && effective != old.real))
            next.saved = next.effective;
        next.filesystem = next.effective;
    } else {
        if (!privilege && ((real != unchanged && !existing(old, real)) ||
                           (effective != unchanged && !existing(old, effective)) ||
                           (saved != unchanged && !existing(old, saved))))
            return -1;
        if (real != unchanged)
            next.real = real;
        if (effective != unchanged)
            next.effective = effective;
        if (saved != unchanged)
            next.saved = saved;
        next.filesystem = next.effective;
    }
    if (group)
        cred.group = next;
    else {
        cred.user = next;
        user_transition(cred, old);
    }
    return 0;
}

uint32_t credential_filesystem(Credentials& cred, bool group, uint32_t value) {
    auto& id = group ? cred.group : cred.user;
    uint32_t previous = id.filesystem;
    if (value == unchanged || (!existing(id, value) && value != previous &&
                               !capable(cred, group ? Capability::setgid : Capability::setuid)))
        return previous;
    id.filesystem = value;
    if (!group && !(cred.securebits & no_setuid_fixup)) {
        if (!previous && value)
            cred.effective &= ~filesystem_caps;
        else if (previous && !value)
            cred.effective |= cred.permitted & filesystem_caps;
    }
    return previous;
}

int credential_capabilities(Credentials& cred, uint64_t effective, uint64_t permitted,
                            uint64_t inheritable) {
    effective &= all_capabilities;
    permitted &= all_capabilities;
    inheritable &= all_capabilities;
    if ((permitted & ~cred.permitted) || (effective & ~permitted) ||
        (inheritable & ~(cred.inheritable | cred.bounding)) ||
        (!capable(cred, Capability::setpcap) &&
         (inheritable & ~(cred.inheritable | cred.permitted))))
        return -1;
    cred.effective = effective;
    cred.permitted = permitted;
    cred.inheritable = inheritable;
    cred.ambient &= permitted & inheritable;
    return 0;
}

int64_t credential_control(Credentials& cred, unsigned option, uint64_t a, uint64_t b, uint64_t c,
                           uint64_t d) {
    switch (option) {
    case 7:
        return bool(cred.securebits & keep_caps);
    case 8:
        if (a > 1)
            return -22;
        if (cred.securebits & (keep_caps << 1))
            return -1;
        cred.securebits = (cred.securebits & ~keep_caps) | (a ? keep_caps : 0);
        return 0;
    case 23:
        return a > 40 ? -22 : bool(cred.bounding & (1ull << a));
    case 24:
        if (!capable(cred, Capability::setpcap))
            return -1;
        if (a > 40)
            return -22;
        cred.bounding &= ~(1ull << a);
        return 0;
    case 27:
        return cred.securebits;
    case 28: {
        constexpr uint32_t locks = 0xaa;
        if (!capable(cred, Capability::setpcap) || (a & ~0xffull) ||
            (((cred.securebits & locks) >> 1) & (cred.securebits ^ a)) ||
            (cred.securebits & locks & ~a))
            return -1;
        cred.securebits = a;
        return 0;
    }
    case 38:
        if (a != 1 || b || c || d)
            return -22;
        cred.no_new_privileges = true;
        return 0;
    case 39:
        return a || b || c || d ? -22 : cred.no_new_privileges;
    case 47:
        if (c || d || (a == 4 ? b != 0 : b > 40))
            return -22;
        if (a == 1)
            return bool(cred.ambient & (1ull << b));
        if (a == 2) {
            if ((cred.securebits & no_ambient_raise) ||
                !(cred.permitted & cred.inheritable & (1ull << b)))
                return -1;
            cred.ambient |= 1ull << b;
        } else if (a == 3)
            cred.ambient &= ~(1ull << b);
        else if (a == 4)
            cred.ambient = 0;
        else
            return -22;
        return 0;
    default:
        return -22;
    }
}

Credentials credential_exec(const Credentials& old, uint32_t uid, uint32_t gid, uint32_t mode,
                            bool nosuid) {
    Credentials next = old;
    if (!nosuid && !old.no_new_privileges) {
        if (mode & 04000)
            next.user.effective = uid;
        if ((mode & 02010) == 02010)
            next.group.effective = gid;
    }
    next.user.saved = next.user.filesystem = next.user.effective;
    next.group.saved = next.group.filesystem = next.group.effective;
    if (next.user.effective != old.user.effective || !credential_group(old, next.group.effective))
        next.ambient = 0;
    next.permitted = next.effective = next.ambient;
    if (!(old.securebits & noroot) && (!next.user.real || !next.user.effective)) {
        next.permitted |= old.bounding | old.inheritable;
        if (!next.user.effective)
            next.effective = next.permitted;
    }
    if (old.no_new_privileges) {
        next.permitted &= old.permitted;
        next.effective &= next.permitted;
    }
    next.securebits &= ~keep_caps;
    return next;
}

int credential_access(const Credentials& cred, uint32_t uid, uint32_t gid, uint32_t mode,
                      unsigned mask, bool real) {
    if (mask & ~7u)
        return -22;
    uint32_t user = real ? cred.user.real : cred.user.filesystem;
    unsigned allowed = user == uid                         ? mode >> 6
                       : credential_group(cred, gid, real) ? mode >> 3
                                                           : mode;
    if ((allowed & mask) == mask)
        return 0;
    uint64_t capabilities = real ? (cred.user.real ? 0 : cred.permitted) : cred.effective;
    bool directory = (mode & 0170000) == 0040000;
    if ((capabilities & (1ull << unsigned(Capability::dac_override))) &&
        (!(mask & 1) || directory || (mode & 0111)))
        return 0;
    if (!(mask & 2) && (directory || !(mask & 1)) &&
        (capabilities & (1ull << unsigned(Capability::dac_read_search))))
        return 0;
    return -13;
}

bool credential_signal(const Credentials& from, const Credentials& target, bool same_session,
                       unsigned signal) {
    return capable(from, Capability::kill) || from.user.real == target.user.real ||
           from.user.real == target.user.saved || from.user.effective == target.user.real ||
           from.user.effective == target.user.saved || (signal == 18 && same_session);
}
} // namespace ax
