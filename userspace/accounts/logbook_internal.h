// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_LOGBOOK_INTERNAL_H
#define AXIOM64_ACCOUNTS_LOGBOOK_INTERNAL_H

#include "logbook.h"

// Sequence numbers are local to each generation. Carried START frames are
// session state, not new historical events; previous_events counts the history
// before this generation, including generations expired by the retention rule.
struct account_logbook_state {
    uint32_t magic, version, size, crc;
    uint64_t generation, carried, previous_events;
};

struct account_logbook {
    int directory, lock, journal, immutable, failed;
    char* path;
    struct account_login_frame* frames;
    size_t count;
    struct account_logbook_state state;
};

struct account_logbook_projection {
    struct account_logbook* book;
    unsigned kind;
};

int account_logbook_load(struct account_logbook*);
int account_logbook_ended(const struct account_logbook*, size_t);
int account_logbook_write_projection(int, void*);
int account_logbook_auth_line(const struct account_logbook*, size_t, char*, size_t);
int account_logbook_rotation_open(struct account_logbook*);
int account_logbook_rotation_validate(struct account_logbook*);
int account_logbook_rotate(struct account_logbook*);
int account_logbook_rotation_collect(struct account_logbook*);

#endif
