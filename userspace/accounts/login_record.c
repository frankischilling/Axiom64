// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "login_record.h"
#include "database.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int failed(int error) {
    errno = error;
    return -1;
}

const char* account_login_kind_name(enum account_login_kind kind) {
    static const char* names[] = {"",     "login",    "logout", "denied", "su",
                                  "sudo", "password", "admin",  "boot",   "recovered"};
    return kind >= ACCOUNT_LOGIN_START && kind <= ACCOUNT_LOGIN_RECOVERED ? names[kind] : NULL;
}

int account_login_terminal(const char* input, char output[32]) {
    if (!input || !output)
        return failed(EINVAL);
    if (!strncmp(input, "/dev/", 5))
        input += 5;
    size_t length = strnlen(input, 32);
    if (length == 32)
        return failed(ENAMETOOLONG);
    int valid = !length || !strcmp(input, "console") || !strcmp(input, "tty") ||
                !strcmp(input, "tty0") || !strcmp(input, "tty1") || !strcmp(input, "ttyS0");
    if (!strncmp(input, "pts/", 4) && length > 4) {
        valid = 1;
        for (size_t i = 4; i < length; i++)
            if (input[i] < '0' || input[i] > '9')
                valid = 0;
    }
    if (!valid)
        return failed(EINVAL);
    memset(output, 0, 32);
    memcpy(output, input, length);
    return 0;
}

static uint32_t checksum(const struct account_login_frame* frame) {
    struct account_login_frame copy = *frame;
    copy.crc = 0;
    const unsigned char* bytes = (const unsigned char*)&copy;
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < sizeof(copy); i++) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
    }
    return crc ^ UINT32_MAX;
}

static int token_present(const unsigned char token[16]) {
    unsigned result = 0;
    for (size_t i = 0; i < 16; i++)
        result |= token[i];
    return result != 0;
}

int account_login_frame_make(struct account_login_frame* frame, enum account_login_kind kind,
                             const char* name, uid_t uid, gid_t gid, pid_t pid,
                             const char* terminal, const char* target, int status,
                             const unsigned char token[16]) {
    if (!frame || !account_login_kind_name(kind) || !name ||
        (kind != ACCOUNT_LOGIN_BOOT && !account_name_valid(name)) ||
        (kind == ACCOUNT_LOGIN_BOOT && *name) || pid < 0 || status < 0 || status > 65535 ||
        (uid == (uid_t)-1 && kind != ACCOUNT_LOGIN_DENIED) ||
        (gid == (gid_t)-1 && kind != ACCOUNT_LOGIN_DENIED) ||
        (target && *target && !account_name_valid(target)))
        return failed(EINVAL);
    int session_event =
        kind == ACCOUNT_LOGIN_START || kind == ACCOUNT_LOGIN_END || kind == ACCOUNT_LOGIN_RECOVERED;
    if (session_event && (!pid || !token || !token_present(token)))
        return failed(EINVAL);
    struct account_login_frame result;
    struct account_login_frame* destination = frame;
    frame = &result;
    memset(frame, 0, sizeof(*frame));
    if (account_login_terminal(terminal ? terminal : "", frame->entry.line) < 0)
        return -1;
    if (session_event && !*frame->entry.line)
        return failed(EINVAL);
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) < 0)
        return -1;
    frame->magic = UINT32_C(0x4c363441);
    frame->version = 1;
    frame->size = sizeof(*frame);
    frame->seconds = now.tv_sec;
    frame->entry.seconds = (int32_t)now.tv_sec;
    frame->entry.microseconds = (int32_t)(now.tv_nsec / 1000);
    frame->entry.pid = pid;
    frame->entry.session = pid;
    frame->entry.type = kind == ACCOUNT_LOGIN_START                                    ? 7
                        : kind == ACCOUNT_LOGIN_END || kind == ACCOUNT_LOGIN_RECOVERED ? 8
                        : kind == ACCOUNT_LOGIN_DENIED                                 ? 6
                        : kind == ACCOUNT_LOGIN_BOOT                                   ? 2
                                                                                       : 0;
    frame->entry.termination = (int16_t)(status & 127);
    frame->entry.exit_code = (int16_t)((status >> 8) & 255);
    char id[5];
    snprintf(id, sizeof(id), "%04x", (unsigned)pid & 65535);
    memcpy(frame->entry.id, id, 4);
    memcpy(frame->entry.user, name, strlen(name));
    if (target)
        memcpy(frame->entry.host, target, strlen(target));
    frame->uid = uid;
    frame->gid = gid;
    frame->kind = kind;
    frame->status = status;
    if (token)
        memcpy(frame->token, token, 16);
    *destination = *frame;
    return 0;
}

void account_login_frame_seal(struct account_login_frame* frame, uint64_t sequence) {
    frame->sequence = sequence;
    frame->crc = checksum(frame);
}

int account_login_frame_valid(const struct account_login_frame* frame, uint64_t sequence) {
    if (!frame || frame->magic != UINT32_C(0x4c363441) || frame->version != 1 ||
        frame->size != sizeof(*frame) || frame->sequence != sequence ||
        frame->crc != checksum(frame) || !account_login_kind_name(frame->kind) ||
        frame->entry.pid < 0 || frame->entry.padding || frame->entry.microseconds < 0 ||
        frame->entry.microseconds >= 1000000 || frame->entry.seconds != (int32_t)frame->seconds ||
        frame->entry.session != frame->entry.pid || frame->status < 0 || frame->status > 65535 ||
        frame->entry.termination != (frame->status & 127) ||
        frame->entry.exit_code != ((frame->status >> 8) & 255))
        return 0;
    char name[33] = {0}, terminal[32], target[257] = {0};
    memcpy(name, frame->entry.user, 32);
    memcpy(target, frame->entry.host, 256);
    if ((frame->kind == ACCOUNT_LOGIN_BOOT ? *name != 0 : !account_name_valid(name)) ||
        (target[0] && !account_name_valid(target)) || memchr(frame->entry.line, 0, 32) == NULL ||
        account_login_terminal(frame->entry.line, terminal) < 0 ||
        memcmp(terminal, frame->entry.line, 32))
        return 0;
    int type = frame->kind == ACCOUNT_LOGIN_START                                           ? 7
               : frame->kind == ACCOUNT_LOGIN_END || frame->kind == ACCOUNT_LOGIN_RECOVERED ? 8
               : frame->kind == ACCOUNT_LOGIN_DENIED                                        ? 6
               : frame->kind == ACCOUNT_LOGIN_BOOT                                          ? 2
                                                                                            : 0;
    if (frame->entry.type != type ||
        (frame->uid == (uid_t)-1 && frame->kind != ACCOUNT_LOGIN_DENIED) ||
        (frame->gid == (gid_t)-1 && frame->kind != ACCOUNT_LOGIN_DENIED))
        return 0;
    for (size_t i = 0; i < 4; i++)
        if (frame->entry.address[i])
            return 0;
    for (size_t i = 0; i < 20; i++)
        if (frame->entry.unused[i])
            return 0;
    size_t name_length = strlen(name), target_length = strlen(target);
    for (size_t i = name_length; i < 32; i++)
        if (frame->entry.user[i])
            return 0;
    for (size_t i = target_length; i < 256; i++)
        if (frame->entry.host[i])
            return 0;
    char id[5];
    snprintf(id, sizeof(id), "%04x", (unsigned)frame->entry.pid & 65535);
    if (memcmp(id, frame->entry.id, 4))
        return 0;
    int session_event = frame->kind == ACCOUNT_LOGIN_START || frame->kind == ACCOUNT_LOGIN_END ||
                        frame->kind == ACCOUNT_LOGIN_RECOVERED;
    if (session_event)
        return frame->entry.pid > 0 && terminal[0] && token_present(frame->token) && !target[0] &&
               (frame->kind == ACCOUNT_LOGIN_END || frame->status == 0);
    if (token_present(frame->token))
        return 0;
    return frame->kind != ACCOUNT_LOGIN_BOOT ||
           (!frame->uid && !frame->gid && !terminal[0] && !target[0] && !frame->status);
}
