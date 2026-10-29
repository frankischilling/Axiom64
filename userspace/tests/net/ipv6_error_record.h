// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

struct metadata_record {
    const char* label;
    unsigned lane, sequence, kind, scoped, variant, mask, capacity, input_flags;
    long result, queued, normal;
    int error, queue_error, normal_error;
    unsigned control_visible, name_visible;
    const struct msghdr *before, *after;
    const unsigned char *name, *name_prefix, *control, *payload, *drain;
};

static void metadata_hex(char* output, const void* pointer, size_t length) {
    static const char digits[] = "0123456789abcdef";
    const unsigned char* data = pointer;
    for (size_t at = 0; at < length; at++) {
        output[at * 2] = digits[data[at] >> 4];
        output[at * 2 + 1] = digits[data[at] & 15];
    }
    output[length * 2] = 0;
}

static int emit_metadata_record(const struct metadata_record* value) {
    if (value->control_visible > 384 || value->name_visible > 1) {
        errno = EINVAL;
        return -1;
    }
    char before[sizeof(struct msghdr) * 2 + 1], after[sizeof(struct msghdr) * 2 + 1];
    char name[81], prefix[3], control[769], payload[65], drain[65], record[2048];
    metadata_hex(before, value->before, sizeof(*value->before));
    metadata_hex(after, value->after, sizeof(*value->after));
    metadata_hex(name, value->name, 40);
    metadata_hex(prefix, value->name_prefix, value->name_visible);
    metadata_hex(control, value->control, value->control_visible);
    metadata_hex(payload, value->payload, 32);
    metadata_hex(drain, value->drain, 32);
    int length = snprintf(
        record, sizeof(record),
        "%s_CASE lane=%u case=%u kind=%u scope=%u variant=%u mask=%u "
        "capacity=%u input_flags=%u result=%ld errno=%d name_length=%u length=%zu "
        "flags=%u queued=%ld queue_errno=%d normal=%ld normal_errno=%d "
        "control_visible=%u name_visible=%u before_header=%s header=%s name=%s name_prefix=%s "
        "control=%s payload=%s drain=%s\n",
        value->label, value->lane, value->sequence, value->kind, value->scoped, value->variant,
        value->mask, value->capacity, value->input_flags, value->result, value->error,
        value->after->msg_namelen, (size_t)value->after->msg_controllen,
        (unsigned)value->after->msg_flags, value->queued, value->queue_error, value->normal,
        value->normal_error, value->control_visible, value->name_visible, before, after, name,
        prefix, control, payload, drain);
    if (length <= 0 || (size_t)length >= sizeof(record)) {
        errno = EOVERFLOW;
        return -1;
    }
    // A kernel diagnostic can run between userspace writes. Keep the original
    // scalar, padding and hexadecimal bytes in one bounded console operation.
    // Native stdout can still buffer earlier stdio records; publish those first.
    if (fflush(stdout) != 0)
        return -1;
    ssize_t written = write(STDOUT_FILENO, record, (size_t)length);
    if (written == length)
        return 0;
    if (written >= 0)
        errno = EIO;
    return -1;
}
