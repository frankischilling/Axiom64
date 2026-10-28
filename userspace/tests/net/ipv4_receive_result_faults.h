// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// These cases share the real transports and packet ownership checks above.

static const unsigned result_payload_prefixes[] = {0, 1, 2, 7, 8, 15, 16, 19, 20, 27, 28, 43, 44};
static const unsigned result_name_prefixes[] = {0, 1, 2, 3, 7, 8, 15, 16, 17, 40};
static const unsigned result_header_prefixes[] = {0,  1,  7,  8,  9,  10, 11, 12, 39,
                                                  40, 41, 44, 47, 48, 49, 52, 56};
static unsigned result_fault_observations;

static void result_wide_field(struct msghdr* message, unsigned offset, uint64_t value) {
    // The Linux syscall layout has 64-bit counts even where libc exposes int.
    memcpy((unsigned char*)message + offset, &value, sizeof(value));
}

static void result_header_image(unsigned char output[56], const void* header,
                                const unsigned char before[56]) {
    memcpy(output, header, 56);
    for (unsigned n = 0; n < 56; n++) {
        int result = (n >= 8 && n < 12) || (n >= 40 && n < 52);
        need(result || output[n] == before[n], "receive preserves every input header byte");
    }
    // Verify pointer bytes before removing their address-space-specific values.
    memset(output, 0, 8);
    memset(output + 16, 0, 8);
    memset(output + 32, 0, 8);
}

static void result_fault_case(struct Transport* value, unsigned phase, unsigned mode,
                              unsigned flags, unsigned char* pages[5], size_t page) {
    for (unsigned n = 0; n < 5; n++) {
        need(!mprotect(pages[n], page * 2, PROT_READ | PROT_WRITE), "reset result guards");
        memset(pages[n], 0xa5, page * 2);
    }
    unsigned char body[16] = {'A', 'X', 'R', 'E', 'S', 'U', 'L', 'T'};
    for (unsigned n = 8; n < 16; n++)
        body[n] = (result_fault_observations * 31 + n * 17) & 255;
    send_packet(value, body);
    unsigned char original[64];
    size_t packet_length = value->kind ? 44 : 16;
    need(recv(value->receiver, original, sizeof(original), MSG_PEEK | MSG_DONTWAIT) ==
                 (ssize_t)packet_length &&
             !memcmp(original + (value->kind ? 28 : 0), body, 16),
         "retain the exact queued packet before result fault");

    unsigned char payload[64], name[40], control[96];
    memset(payload, 0xa5, sizeof(payload));
    memset(name, 0xa5, sizeof(name));
    memset(control, 0xa5, sizeof(control));
    struct iovec vectors[3] = {{payload, 7}, {payload + 7, packet_length - 7}, {0}};
    struct msghdr message;
    memset(&message, 0xa5, sizeof(message));
    message.msg_name = name;
    message.msg_namelen = sizeof(name);
    message.msg_iov = vectors;
    result_wide_field(&message, 24, 2);
    message.msg_control = control;
    result_wide_field(&message, 40, sizeof(control));
    message.msg_flags = 0x5a5a;
    void* header = &message;
    void* record_header = header;
    unsigned char* payload_guard = NULL;
    unsigned char* name_guard = NULL;
    unsigned payload_visible = 0, name_visible = 0;
    void* from_payload = payload;
    void* from_name = name;
    socklen_t ordinary_length = sizeof(name);
    socklen_t* from_length = &ordinary_length;
    unsigned length_visible = sizeof(ordinary_length);
    size_t from_capacity = packet_length;

    if (!phase) {
        switch (mode) {
        case 0:
            break;
        case 1:
            vectors[0] = (struct iovec){(void*)1, packet_length};
            result_wide_field(&message, 24, 1);
            break;
        case 2:
            vectors[1].iov_base = (void*)1;
            break;
        case 3:
            vectors[0] = (struct iovec){(void*)1, 0};
            vectors[1] = (struct iovec){payload, 7};
            vectors[2] = (struct iovec){(void*)1, packet_length - 7};
            result_wide_field(&message, 24, 3);
            break;
        case 4:
            vectors[0] = (struct iovec){(void*)1, 0};
            result_wide_field(&message, 24, 1);
            break;
        case 5:
            vectors[0] = (struct iovec){payload, 8};
            result_wide_field(&message, 24, 1);
            break;
        case 6:
        case 7:
            message.msg_iov = mode == 6 ? NULL : (void*)1;
            result_wide_field(&message, 24, 1);
            break;
        case 8:
            message.msg_iov = (void*)(pages[3] + page - sizeof(struct iovec));
            memcpy(message.msg_iov, vectors, sizeof(struct iovec));
            need(!mprotect(pages[3] + page, page, PROT_NONE), "partial input vector array");
            break;
        case 9:
            message.msg_iov = (void*)1;
            result_wide_field(&message, 24, 1025);
            break;
        case 10:
            vectors[0].iov_len = SIZE_MAX;
            result_wide_field(&message, 24, 1);
            break;
        case 11:
            header = (void*)1;
            break;
        case 25:
        case 26:
            vectors[0] = (struct iovec){
                (void*)(mode == 25 ? UINT64_C(0xffff800000000000) : UINT64_MAX - 4), packet_length};
            result_wide_field(&message, 24, 1);
            break;
        case 27:
            message.msg_iov = (void*)1;
            result_wide_field(&message, 24, 0);
            break;
        default:
            payload_visible = result_payload_prefixes[mode - 12];
            payload_guard = pages[0] + page - payload_visible;
            vectors[0] = (struct iovec){payload_guard, packet_length};
            result_wide_field(&message, 24, 1);
            need(!mprotect(pages[0] + page, page, PROT_NONE), "payload output page");
        }
    } else if (phase == 1) {
        switch (mode) {
        case 0:
            break;
        case 1:
        case 2:
            message.msg_name = NULL;
            message.msg_namelen = mode == 1 ? 40 : UINT32_MAX;
            break;
        case 3:
        case 4:
            message.msg_name = mode == 3 ? (void*)1 : name;
            message.msg_namelen = 0;
            break;
        case 5:
            message.msg_name = (void*)1;
            message.msg_namelen = 1;
            break;
        case 6:
        case 7:
            message.msg_namelen = mode == 6 ? UINT32_MAX : UINT32_C(0x80000000);
            break;
        case 8:
        case 9:
        case 10:
            message.msg_namelen = mode == 8 ? UINT32_C(0x7fffffff) : mode == 9 ? 128 : 1;
            break;
        default:
            name_visible = result_name_prefixes[mode - 11];
            name_guard = pages[1] + page - name_visible;
            message.msg_name = name_guard;
            need(!mprotect(pages[1] + page, page, PROT_NONE), "source output page");
        }
    } else if (phase == 2) {
        unsigned count = sizeof(result_header_prefixes) / sizeof(result_header_prefixes[0]);
        unsigned prefix = result_header_prefixes[mode % count];
        if (mode >= count)
            message.msg_name = NULL;
        header = pages[2] + page - prefix;
        memcpy(header, &message, sizeof(message));
        record_header = header;
        need(!mprotect(pages[2] + (mode < count ? page : 0), page, PROT_READ),
             "readable protected result header");
    } else {
        switch (mode) {
        case 0:
            break;
        case 1:
        case 2:
        case 3:
            from_name = NULL;
            from_length = mode == 1 ? NULL : mode == 2 ? (void*)1 : &ordinary_length;
            ordinary_length = UINT32_MAX;
            length_visible = mode == 3 ? 4 : 0;
            break;
        case 4:
        case 5:
            from_name = (void*)1;
            ordinary_length = mode == 4 ? 0 : 1;
            break;
        case 6:
        case 7:
            from_length = mode == 6 ? NULL : (void*)1;
            length_visible = 0;
            break;
        case 8:
            from_length = (void*)(pages[4] + page);
            memcpy(from_length, &ordinary_length, sizeof(ordinary_length));
            need(!mprotect(pages[4] + page, page, PROT_READ), "readable protected recvfrom length");
            break;
        case 9:
        case 10:
        case 11:
            ordinary_length = mode == 9    ? UINT32_MAX
                              : mode == 10 ? UINT32_C(0x80000000)
                                           : UINT32_C(0x7fffffff);
            break;
        case 12:
            from_length = (void*)(pages[4] + page - 2);
            memcpy(from_length, &ordinary_length, sizeof(ordinary_length));
            length_visible = 2;
            need(!mprotect(pages[4] + page, page, PROT_NONE), "partial recvfrom length input");
            break;
        case 13:
            from_payload = (void*)1;
            break;
        case 14:
        case 15:
            payload_visible = mode == 14 ? 7 : packet_length;
            payload_guard = pages[0] + page - payload_visible;
            from_payload = payload_guard;
            need(!mprotect(pages[0] + page, page, PROT_NONE), "recvfrom payload output page");
            break;
        case 26:
        case 27:
            from_payload = (void*)(mode == 26 ? UINT64_C(0xffff800000000000) : UINT64_MAX - 4);
            break;
        case 28:
            from_payload = (void*)1;
            from_capacity = 0;
            break;
        default:
            name_visible = result_name_prefixes[mode - 16];
            name_guard = pages[1] + page - name_visible;
            from_name = name_guard;
            need(!mprotect(pages[1] + page, page, PROT_NONE), "recvfrom source output page");
        }
    }
    unsigned char before[56], after[56];
    memcpy(before, record_header, sizeof(before));
    errno = 0;
    ssize_t result = phase == 3
                         ? syscall(SYS_recvfrom, value->receiver, from_payload, from_capacity,
                                   flags | MSG_DONTWAIT, from_name, from_length)
                         : syscall(SYS_recvmsg, value->receiver, header, flags | MSG_DONTWAIT);
    int error = result < 0 ? errno : 0;
    result_header_image(after, record_header, before);
    unsigned char queued_bytes[64];
    errno = 0;
    ssize_t queued =
        recv(value->receiver, queued_bytes, sizeof(queued_bytes), MSG_PEEK | MSG_DONTWAIT);
    int queue_error = queued < 0 ? errno : 0;
    if (queued >= 0)
        need(queued == (ssize_t)packet_length && !memcmp(queued_bytes, original, packet_length) &&
                 recv(value->receiver, queued_bytes, sizeof(queued_bytes), MSG_DONTWAIT) ==
                     queued &&
                 !memcmp(queued_bytes, original, packet_length),
             "the same original survives a failed or peeked receive");
    struct pollfd empty = {.fd = value->receiver, .events = POLLIN};
    need(poll(&empty, 1, 0) == 0, "one exact original per result case");
    printf("{\"kind\":\"result_fault\",\"case\":%u,\"transport\":%u,\"phase\":%u,\"mode\":%u,"
           "\"input_flags\":%u,\"result\":%zd,\"errno\":%d,\"queued\":%zd,\"queue_errno\":%d,"
           "\"input\":\"",
           result_fault_observations, value->kind, phase, mode, flags, result, error, queued,
           queue_error);
    hex(original, packet_length);
    printf("\",\"payload\":\"");
    hex(payload, sizeof(payload));
    printf("\",\"payload_guard\":\"");
    if (payload_visible)
        hex(payload_guard, payload_visible);
    printf("\",\"name\":\"");
    hex(name, sizeof(name));
    printf("\",\"name_guard\":\"");
    if (name_visible)
        hex(name_guard, name_visible);
    printf("\",\"control_hex\":\"");
    hex(control, sizeof(control));
    printf("\",\"header\":\"");
    hex(after, sizeof(after));
    printf("\",\"length_hex\":\"");
    if (length_visible)
        hex((void*)from_length, length_visible);
    puts("\"}");
    result_fault_observations++;
}

static void result_fault_cases(void) {
    long page = sysconf(_SC_PAGESIZE);
    need(page >= 4096, "actual result fault page size");
    unsigned char* pages[5];
    for (unsigned n = 0; n < 5; n++) {
        pages[n] = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                        -1, 0);
        need(pages[n] != MAP_FAILED, "owned result fault mapping");
    }
    const unsigned counts[] = {
        15 + sizeof(result_payload_prefixes) / sizeof(result_payload_prefixes[0]),
        11 + sizeof(result_name_prefixes) / sizeof(result_name_prefixes[0]),
        2 * sizeof(result_header_prefixes) / sizeof(result_header_prefixes[0]),
        19 + sizeof(result_name_prefixes) / sizeof(result_name_prefixes[0])};
    for (unsigned kind = 0; kind < 3; kind++) {
        struct Transport value = transport(kind);
        if (!kind) {
            need(!close(value.sender), "replace automatic result source");
            value.sender = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
            value.source = address(0x7f000001, 53598);
            need(value.sender >= 0 &&
                     !bind(value.sender, (struct sockaddr*)&value.source, sizeof(value.source)),
                 "explicit owned result source port");
            int ttl = 37, tos = 0x6e;
            need(!setsockopt(value.sender, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) &&
                     !setsockopt(value.sender, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)),
                 "result source header settings");
        }
        enable(value.receiver, 7);
        for (unsigned flags = 0; flags < 4; flags++) {
            unsigned input = (flags & 1 ? MSG_PEEK : 0) | (flags & 2 ? MSG_TRUNC : 0);
            for (unsigned phase = 0; phase < 4; phase++)
                for (unsigned mode = 0; mode < counts[phase]; mode++)
                    result_fault_case(&value, phase, mode, input, pages, (size_t)page);
        }
        need(!close(value.receiver) && !close(value.sender), "retire result descriptions");
        if (value.guard >= 0)
            need(!close(value.guard), "retire paired result UDP description");
    }
    for (unsigned n = 0; n < 5; n++)
        need(!munmap(pages[n], (size_t)page * 2), "release result fault mappings");
}
