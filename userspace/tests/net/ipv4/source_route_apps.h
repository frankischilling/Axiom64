// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_SOURCE_ROUTE_APPS_H
#define AXIOM64_SOURCE_ROUTE_APPS_H

#include <poll.h>

static int application_fd = -1, accepted_fd = -1, application_stream;

static void application_bytes(const char* record, const char* fields, const void* data,
                              size_t length) {
    const unsigned char* bytes = data;
    char text[257];
    require(length <= 128, "bounded-application-value");
    for (size_t at = 0; at < length; at++) {
        text[2 * at] = "0123456789abcdef"[bytes[at] >> 4];
        text[2 * at + 1] = "0123456789abcdef"[bytes[at] & 15];
    }
    text[2 * length] = 0;
    emit("IPV4_SOURCE_APP_%s case=%u %s bytes=%zu data=%s\n", record, current_case, fields, length,
         text);
}

static void application_options(int fd, const char* fields) {
    unsigned char bytes[48];
    memset(bytes, 0xa5, sizeof(bytes));
    socklen_t length = sizeof(bytes);
    require(getsockopt(fd, IPPROTO_IP, IP_OPTIONS, bytes, &length) == 0 && length <= 40 &&
                bytes[length] == 0xa5,
            "application-options-query");
    application_bytes("OPTIONS", fields, bytes, length);
}

static void application_ready(int fd) {
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    require(poll(&ready, 1, 2000) == 1 && (ready.revents & POLLIN), "application-ready");
}

static void application_open(const char* kind, unsigned port) {
    require(application_fd == -1 && accepted_fd == -1 && port >= 1024 && port < 65536,
            "new-application-description");
    require(!strcmp(kind, "udp") || !strcmp(kind, "udp-bound") || !strcmp(kind, "tcp"),
            "application-transport");
    application_stream = !strcmp(kind, "tcp");
    application_fd = socket(AF_INET, application_stream ? SOCK_STREAM : SOCK_DGRAM, 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    if (!strcmp(kind, "udp-bound"))
        local.sin_addr.s_addr = htonl(0x0a000001);
    require(application_fd >= 0 &&
                bind(application_fd, (struct sockaddr*)&local, sizeof(local)) == 0,
            "application-bind");
    if (application_stream)
        require(listen(application_fd, 2) == 0, "application-listen");
    else {
        int enabled = 1;
        const int names[] = {IP_PKTINFO, IP_RECVOPTS, IP_RETOPTS};
        for (unsigned at = 0; at < sizeof(names) / sizeof(names[0]); at++)
            require(setsockopt(application_fd, IPPROTO_IP, names[at], &enabled, sizeof(enabled)) ==
                        0,
                    "application-receive-control");
        const unsigned char options[] = {1, 1, 1, 1};
        require(setsockopt(application_fd, IPPROTO_IP, IP_OPTIONS, options, sizeof(options)) == 0,
                "application-description-options");
    }
    application_options(application_fd, "owner=listener phase=open");
    emit("IPV4_SOURCE_APP_OPEN case=%u kind=%s port=%u ingress=%u\n", current_case, kind, port,
         if_nametoindex("eth0"));
}

static void application_accept(void) {
    require(application_stream && application_fd >= 0 && accepted_fd == -1,
            "active-application-listener");
    application_ready(application_fd);
    struct sockaddr_in peer = {0}, local = {0};
    socklen_t length = sizeof(peer);
    accepted_fd = accept(application_fd, (struct sockaddr*)&peer, &length);
    require(accepted_fd >= 0 && length == sizeof(peer) && peer.sin_family == AF_INET,
            "application-accept");
    length = sizeof(local);
    require(getsockname(accepted_fd, (struct sockaddr*)&local, &length) == 0 &&
                length == sizeof(local) && local.sin_family == AF_INET,
            "accepted-local-address");
    emit("IPV4_SOURCE_APP_ACCEPT case=%u source=%08x source_port=%u local=%08x local_port=%u\n",
         current_case, ntohl(peer.sin_addr.s_addr), ntohs(peer.sin_port),
         ntohl(local.sin_addr.s_addr), ntohs(local.sin_port));
    application_options(accepted_fd, "owner=accepted phase=before");
    const unsigned char options[] = {1, 1, 1, 1};
    require(setsockopt(application_fd, IPPROTO_IP, IP_OPTIONS, options, sizeof(options)) == 0 &&
                close(application_fd) == 0,
            "retire-application-listener");
    application_fd = -1;
    application_options(accepted_fd, "owner=accepted phase=after");
}

static void application_receive(void) {
    int fd = application_stream ? accepted_fd : application_fd;
    require(fd >= 0, "active-application-receiver");
    application_ready(fd);
    unsigned char bytes[128];
    if (application_stream) {
        ssize_t length = recv(fd, bytes, sizeof(bytes), 0);
        require(length > 0 && length <= (ssize_t)sizeof(bytes), "application-stream-data");
        application_bytes("DATA", "kind=tcp", bytes, (size_t)length);
        require(send(fd, bytes, (size_t)length, MSG_NOSIGNAL) == length, "application-stream-echo");
        require(shutdown(fd, SHUT_WR) == 0, "application-stream-half-close");
    } else {
        union {
            struct cmsghdr alignment;
            unsigned char bytes[512];
        } controls;
        struct sockaddr_in peer = {0};
        struct iovec vector = {bytes, sizeof(bytes)};
        memset(&controls, 0, sizeof(controls));
        struct msghdr message = {.msg_name = &peer,
                                 .msg_namelen = sizeof(peer),
                                 .msg_iov = &vector,
                                 .msg_iovlen = 1,
                                 .msg_control = controls.bytes,
                                 .msg_controllen = sizeof(controls.bytes)};
        ssize_t length = recvmsg(fd, &message, 0);
        require(length > 0 && length <= (ssize_t)sizeof(bytes) && !message.msg_flags &&
                    message.msg_namelen == sizeof(peer) && peer.sin_family == AF_INET,
                "application-datagram-data");
        emit("IPV4_SOURCE_APP_PEER case=%u source=%08x port=%u\n", current_case,
             ntohl(peer.sin_addr.s_addr), ntohs(peer.sin_port));
        application_bytes("DATA", "kind=udp", bytes, (size_t)length);
        unsigned char returned[40];
        size_t returned_size = 0;
        unsigned seen = 0;
        for (struct cmsghdr* header = CMSG_FIRSTHDR(&message); header;
             header = CMSG_NXTHDR(&message, header)) {
            size_t offset = (unsigned char*)header - controls.bytes;
            require(header->cmsg_len >= CMSG_LEN(0) && offset <= message.msg_controllen &&
                        header->cmsg_len <= message.msg_controllen - offset &&
                        header->cmsg_level == IPPROTO_IP && ++seen <= 3,
                    "application-control-bounds");
            size_t count = header->cmsg_len - CMSG_LEN(0);
            char fields[64];
            snprintf(fields, sizeof(fields), "level=%d kind=%d", header->cmsg_level,
                     header->cmsg_type);
            application_bytes("CONTROL", fields, CMSG_DATA(header), count);
            if (header->cmsg_type == IP_RETOPTS) {
                require(!returned_size && count > 0 && count <= sizeof(returned),
                        "application-return-options");
                memcpy(returned, CMSG_DATA(header), count);
                returned_size = count;
            }
        }
        require(seen == 3 && returned_size, "application-complete-controls");

        union {
            struct cmsghdr alignment;
            unsigned char bytes[CMSG_SPACE(40)];
        } sent_controls;

        memset(&sent_controls, 0, sizeof(sent_controls));
        vector.iov_len = (size_t)length;
        message.msg_control = sent_controls.bytes;
        message.msg_controllen = CMSG_SPACE(returned_size);
        struct cmsghdr* header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = IPPROTO_IP;
        header->cmsg_type = IP_RETOPTS;
        header->cmsg_len = CMSG_LEN(returned_size);
        memcpy(CMSG_DATA(header), returned, returned_size);
        require(sendmsg(fd, &message, MSG_NOSIGNAL) == length, "application-datagram-return");
        application_options(fd, "owner=listener phase=after");
    }
    emit("IPV4_SOURCE_APP_RECEIVED case=%u\n", current_case);
}

static void application_close(void) {
    require(application_fd >= 0 || accepted_fd >= 0, "active-application-close");
    if (application_fd >= 0) {
        require(close(application_fd) == 0, "application-listener-close");
        application_fd = -1;
    }
    if (accepted_fd >= 0) {
        require(close(accepted_fd) == 0, "application-accepted-close");
        accepted_fd = -1;
    }
    emit("IPV4_SOURCE_APP_CLOSED case=%u\n", current_case);
}

#endif
