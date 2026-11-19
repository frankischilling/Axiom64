// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "UNIX_STREAM_NAMES_FAIL line=%d expression=%s errno=%d\n", __LINE__,   \
                    #value, errno);                                                                \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static int length_first;

static int native_length_first(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    socklen_t length = sizeof(address);
    CHECK(!getsockname(fd, (struct sockaddr*)&address, &length));
    CHECK(length == offsetof(struct sockaddr_un, sun_path));
    socklen_t fault_length = sizeof(address);
    errno = 0;
    CHECK(getsockname(fd, (struct sockaddr*)1, &fault_length) == -1 && errno == EFAULT);
    CHECK(fault_length == sizeof(address) || fault_length == length);
    CHECK(!close(fd));
    return fault_length == length;
}

static void bind_descriptors(void) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    socklen_t length = offsetof(struct sockaddr_un, sun_path);
    char path[] = "/tmp/axiom-stream-bind-XXXXXX";
    int file = mkstemp(path), channel[2];
    CHECK(file >= 0 && !unlink(path) && !pipe(channel));
    int closed = dup(file);
    CHECK(closed >= 0 && !close(closed));
    int descriptors[] = {file, channel[0], channel[1], closed, -1};
    for (unsigned n = 0; n < sizeof(descriptors) / sizeof(descriptors[0]); n++) {
        int expected = n < 3 ? ENOTSOCK : EBADF;
        CHECK(bind(descriptors[n], (struct sockaddr*)&address, length) == -1 && errno == expected);
        CHECK(bind(descriptors[n], (struct sockaddr*)1, sizeof(address)) == -1 &&
              errno == expected);
        CHECK(bind(descriptors[n], (struct sockaddr*)1, 0) == -1 && errno == expected);
    }
    CHECK(!close(file) && !close(channel[0]) && !close(channel[1]));
    for (int type = SOCK_STREAM; type <= SOCK_DGRAM; type++) {
        int fd = socket(AF_UNIX, type, 0);
        CHECK(fd >= 0);
        CHECK(!bind(fd, (struct sockaddr*)&address, length));
        CHECK(!close(fd));
    }
    puts("UNIX_STREAM_NAMES_BIND_PASS descriptors=5 successful=2");
}

static void check_name(int fd, int peer, const struct sockaddr_un* expected, socklen_t length) {
    unsigned char actual[128];
    memset(actual, 0xa5, sizeof(actual));
    socklen_t capacity = sizeof(actual);
    int (*query)(int, struct sockaddr*, socklen_t*) = peer ? getpeername : getsockname;
    CHECK(!query(fd, (struct sockaddr*)actual, &capacity));
    CHECK(capacity == length && !memcmp(actual, expected, length) && actual[length] == 0xa5);
    capacity = 1;
    actual[1] = 0xa5;
    CHECK(!query(fd, (struct sockaddr*)actual, &capacity));
    CHECK(capacity == length && actual[0] == AF_UNIX && actual[1] == 0xa5);
    capacity = sizeof(actual);
    CHECK(query(fd, (struct sockaddr*)1, &capacity) == -1 && errno == EFAULT);
    CHECK(capacity == (length_first ? length : sizeof(actual)));
}

static void connected_names(unsigned kind) {
    struct sockaddr_un local = {.sun_family = AF_UNIX}, remote = {.sun_family = AF_UNIX};
    socklen_t header = offsetof(struct sockaddr_un, sun_path);
    socklen_t local_length, remote_length = header;
    if (kind == 0) {
        int count = snprintf(local.sun_path, sizeof(local.sun_path), "/tmp/axiom-stream-%ld",
                             (long)getpid());
        CHECK(count > 0 && (size_t)count < sizeof(local.sun_path));
        local_length = header + count + 1;
    } else {
        int count = snprintf(local.sun_path + 1, sizeof(local.sun_path) - 1, "listen-%ld-%u",
                             (long)getpid(), kind);
        CHECK(count > 0 && (size_t)count < sizeof(local.sun_path) - 1);
        local_length = header + count + 1;
    }
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int client = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(listener >= 0 && client >= 0);
    check_name(client, 0, &remote, header);
    struct sockaddr_un peer;
    socklen_t capacity = sizeof(peer);
    CHECK(getpeername(client, (struct sockaddr*)&peer, &capacity) == -1 && errno == ENOTCONN);
    CHECK(!bind(listener, (struct sockaddr*)&local, local_length) && !listen(listener, 1));
    CHECK(bind(listener, (struct sockaddr*)&local, local_length) == -1 &&
          errno == (kind == 0 ? EADDRINUSE : EINVAL));
    CHECK(!bind(listener, (struct sockaddr*)&local, header));
    if (kind == 1) {
        memcpy(remote.sun_path, local.sun_path, sizeof(remote.sun_path));
        remote.sun_path[1] = 'C';
        remote_length = local_length;
        CHECK(!bind(client, (struct sockaddr*)&remote, remote_length));
    } else if (kind == 2) {
        int enabled = 1;
        CHECK(!setsockopt(client, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)));
    }
    CHECK(!connect(client, (struct sockaddr*)&local, local_length));
    if (kind == 2) {
        remote_length = sizeof(remote);
        CHECK(!getsockname(client, (struct sockaddr*)&remote, &remote_length));
        CHECK(remote_length == header + 6 && remote.sun_family == AF_UNIX && !remote.sun_path[0]);
        CHECK(strspn(remote.sun_path + 1, "0123456789abcdef") == 5);
    }
    check_name(client, 0, &remote, remote_length);
    check_name(client, 1, &local, local_length);
    capacity = sizeof(peer);
    int accepted = accept(listener, (struct sockaddr*)&peer, &capacity);
    CHECK(accepted >= 0 && capacity == remote_length && !memcmp(&peer, &remote, remote_length));
    check_name(accepted, 0, &local, local_length);
    check_name(accepted, 1, &remote, remote_length);
    CHECK(!close(listener));
    if (kind == 0)
        CHECK(!unlink(local.sun_path));
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(listener >= 0 && !bind(listener, (struct sockaddr*)&local, local_length));
    CHECK(!close(listener) && !close(client));
    check_name(accepted, 0, &local, local_length);
    check_name(accepted, 1, &remote, remote_length);
    CHECK(!close(accepted));
    if (kind == 0)
        CHECK(!unlink(local.sun_path));
}

static void accept_name_fault(void) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int count =
        snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1, "accept-%ld", (long)getpid());
    CHECK(count > 0 && (size_t)count < sizeof(address.sun_path) - 1);
    socklen_t actual = offsetof(struct sockaddr_un, sun_path) + count + 1;
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int client = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(listener >= 0 && client >= 0);
    CHECK(!bind(listener, (struct sockaddr*)&address, actual) && !listen(listener, 1));
    CHECK(!connect(client, (struct sockaddr*)&address, actual));
    socklen_t capacity = sizeof(address);
    CHECK(accept4(listener, (struct sockaddr*)1, &capacity, SOCK_CLOEXEC) == -1 && errno == EFAULT);
    CHECK(capacity == (length_first ? offsetof(struct sockaddr_un, sun_path) : sizeof(address)));
    CHECK(accept(listener, NULL, NULL) == -1 && errno == EAGAIN);
    unsigned char byte;
    CHECK(recv(client, &byte, 1, 0) == 0);
    CHECK(!close(client));
    client = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(client >= 0 && !connect(client, (struct sockaddr*)&address, actual));
    int accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    CHECK(accepted >= 0 && fcntl(accepted, F_GETFD) == FD_CLOEXEC);
    CHECK(!close(accepted) && !close(client) && !close(listener));
}

static void receive_case(unsigned form, unsigned kind) {
    int pair[2], replacement = -1;
    CHECK(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair));
    unsigned char* pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED && !mprotect(pages + 4096, 4096, PROT_NONE));
    struct sockaddr_un source = {.sun_family = AF_UNIX};
    memcpy(source.sun_path + 1, "stream", 6);
    unsigned serial = (unsigned)getpid() * 32 + form * 16 + kind;
    memcpy(source.sun_path + 7, &serial, sizeof(serial));
    socklen_t actual = offsetof(struct sockaddr_un, sun_path) + 11;
    if (kind != 0 && kind != 2 && kind != 10)
        CHECK(!bind(pair[0], (struct sockaddr*)&source, actual));
    CHECK(send(pair[0], "N", 1, 0) == 1);
    if (kind == 2)
        CHECK(!bind(pair[0], (struct sockaddr*)&source, actual));
    if (kind == 3 || kind == 10) {
        CHECK(!close(pair[0]));
        pair[0] = -1;
        replacement = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
        CHECK(replacement >= 0);
        struct sockaddr_un other = source;
        other.sun_path[1] = 'R';
        CHECK(!bind(replacement, (struct sockaddr*)&other, actual));
    }
    unsigned char name[128], payload[2] = {0xa5, 0xa5};
    memset(name, 0xa5, sizeof(name));
    memset(pages, 0xa5, 4096);
    void* output = kind == 7 ? pages + 4095 : kind == 8 ? (void*)1 : name;
    socklen_t capacity = kind == 5   ? 0
                         : kind == 6 ? 1
                         : kind == 7 ? 110
                         : kind == 8 ? 0
                         : kind == 9 ? UINT32_MAX
                                     : 110;
    socklen_t length = capacity;
    void* data = kind == 12 ? pages + 4096 : payload;
    size_t count = kind == 11 ? 0 : 1;
    int flags = kind == 4 ? MSG_PEEK : 0;
    struct iovec vector = {data, count};
    struct msghdr message = {.msg_name = kind == 13 ? NULL : output,
                             .msg_namelen = capacity,
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_flags = 0x5a5a};
    errno = 0;
    ssize_t result =
        form ? recvfrom(pair[1], data, count, flags, kind == 13 ? NULL : output, &length)
             : recvmsg(pair[1], &message, flags);
    int error = result < 0 ? errno : 0;
    if (!form)
        length = message.msg_namelen;
    unsigned char next = 0xa5;
    errno = 0;
    ssize_t queued = recv(pair[1], &next, 1, MSG_DONTWAIT);
    int queue_error = queued < 0 ? errno : 0;
    printf("UNIX_STREAM_NAMES_CASE form=%u case=%u result=%ld errno=%d length=%u flags=%x "
           "payload=%02x next=%ld next_errno=%d next_byte=%02x guard=%02x name=",
           form, kind, (long)result, error, length, form ? 0 : message.msg_flags, payload[0],
           (long)queued, queue_error, next, pages[4095]);
    for (unsigned at = 0; at < 16; at++)
        printf("%02x", name[at]);
    puts("");
    int fault = kind == 7 || kind == 9 || kind == 12;
    CHECK(result == (fault ? -1 : (ssize_t)count));
    CHECK(error == (kind == 9 ? EINVAL : fault ? EFAULT : 0));
    socklen_t expected_length = kind == 9                    ? UINT32_MAX
                                : kind == 12                 ? 110
                                : kind == 13                 ? 110
                                : kind == 7 && !length_first ? 110
                                : kind == 0 || kind == 10    ? 0
                                                             : actual;
    CHECK(length == expected_length);
    CHECK(form || message.msg_flags == (fault ? 0x5a5a : 0));
    CHECK(payload[0] == (kind == 11 || kind == 12 || (!form && kind == 9) ? 0xa5 : 'N'));
    int retained = kind == 4 || kind == 11 || kind == 12 || (!form && kind == 9);
    CHECK(queued == (retained ? 1 : kind == 3 || kind == 10 ? 0 : -1));
    CHECK(queue_error == (queued < 0 ? EAGAIN : 0));
    CHECK(next == (retained ? 'N' : 0xa5));
    CHECK(pages[4095] == (kind == 7 ? 1 : 0xa5));
    size_t copied = kind == 0 || kind == 5 || kind == 7 || kind == 8 || kind == 9 || kind == 10 ||
                            kind == 12 || kind == 13
                        ? 0
                    : kind == 6 ? 1
                                : actual;
    CHECK(!memcmp(name, &source, copied));
    for (size_t at = copied; at < sizeof(name); at++)
        CHECK(name[at] == 0xa5);
    if (pair[0] >= 0)
        CHECK(!close(pair[0]));
    if (replacement >= 0)
        CHECK(!close(replacement));
    CHECK(!close(pair[1]) && !munmap(pages, 8192));
}

union rights_buffer {
    struct cmsghdr header;
    unsigned char bytes[CMSG_SPACE(sizeof(int))];
};

static void check_right(struct msghdr* message, int write_end) {
    struct cmsghdr* control = CMSG_FIRSTHDR(message);
    CHECK(control && control->cmsg_level == SOL_SOCKET && control->cmsg_type == SCM_RIGHTS);
    CHECK(control->cmsg_len == CMSG_LEN(sizeof(int)));
    int fd;
    memcpy(&fd, CMSG_DATA(control), sizeof(fd));
    unsigned char byte;
    CHECK(write(write_end, "R", 1) == 1 && read(fd, &byte, 1) == 1 && byte == 'R');
    CHECK(!close(fd));
}

static void zero_with_rights(unsigned kind) {
    int pair[2], channel[2];
    CHECK(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) && !pipe(channel));
    struct sockaddr_un source = {.sun_family = AF_UNIX};
    memcpy(source.sun_path + 1, "rights", 6);
    unsigned id = (unsigned)getpid() * 4 + kind;
    memcpy(source.sun_path + 7, &id, sizeof(id));
    socklen_t actual = offsetof(struct sockaddr_un, sun_path) + 11;
    CHECK(!bind(pair[0], (struct sockaddr*)&source, actual));
    union rights_buffer rights = {0};
    struct iovec vector = {(void*)"N", 1};
    struct msghdr message = {.msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = rights.bytes,
                             .msg_controllen = sizeof(rights.bytes)};
    struct cmsghdr* control = CMSG_FIRSTHDR(&message);
    control->cmsg_len = CMSG_LEN(sizeof(int));
    control->cmsg_level = SOL_SOCKET;
    control->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(control), &channel[0], sizeof(channel[0]));
    CHECK(sendmsg(pair[0], &message, 0) == 1 && !close(channel[0]));

    struct sockaddr_un name;
    unsigned char byte = 0xa5;
    vector = (struct iovec){&byte, 0};
    memset(&rights, 0, sizeof(rights));
    message.msg_name = kind == 3 ? (void*)1 : &name;
    message.msg_namelen = sizeof(name);
    message.msg_control = kind == 1 ? NULL : rights.bytes;
    message.msg_controllen = kind == 1 ? 0 : sizeof(rights.bytes);
    message.msg_flags = 0x5a5a;
    errno = 0;
    ssize_t result = recvmsg(pair[1], &message, kind == 2 ? MSG_PEEK : 0);
    int error = result == -1 ? errno : 0;
    CHECK(result == (kind == 3 ? -1 : 0) && error == (kind == 3 ? EFAULT : 0));
    CHECK(byte == 0xa5);
    CHECK(message.msg_namelen == (kind == 3 && !length_first ? sizeof(name) : actual));
    CHECK(message.msg_flags == (kind == 3 ? 0x5a5a : kind == 1 ? MSG_CTRUNC : 0));
    if (kind != 3)
        CHECK(!memcmp(&name, &source, actual));
    if (kind != 1)
        check_right(&message, channel[1]);

    vector.iov_len = 1;
    memset(&rights, 0, sizeof(rights));
    message.msg_name = &name;
    message.msg_namelen = sizeof(name);
    message.msg_control = rights.bytes;
    message.msg_controllen = sizeof(rights.bytes);
    CHECK(recvmsg(pair[1], &message, 0) == 1 && byte == 'N');
    CHECK(message.msg_namelen == actual && !memcmp(&name, &source, actual));
    CHECK(!message.msg_flags && (message.msg_controllen != 0) == (kind == 2));
    if (kind == 2)
        check_right(&message, channel[1]);
    CHECK(recv(pair[1], &byte, 1, 0) == -1 && errno == EAGAIN);
    CHECK(!close(pair[0]) && !close(pair[1]) && !close(channel[1]));
}

int main(int argc, char** argv) {
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")));
    if (argc == 2) {
        CHECK(!geteuid() && !setgroups(0, NULL));
        CHECK(!setresgid(65534, 65534, 65534) && !setresuid(65534, 65534, 65534));
    }
    struct utsname identity;
    CHECK(!uname(&identity));
    CHECK(!strcmp(identity.sysname, "Axiom64") || !strcmp(identity.sysname, "Linux"));
    length_first = !strcmp(identity.sysname, "Axiom64") || native_length_first();
    printf("UNIX_STREAM_NAMES_IDENTITY uid=%u euid=%u gid=%u egid=%u groups=%d\n", getuid(),
           geteuid(), getgid(), getegid(), getgroups(0, NULL));
    printf("UNIX_STREAM_NAMES_PROCESS pid=%ld kernel=%s length_first=%d\n", (long)getpid(),
           identity.release, length_first);
    bind_descriptors();
    for (unsigned kind = 0; kind < 3; kind++)
        connected_names(kind);
    accept_name_fault();
    puts("UNIX_STREAM_NAMES_QUERY_PASS cases=4 filesystem abstract autobind accept_fault");
    for (unsigned form = 0; form < 2; form++)
        for (unsigned kind = 0; kind < 14; kind++)
            receive_case(form, kind);
    puts("UNIX_STREAM_NAMES_RECEIVE_PASS cases=28 named unbound late_bind close reuse peek zero "
         "negative_capacity source_fault payload_fault");
    for (unsigned kind = 0; kind < 4; kind++)
        zero_with_rights(kind);
    puts("UNIX_STREAM_NAMES_RIGHTS_PASS cases=4 delivered discarded peek source_fault");
    puts("UNIX_STREAM_NAMES_PASS groups=4");
}
