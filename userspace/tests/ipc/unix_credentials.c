// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "UNIX_CREDENTIALS_FAIL line=%d expression=%s errno=%d\n", __LINE__,    \
                    #value, errno);                                                                \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

union control {
    struct cmsghdr aligned;
    unsigned char bytes[64];
};

static void pair(int sockets[2]) {
    CHECK(!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets));
}

static void finish(int sockets[2]) {
    CHECK(!close(sockets[0]) && !close(sockets[1]));
}

static void enable(int fd, int value) {
    CHECK(!setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &value, sizeof(value)));
}

static void equal(struct ucred actual, struct ucred expected) {
    CHECK(actual.pid == expected.pid && actual.uid == expected.uid && actual.gid == expected.gid);
}

static struct ucred receive(int fd, int flags) {
    union control control = {0};
    char byte = 0;
    struct iovec vector = {&byte, 1};
    struct msghdr message = {.msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control.bytes,
                             .msg_controllen = sizeof(control.bytes)};
    CHECK(recvmsg(fd, &message, flags) == 1 && byte == 'C' && !message.msg_flags);
    CHECK(message.msg_controllen == CMSG_SPACE(sizeof(struct ucred)));
    struct cmsghdr* field = CMSG_FIRSTHDR(&message);
    CHECK(field && field->cmsg_len == CMSG_LEN(sizeof(struct ucred)) &&
          field->cmsg_level == SOL_SOCKET && field->cmsg_type == SCM_CREDENTIALS &&
          !CMSG_NXTHDR(&message, field));
    struct ucred result;
    memcpy(&result, CMSG_DATA(field), sizeof(result));
    return result;
}

static void options(void) {
    int sockets[2];
    pair(sockets);
    for (unsigned enabled = 0; enabled < 2; enabled++) {
        if (enabled)
            enable(sockets[0], 17);
        for (unsigned capacity = 0; capacity <= 6; capacity++) {
            union {
                int aligned;
                unsigned char bytes[8];
            } output;

            memset(&output, 0xa5, sizeof(output));
            socklen_t length = capacity;
            CHECK(!getsockopt(sockets[0], SOL_SOCKET, SO_PASSCRED, &output, &length));
            CHECK(length == (capacity < sizeof(int) ? capacity : sizeof(int)));
            int value = enabled;
            CHECK(!memcmp(output.bytes, &value, length));
            for (unsigned n = length; n < sizeof(output); n++)
                CHECK(output.bytes[n] == 0xa5);
        }
    }
    int value = 1;
    CHECK(setsockopt(sockets[0], SOL_SOCKET, SO_PASSCRED, &value, 3) == -1 && errno == EINVAL);
    CHECK(setsockopt(sockets[0], SOL_SOCKET, SO_PASSCRED, &value, (socklen_t)-1) == -1 &&
          errno == EINVAL);
    socklen_t negative = (socklen_t)-1;
    CHECK(getsockopt(sockets[0], SOL_SOCKET, SO_PASSCRED, &value, &negative) == -1 &&
          errno == EINVAL && negative == (socklen_t)-1);
    enable(sockets[0], 0);
    finish(sockets);
    puts("UNIX_CREDENTIALS_OPTIONS_PASS default boolean partial_get short_set");
}

static void queued(void) {
    for (unsigned before = 0; before < 2; before++) {
        for (unsigned sender = 0; sender < 2; sender++) {
            int sockets[2];
            pair(sockets);
            enable(sockets[1], before);
            enable(sockets[0], sender);
            CHECK(send(sockets[0], "C", 1, 0) == 1);
            enable(sockets[0], 0);
            enable(sockets[1], 1);
            struct ucred expected = before || sender ? (struct ucred){getpid(), getuid(), getgid()}
                                                     : (struct ucred){0, 65534, 65534};
            equal(receive(sockets[1], MSG_PEEK), expected);
            equal(receive(sockets[1], MSG_PEEK), expected);
            equal(receive(sockets[1], 0), expected);
            char byte;
            CHECK(recv(sockets[1], &byte, 1, 0) == -1 && errno == EAGAIN);
            finish(sockets);
        }
    }
    puts("UNIX_CREDENTIALS_QUEUED_PASS late_receiver sender_capture repeated_peek");
}

static void capacities(void) {
    int sockets[2];
    pair(sockets);
    enable(sockets[1], 1);
    CHECK(send(sockets[0], "C", 1, 0) == 1);
    for (unsigned capacity = 0; capacity <= 33; capacity++) {
        union control control;
        memset(&control, 0xa5, sizeof(control));
        char byte = 0;
        struct iovec vector = {&byte, 1};
        struct msghdr message = {.msg_iov = &vector,
                                 .msg_iovlen = 1,
                                 .msg_control = control.bytes,
                                 .msg_controllen = capacity};
        CHECK(recvmsg(sockets[1], &message, MSG_PEEK) == 1 && byte == 'C');
        CHECK(message.msg_flags == (capacity < CMSG_LEN(sizeof(struct ucred)) ? MSG_CTRUNC : 0));
        size_t used = capacity < sizeof(struct cmsghdr) ? 0 : capacity < 32 ? capacity : 32;
        CHECK(message.msg_controllen == used);
        if (used) {
            struct cmsghdr* field = CMSG_FIRSTHDR(&message);
            CHECK(field && field->cmsg_level == SOL_SOCKET && field->cmsg_type == SCM_CREDENTIALS &&
                  field->cmsg_len == (capacity < 28 ? capacity : 28));
            struct ucred expected = {getpid(), getuid(), getgid()};
            CHECK(!memcmp(CMSG_DATA(field), &expected, capacity < 28 ? capacity - 16 : 12));
        }
        for (unsigned n = capacity < 28 ? used : 28; n < sizeof(control.bytes); n++)
            CHECK(control.bytes[n] == 0xa5);
    }
    equal(receive(sockets[1], 0), (struct ucred){getpid(), getuid(), getgid()});
    finish(sockets);
    puts("UNIX_CREDENTIALS_CAPACITY_PASS capacities=34 partial_header padding peek_retains");
}

static ssize_t claim(int fd, struct ucred value, int level, int type, size_t field_length) {
    union control control = {0};
    char byte = 'C';
    struct iovec vector = {&byte, 1};
    struct msghdr message = {
        .msg_iov = &vector, .msg_iovlen = 1, .msg_control = control.bytes, .msg_controllen = 32};
    struct cmsghdr* field = CMSG_FIRSTHDR(&message);
    field->cmsg_level = level;
    field->cmsg_type = type;
    field->cmsg_len = field_length;
    memcpy(CMSG_DATA(field), &value, sizeof(value));
    return sendmsg(fd, &message, 0);
}

static void claims(void) {
    int sockets[2];
    pair(sockets);
    enable(sockets[1], 1);
    struct ucred self = {getpid(), getuid(), getgid()};
    CHECK(claim(sockets[0], self, SOL_SOCKET, SCM_CREDENTIALS, 28) == 1);
    equal(receive(sockets[1], 0), self);
    CHECK(claim(sockets[0], self, SOL_SOCKET, SCM_CREDENTIALS, 27) == -1 && errno == EINVAL);
    CHECK(claim(sockets[0], self, SOL_SOCKET, SCM_CREDENTIALS, 33) == -1 && errno == EINVAL);
    CHECK(claim(sockets[0], self, SOL_SOCKET, 0x7fff, 28) == -1 && errno == EINVAL);
    CHECK(claim(sockets[0], self, SOL_SOCKET, SCM_CREDENTIALS, 15) == -1 && errno == EINVAL);
    if (geteuid()) {
        struct ucred wrong[] = {{getppid(), getuid(), getgid()},
                                {getpid(), getuid() + 1, getgid()},
                                {getpid(), getuid(), getgid() + 1}};
        for (unsigned n = 0; n < sizeof(wrong) / sizeof(wrong[0]); n++)
            CHECK(claim(sockets[0], wrong[n], SOL_SOCKET, SCM_CREDENTIALS, 28) == -1 &&
                  errno == EPERM);
    }
    char byte;
    CHECK(recv(sockets[1], &byte, 1, 0) == -1 && errno == EAGAIN);
    finish(sockets);
    puts("UNIX_CREDENTIALS_CLAIMS_PASS explicit_self malformed unsupported denied_not_queued");
}

static void child_identity(void) {
    int sockets[2];
    pair(sockets);
    enable(sockets[1], 1);
    int mixed = !geteuid();
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        if (mixed) {
            CHECK(!setgroups(0, NULL));
            CHECK(!setresgid(1100, 1101, 1102) && !setresuid(1000, 1001, 1002));
        }
        CHECK(send(sockets[0], "C", 1, 0) == 1);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    equal(receive(sockets[1], MSG_PEEK),
          (struct ucred){child, mixed ? 1000 : getuid(), mixed ? 1100 : getgid()});
    equal(receive(sockets[1], 0),
          (struct ucred){child, mixed ? 1000 : getuid(), mixed ? 1100 : getgid()});
    finish(sockets);
    puts("UNIX_CREDENTIALS_CHILD_PASS departed_sender real_ids repeated_peek");
}

int main(int argc, char** argv) {
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")));
    if (argc == 2) {
        CHECK(!geteuid() && !setgroups(0, NULL));
        CHECK(!setresgid(65534, 65534, 65534) && !setresuid(65534, 65534, 65534));
    }
    printf("UNIX_CREDENTIALS_IDENTITY uid=%u euid=%u gid=%u egid=%u groups=%d\n", getuid(),
           geteuid(), getgid(), getegid(), getgroups(0, NULL));
    options();
    queued();
    capacities();
    claims();
    child_identity();
    puts("UNIX_CREDENTIALS_PASS groups=5");
}
