// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(v)                                                                                   \
    do {                                                                                           \
        if (!(v)) {                                                                                \
            fprintf(stderr, "UNIX_STREAM_FAIL line=%d expression=%s errno=%d\n", __LINE__, #v,     \
                    errno);                                                                        \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

union control {
    struct cmsghdr aligned;
    unsigned char bytes[128];
};

static void pair(int f[2]) {
    CHECK(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, f));
}

static void pipes(int f[2]) {
    CHECK(!pipe2(f, O_NONBLOCK | O_CLOEXEC));
}

static void eof(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN | POLLHUP};
    CHECK(poll(&p, 1, 3000) == 1 && (p.revents & POLLHUP));
    char b;
    CHECK(!read(fd, &b, 1));
}

static void alive(int fd) {
    char b;
    CHECK(read(fd, &b, 1) == -1 && errno == EAGAIN);
}

static void send_right(int fd, const char* bytes, int file) {
    union control control = {0};
    struct iovec v = {(void*)bytes, strlen(bytes)};
    struct msghdr m = {.msg_iov = &v,
                       .msg_iovlen = 1,
                       .msg_control = control.bytes,
                       .msg_controllen = CMSG_SPACE(sizeof(int))};
    struct cmsghdr* c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &file, sizeof(file));
    CHECK(sendmsg(fd, &m, 0) == (ssize_t)strlen(bytes));
}

static int receive(int fd, const char* expected, unsigned capacity, unsigned flags,
                   struct ucred* identity, int rights) {
    char bytes[64];
    union control control = {0};
    struct iovec v = {bytes, capacity};
    struct msghdr m = {.msg_iov = &v,
                       .msg_iovlen = 1,
                       .msg_control = control.bytes,
                       .msg_controllen = sizeof(control)};
    CHECK(recvmsg(fd, &m, flags) == (ssize_t)strlen(expected) &&
          !memcmp(bytes, expected, strlen(expected)));
    CHECK((unsigned)m.msg_flags == (flags & MSG_CMSG_CLOEXEC));
    struct cmsghdr* c = CMSG_FIRSTHDR(&m);
    if (!rights && !identity) {
        CHECK(!c && !m.msg_controllen);
        return -1;
    }
    CHECK(c && c->cmsg_level == SOL_SOCKET && !CMSG_NXTHDR(&m, c));
    if (identity) {
        CHECK(c->cmsg_type == SCM_CREDENTIALS && c->cmsg_len == CMSG_LEN(sizeof(struct ucred)) &&
              m.msg_controllen == CMSG_SPACE(sizeof(struct ucred)));
        struct ucred value;
        memcpy(&value, CMSG_DATA(c), sizeof(value));
        CHECK(value.pid == identity->pid && value.uid == identity->uid &&
              value.gid == identity->gid);
        return -1;
    }
    CHECK(c->cmsg_type == SCM_RIGHTS && c->cmsg_len == CMSG_LEN(sizeof(int)) &&
          m.msg_controllen == CMSG_SPACE(sizeof(int)));
    int file;
    memcpy(&file, CMSG_DATA(c), sizeof(file));
    CHECK(fcntl(file, F_GETFD) == ((flags & MSG_CMSG_CLOEXEC) ? FD_CLOEXEC : 0));
    return file;
}

static void options(void) {
    int f[2];
    pair(f);
    int option = -1;
    socklen_t n = sizeof(option);
    CHECK(!getsockopt(f[1], SOL_SOCKET, SO_PASSCRED, &option, &n) && !option &&
          n == sizeof(option));
    option = 1;
    CHECK(!setsockopt(f[1], SOL_SOCKET, SO_PASSCRED, &option, sizeof(option)));
    option = -1;
    n = sizeof(option);
    CHECK(!getsockopt(f[1], SOL_SOCKET, SO_PASSCRED, &option, &n) && option == 1);
    struct ucred peer;
    n = sizeof(peer);
    CHECK(!getsockopt(f[1], SOL_SOCKET, SO_PEERCRED, &peer, &n) && peer.pid == getpid() &&
          peer.uid == geteuid() && peer.gid == getegid());
    CHECK(!close(f[0]) && !close(f[1]));
    puts("UNIX_STREAM_OPTIONS_PASS passcred peercred");
}

static void boundaries(void) {
    int f[2], p[2], q[2];
    pair(f);
    pipes(p);
    pipes(q);
    CHECK(write(f[0], "A", 1) == 1);
    send_right(f[0], "BC", p[1]);
    CHECK(!close(p[1]));
    CHECK(write(f[0], "D", 1) == 1);
    send_right(f[0], "E", q[1]);
    CHECK(!close(q[1]) && write(f[0], "F", 1) == 1);
    // Linux peeking can reach the following control-bearing segment after
    // filling the byte buffer with its plain predecessor.
    int ahead = receive(f[1], "A", 1, MSG_PEEK, NULL, 1);
    CHECK(!close(ahead));
    int first = receive(f[1], "ABC", 64, MSG_PEEK | MSG_CMSG_CLOEXEC, NULL, 1);
    int second = receive(f[1], "AB", 2, MSG_PEEK | MSG_CMSG_CLOEXEC, NULL, 1);
    CHECK(first != second && !close(first) && !close(second));
    alive(p[0]);
    alive(q[0]);
    first = receive(f[1], "AB", 2, MSG_CMSG_CLOEXEC, NULL, 1);
    CHECK(write(first, "P", 1) == 1);
    char b;
    CHECK(read(p[0], &b, 1) == 1 && b == 'P' && !close(first));
    eof(p[0]);
    second = receive(f[1], "CDE", 64, MSG_CMSG_CLOEXEC, NULL, 1);
    CHECK(write(second, "Q", 1) == 1);
    CHECK(read(q[0], &b, 1) == 1 && b == 'Q' && !close(second));
    eof(q[0]);
    receive(f[1], "F", 64, MSG_CMSG_CLOEXEC, NULL, 0);
    CHECK(recv(f[1], &b, 1, 0) == -1 && errno == EAGAIN);
    CHECK(!close(p[0]) && !close(q[0]) && !close(f[0]) && !close(f[1]));
    puts("UNIX_STREAM_BOUNDARIES_PASS prefix_and_control_end partial_consume distinct_peeks "
         "retained_descriptions");
}

static void read_discards(void) {
    int f[2], p[2];
    pair(f);
    pipes(p);
    send_right(f[0], "UVW", p[1]);
    CHECK(!close(p[1]) && write(f[0], "X", 1) == 1);
    char b;
    CHECK(read(f[1], &b, 1) == 1 && b == 'U');
    eof(p[0]);
    receive(f[1], "VWX", 64, 0, NULL, 0);
    CHECK(!close(p[0]) && !close(f[0]) && !close(f[1]));
    puts("UNIX_STREAM_READ_DROP_PASS first_consumed_byte discards_control "
         "preserves_remaining_bytes");
}

static void credentials(void) {
    int f[2];
    pair(f);
    int option = 1;
    CHECK(!setsockopt(f[1], SOL_SOCKET, SO_PASSCRED, &option, sizeof(option)));
    struct ucred parent = {.pid = getpid(), .uid = getuid(), .gid = getgid()};
    CHECK(write(f[0], "PQ", 2) == 2 && !fflush(stdout));
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        if (!geteuid()) {
            CHECK(!setgroups(0, NULL) && !setresgid(1100, 1101, 1102) &&
                  !setresuid(1000, 1001, 1002));
        }
        CHECK(write(f[0], "RS", 2) == 2);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(write(f[0], "T", 1) == 1);
    struct ucred sender = {
        .pid = child, .uid = parent.uid ? parent.uid : 1000, .gid = parent.uid ? parent.gid : 1100};
    receive(f[1], "PQ", 64, MSG_CMSG_CLOEXEC, &parent, 0);
    receive(f[1], "RS", 64, MSG_CMSG_CLOEXEC, &sender, 0);
    receive(f[1], "T", 64, MSG_CMSG_CLOEXEC, &parent, 0);
    struct ucred peer;
    socklen_t n = sizeof(peer);
    CHECK(!getsockopt(f[1], SOL_SOCKET, SO_PEERCRED, &peer, &n) && peer.pid == parent.pid &&
          peer.uid == geteuid() && peer.gid == getegid());
    CHECK(!close(f[0]) && !close(f[1]));
    puts("UNIX_STREAM_CREDENTIALS_PASS identity_boundaries real_ids exited_sender "
         "distinct_peercred");
}

static void empty_control(void) {
    int f[2], p[2];
    pair(f);
    pipes(p);
    send_right(f[0], "", p[1]);
    CHECK(!close(p[1]));
    eof(p[0]);
    char b;
    CHECK(recv(f[1], &b, 1, 0) == -1 && errno == EAGAIN);
    CHECK(!close(p[0]) && !close(f[0]) && !close(f[1]));
    puts("UNIX_STREAM_EMPTY_CONTROL_PASS no_bytes_no_transfer");
}

static void truncated_control(void) {
    int f[2], p[2];
    pair(f);
    pipes(p);
    send_right(f[0], "XY", p[1]);
    CHECK(!close(p[1]));
    char b;
    struct iovec v = {&b, 1};
    struct msghdr m = {.msg_iov = &v, .msg_iovlen = 1};
    CHECK(recvmsg(f[1], &m, MSG_PEEK) == 1 && b == 'X' && m.msg_flags == MSG_CTRUNC);
    alive(p[0]);
    m.msg_flags = 0;
    CHECK(recvmsg(f[1], &m, 0) == 1 && b == 'X' && m.msg_flags == MSG_CTRUNC);
    eof(p[0]);
    receive(f[1], "Y", 1, 0, NULL, 0);
    CHECK(!close(p[0]) && !close(f[0]) && !close(f[1]));
    puts("UNIX_STREAM_TRUNCATED_CONTROL_PASS peek_retains consume_discards");
}

static void late_credentials(void) {
    int f[2];
    pair(f);
    CHECK(write(f[0], "A", 1) == 1);
    int option = 1;
    CHECK(!setsockopt(f[1], SOL_SOCKET, SO_PASSCRED, &option, sizeof(option)));
    CHECK(write(f[0], "B", 1) == 1);
    struct ucred anonymous = {.pid = 0, .uid = 65534, .gid = 65534};
    struct ucred sender = {.pid = getpid(), .uid = getuid(), .gid = getgid()};
    receive(f[1], "A", 64, MSG_CMSG_CLOEXEC, &anonymous, 0);
    receive(f[1], "B", 64, MSG_CMSG_CLOEXEC, &sender, 0);
    CHECK(!close(f[0]) && !close(f[1]));
    puts("UNIX_STREAM_LATE_CREDENTIALS_PASS anonymous_then_captured");
}

static void queued_close(void) {
    for (unsigned repeat = 0; repeat < 300; repeat++) {
        int f[2], p[2];
        pair(f);
        pipes(p);
        send_right(f[0], "X", p[1]);
        CHECK(!close(p[1]));
        alive(p[0]);
        CHECK(!close(f[1]));
        eof(p[0]);
        CHECK(!close(p[0]) && !close(f[0]));
    }
    puts("UNIX_STREAM_QUEUED_CLOSE_PASS rounds=300 description_release");
}

static void fault_copies(void) {
    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    unsigned char* memory =
        mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(memory != MAP_FAILED && !mprotect(memory, page, PROT_NONE));
    int f[2], p[2];
    pair(f);
    pipes(p);
    send_right(f[0], "R", p[1]);
    CHECK(!close(p[1]));
    struct iovec vector = {memory, 1};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    CHECK(recvmsg(f[1], &message, MSG_PEEK) == -1 && errno == EFAULT);
    alive(p[0]);
    CHECK(recvmsg(f[1], &message, 0) == -1 && errno == EFAULT);
    alive(p[0]);
    int received = receive(f[1], "R", 1, MSG_CMSG_CLOEXEC, NULL, 1);
    CHECK(!close(received));
    eof(p[0]);
    CHECK(!close(p[0]));
    pipes(p);
    send_right(f[0], "S", p[1]);
    CHECK(!close(p[1]));
    char byte;
    vector.iov_base = &byte;
    message.msg_control = memory;
    message.msg_controllen = 32;
    CHECK(recvmsg(f[1], &message, MSG_PEEK) == 1 && byte == 'S' && message.msg_controllen == 0 &&
          message.msg_flags == MSG_CTRUNC);
    alive(p[0]);
    message.msg_controllen = 32;
    CHECK(recvmsg(f[1], &message, 0) == 1 && message.msg_controllen == 0 &&
          message.msg_flags == MSG_CTRUNC);
    eof(p[0]);
    CHECK(!close(p[0]));
    pipes(p);
    send_right(f[0], "T", p[1]);
    CHECK(!close(p[1]));
    message.msg_control = memory + page - 16;
    message.msg_controllen = 32;
    CHECK(recvmsg(f[1], &message, MSG_CMSG_CLOEXEC) == 1 && byte == 'T' &&
          message.msg_controllen == 0 && message.msg_flags == MSG_CMSG_CLOEXEC);
    memcpy(&received, memory + page, sizeof(received));
    CHECK(fcntl(received, F_GETFD) == FD_CLOEXEC && !close(received));
    eof(p[0]);
    CHECK(!close(p[0]) && !close(f[0]) && !close(f[1]) && !munmap(memory, 2 * page));
    puts("UNIX_STREAM_FAULT_COPIES_PASS payload_fault_retains control_fault_releases "
         "header_fault_keeps_installed_fd");
}

int main(int argc, char** argv) {
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")));
    if (argc == 2) {
        CHECK(!geteuid() && !setgroups(0, NULL) && !setresgid(65534, 65534, 65534) &&
              !setresuid(65534, 65534, 65534));
    }
    printf("UNIX_STREAM_IDENTITY uid=%u euid=%u gid=%u egid=%u groups=%d\n", getuid(), geteuid(),
           getgid(), getegid(), getgroups(0, NULL));
    options();
    boundaries();
    read_discards();
    credentials();
    empty_control();
    truncated_control();
    late_credentials();
    queued_close();
    fault_copies();
    puts("UNIX_STREAM_PASS groups=9");
}
