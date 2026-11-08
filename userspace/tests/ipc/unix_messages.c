// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "UNIX_MESSAGES_FAIL line=%d expression=%s errno=%d\n", __LINE__,       \
                    #value, errno);                                                                \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void pair(int sockets[2]) {
    CHECK(!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets));
    for (unsigned n = 0; n != 2; ++n) {
        CHECK(fcntl(sockets[n], F_GETFD) == FD_CLOEXEC);
        CHECK(fcntl(sockets[n], F_GETFL) & O_NONBLOCK);
    }
}

static void finish(int sockets[2]) {
    CHECK(!close(sockets[0]) && !close(sockets[1]));
}

static void readable(int fd) {
    struct pollfd event = {.fd = fd, .events = POLLIN};
    CHECK(poll(&event, 1, 3000) == 1 && (event.revents & POLLIN));
}

static int document(void) {
    char name[] = "/tmp/axiom-unix-XXXXXX";
    int fd = mkstemp(name);
    CHECK(fd >= 0 && !unlink(name));
    CHECK(write(fd, "abcdef", 6) == 6 && lseek(fd, 1, SEEK_SET) == 1);
    return fd;
}

static void send_rights(int socket, const int* files, unsigned count) {
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(2 * sizeof(int))];
    } control = {0};

    char byte = 'R';
    struct iovec vector = {&byte, 1};
    struct msghdr message = {.msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control.bytes,
                             .msg_controllen = CMSG_SPACE(count * sizeof(int))};
    CHECK(count && count <= 2);
    struct cmsghdr* field = CMSG_FIRSTHDR(&message);
    field->cmsg_level = SOL_SOCKET;
    field->cmsg_type = SCM_RIGHTS;
    field->cmsg_len = CMSG_LEN(count * sizeof(int));
    memcpy(CMSG_DATA(field), files, count * sizeof(int));
    CHECK(sendmsg(socket, &message, 0) == 1);
}

static unsigned receive_rights(int socket, int* files, size_t capacity, int flags,
                               unsigned* returned_flags, struct ucred* credentials) {
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(8 * sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))];
    } control = {0};

    char byte = 0;
    struct iovec vector = {&byte, 1};
    struct msghdr message = {.msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control.bytes,
                             .msg_controllen = capacity};
    CHECK(capacity <= sizeof(control.bytes));
    CHECK(recvmsg(socket, &message, flags) == 1 && byte == 'R');
    unsigned count = 0;
    for (struct cmsghdr* field = CMSG_FIRSTHDR(&message); field;
         field = CMSG_NXTHDR(&message, field)) {
        CHECK(field->cmsg_level == SOL_SOCKET);
        if (field->cmsg_type == SCM_RIGHTS) {
            size_t size = field->cmsg_len - CMSG_LEN(0);
            CHECK(size % sizeof(int) == 0 && count + size / sizeof(int) <= 8);
            memcpy(files + count, CMSG_DATA(field), size);
            count += size / sizeof(int);
        } else {
            CHECK(field->cmsg_type == SCM_CREDENTIALS && credentials &&
                  field->cmsg_len == CMSG_LEN(sizeof(*credentials)));
            memcpy(credentials, CMSG_DATA(field), sizeof(*credentials));
        }
    }
    *returned_flags = message.msg_flags;
    return count;
}

static void boundaries(void) {
    int sockets[2];
    pair(sockets);
    char first[] = "message";
    struct iovec vectors[] = {{first, 3}, {first + 3, 4}};
    CHECK(writev(sockets[0], vectors, 2) == 7 && write(sockets[0], "next", 4) == 4);
    memset(first, 'x', 7);
    char bytes[16] = {0};
    struct iovec vector = {bytes, 3};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    CHECK(recvmsg(sockets[1], &message, MSG_PEEK | MSG_TRUNC) == 7 &&
          (message.msg_flags & MSG_TRUNC) && !memcmp(bytes, "mes", 3));
    int available = -1;
    CHECK(!ioctl(sockets[1], FIONREAD, &available) && available == 7);
    CHECK(recv(sockets[1], bytes, 3, 0) == 3 && !memcmp(bytes, "mes", 3));
    CHECK(recv(sockets[1], bytes, sizeof(bytes), 0) == 4 && !memcmp(bytes, "next", 4));
    CHECK(!send(sockets[0], bytes, 0, 0));
    readable(sockets[1]);
    CHECK(!ioctl(sockets[1], FIONREAD, &available) && available == 0);
    CHECK(!recv(sockets[1], bytes, sizeof(bytes), 0));
    CHECK(recv(sockets[1], bytes, sizeof(bytes), 0) == -1 && errno == EAGAIN);
    finish(sockets);
    puts("UNIX_MESSAGES_BOUNDARIES_PASS vectors copied peek truncation zero_record readiness");
}

static void credentials(void) {
    int sockets[2];
    pair(sockets);
    struct ucred peer = {0};
    socklen_t size = sizeof(peer);
    CHECK(!getsockopt(sockets[1], SOL_SOCKET, SO_PEERCRED, &peer, &size) && size == sizeof(peer) &&
          peer.pid == getpid() && peer.uid == geteuid() && peer.gid == getegid());
    int enabled = 1;
    CHECK(!setsockopt(sockets[1], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)));
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        int fd = document();
        send_rights(sockets[0], &fd, 1);
        CHECK(!close(fd));
        _exit(0);
    }
    readable(sockets[1]);
    int files[8], status;
    unsigned flags;
    struct ucred sender = {0};
    CHECK(receive_rights(sockets[1], files, CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(sender)),
                         MSG_CMSG_CLOEXEC, &flags, &sender) == 1);
    CHECK(!(flags & MSG_CTRUNC) && sender.pid == child && sender.uid == geteuid() &&
          sender.gid == getegid() && fcntl(files[0], F_GETFD) == FD_CLOEXEC);
    char byte;
    CHECK(read(files[0], &byte, 1) == 1 && byte == 'b' && !close(files[0]));
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    finish(sockets);
    puts("UNIX_MESSAGES_CREDENTIALS_PASS connection_identity per_message_child queued_description "
         "cloexec");
}

static void peek_rights(void) {
    int sockets[2], fd = document();
    pair(sockets);
    send_rights(sockets[0], &fd, 1);
    CHECK(!close(fd));
    int retained[3];
    for (unsigned n = 0; n != 3; ++n) {
        int files[8];
        unsigned flags;
        CHECK(receive_rights(sockets[1], files, CMSG_SPACE(sizeof(int)),
                             MSG_CMSG_CLOEXEC | (n < 2 ? MSG_PEEK : 0), &flags, NULL) == 1 &&
              !(flags & MSG_CTRUNC) && fcntl(files[0], F_GETFD) == FD_CLOEXEC);
        retained[n] = files[0];
        for (unsigned previous = 0; previous < n; ++previous)
            CHECK(retained[n] != retained[previous]);
        char byte;
        CHECK(read(retained[n], &byte, 1) == 1 && byte == (char)('b' + n));
    }
    for (unsigned n = 0; n != 3; ++n)
        CHECK(!close(retained[n]));
    finish(sockets);
    puts("UNIX_MESSAGES_PEEK_RIGHTS_PASS distinct_descriptors shared_offset "
         "retained_after_sender_close");
}

static void discarded_rights(int limited) {
    int sockets[2], pipefd[2], fd = document();
    pair(sockets);
    CHECK(!pipe2(pipefd, O_NONBLOCK | O_CLOEXEC));
    int rights[] = {fd, pipefd[1]};
    send_rights(sockets[0], rights, 2);
    CHECK(!close(fd) && !close(pipefd[1]));
    char byte;
    CHECK(read(pipefd[0], &byte, 1) == -1 && errno == EAGAIN);
    struct rlimit before, none;
    if (limited) {
        CHECK(!getrlimit(RLIMIT_NOFILE, &before));
        none = before;
        none.rlim_cur = 0;
        CHECK(!setrlimit(RLIMIT_NOFILE, &none));
    }
    int files[8];
    unsigned flags;
    unsigned count = receive_rights(sockets[1], files, CMSG_LEN(sizeof(int)), 0, &flags, NULL);
    if (limited)
        CHECK(!setrlimit(RLIMIT_NOFILE, &before));
    CHECK(count == (limited ? 0u : 1u) && (flags & MSG_CTRUNC));
    for (unsigned n = 0; n < count; ++n)
        CHECK(fcntl(files[n], F_GETFD) == 0 && !close(files[n]));
    CHECK(read(pipefd[0], &byte, 1) == 0 && !close(pipefd[0]));
    finish(sockets);
    printf("UNIX_MESSAGES_DISCARDED_RIGHTS_PASS mode=%s payload_received "
           "final_pipe_reference_released\n",
           limited ? "descriptor_limit" : "short_control");
}

static void unread_close(void) {
    int sockets[2], pipefd[2];
    pair(sockets);
    CHECK(!pipe2(pipefd, O_NONBLOCK | O_CLOEXEC));
    send_rights(sockets[0], &pipefd[1], 1);
    CHECK(!close(pipefd[1]));
    char byte;
    CHECK(read(pipefd[0], &byte, 1) == -1 && errno == EAGAIN);
    CHECK(!close(sockets[1]));
    CHECK(read(pipefd[0], &byte, 1) == 0 && !close(pipefd[0]) && !close(sockets[0]));
    puts("UNIX_MESSAGES_UNREAD_CLOSE_PASS queued_reference_released");
}

static void fault_consumption(void) {
    int sockets[2];
    pair(sockets);
    CHECK(send(sockets[0], "fault", 5, 0) == 5);
    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    void* inaccessible = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(inaccessible != MAP_FAILED);
    CHECK(recv(sockets[1], inaccessible, 5, 0) == -1 && errno == EFAULT);
    char bytes[8];
    errno = 0;
    ssize_t remaining = recv(sockets[1], bytes, sizeof(bytes), 0);
    int error = errno;
    CHECK(remaining == -1 && error == EAGAIN);
    CHECK(!munmap(inaccessible, page));
    finish(sockets);
    puts("UNIX_MESSAGES_FAULT_CONSUMPTION_PASS inaccessible_payload consumes_record");
}

int main(void) {
    printf("UNIX_MESSAGES_IDENTITY pid=%ld uid=%u euid=%u gid=%u egid=%u groups=%d\n",
           (long)getpid(), getuid(), geteuid(), getgid(), getegid(), getgroups(0, NULL));
    boundaries();
    credentials();
    peek_rights();
    discarded_rights(0);
    discarded_rights(1);
    unread_close();
    fault_consumption();
    puts("UNIX_MESSAGES_PASS groups=7");
}
