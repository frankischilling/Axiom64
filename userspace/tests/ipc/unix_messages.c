// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
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

static void data_vectors(void) {
    int sockets[2];
    pair(sockets);
    unsigned char input[13007], output[13007];
    for (unsigned index = 0; index < sizeof(input); ++index)
        input[index] = (unsigned char)(index * 71 + 5);
    struct iovec send_vectors[] = {{input, 7001}, {NULL, 0}, {input + 7001, 6006}};
    CHECK(writev(sockets[0], send_vectors, 3) == sizeof(input));
    memset(input, 0, sizeof(input));
    struct iovec receive_vectors[] = {{output, 17}, {output + 17, 10000}, {output + 10017, 2990}};
    CHECK(readv(sockets[1], receive_vectors, 3) == sizeof(output));
    for (unsigned index = 0; index < sizeof(output); ++index)
        CHECK(output[index] == (unsigned char)(index * 71 + 5));
    CHECK(send(sockets[0], "queued", 6, 0) == 6);
    CHECK(!close(sockets[0]));
    struct sockaddr_un source;
    memset(&source, 0xaa, sizeof(source));
    socklen_t length = sizeof(source);
    CHECK(recvfrom(sockets[1], output, sizeof(output), 0, (struct sockaddr*)&source, &length) ==
              6 &&
          length == 0 && (unsigned char)source.sun_path[0] == 0xaa && !memcmp(output, "queued", 6));
    CHECK(recv(sockets[1], output, sizeof(output), 0) == -1 && errno == EAGAIN);
    struct pollfd event = {.fd = sockets[1], .events = POLLIN | POLLRDHUP};
    CHECK(!poll(&event, 1, 0) && !event.revents);
    CHECK(!close(sockets[1]));
    puts("UNIX_MESSAGES_VECTORS_PASS atomic_large_record copied_vectors unnamed_source "
         "retained_after_peer_close");
}

static int buffer_size(int fd, int option) {
    int value = 0;
    socklen_t size = sizeof(value);
    CHECK(!getsockopt(fd, SOL_SOCKET, option, &value, &size) && size == sizeof(value));
    return value;
}

static void buffer_ownership(void) {
    int sockets[2];
    pair(sockets);
    int requests[] = {-1, 0, 1, 1024, 4096, 65536, 2147483647};
    int send_values[] = {425984, 4608, 4608, 4608, 8192, 131072, 425984};
    int receive_values[] = {425984, 2304, 2304, 2304, 8192, 131072, 425984};
    for (unsigned index = 0; index < sizeof(requests) / sizeof(requests[0]); ++index) {
        CHECK(!setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &requests[index], sizeof(int)));
        CHECK(!setsockopt(sockets[0], SOL_SOCKET, SO_RCVBUF, &requests[index], sizeof(int)));
        CHECK(buffer_size(sockets[0], SO_SNDBUF) == send_values[index]);
        CHECK(buffer_size(sockets[0], SO_RCVBUF) == receive_values[index]);
    }
    int amount = 4096;
    CHECK(!setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &amount, sizeof(amount)));
    amount = 0;
    CHECK(!setsockopt(sockets[1], SOL_SOCKET, SO_RCVBUF, &amount, sizeof(amount)));
    unsigned char payload[4096], received[4096];
    memset(payload, 0x37, sizeof(payload));
    unsigned count = 0;
    while (send(sockets[0], payload, sizeof(payload), 0) == sizeof(payload))
        CHECK(++count < 4096);
    CHECK(errno == EAGAIN && count);
    struct pollfd writable = {.fd = sockets[0], .events = POLLOUT};
    CHECK(!poll(&writable, 1, 0) && !writable.revents);
    CHECK(!setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &amount, sizeof(amount)));
    CHECK(buffer_size(sockets[0], SO_SNDBUF) == 4608);
    CHECK(send(sockets[0], payload, sizeof(payload), 0) == -1 && errno == EAGAIN);
    amount = 65536;
    CHECK(!setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &amount, sizeof(amount)));
    CHECK(send(sockets[0], payload, sizeof(payload), 0) == sizeof(payload));
    for (unsigned index = 0; index <= count; ++index)
        CHECK(recv(sockets[1], received, sizeof(received), 0) == sizeof(received) &&
              !memcmp(payload, received, sizeof(payload)));
    CHECK(poll(&writable, 1, 0) == 1 && writable.revents == POLLOUT);
    CHECK(send(sockets[0], payload, sizeof(payload), 0) == sizeof(payload));
    CHECK(!close(sockets[0]));
    int reused[2];
    pair(reused);
    CHECK(send(reused[0], "new", 3, 0) == 3 &&
          recv(reused[1], received, sizeof(received), 0) == 3 && !memcmp(received, "new", 3));
    CHECK(recv(sockets[1], received, sizeof(received), 0) == sizeof(received) &&
          !memcmp(payload, received, sizeof(payload)));
    CHECK(!close(sockets[1]));
    finish(reused);
    puts("UNIX_MESSAGES_BUFFERS_PASS setters clamping sender_pressure resize readiness "
         "queued_sender_close reuse");
}

static volatile sig_atomic_t pipe_signals;

static void pipe_signal(int number) {
    (void)number;
    ++pipe_signals;
}

static void shutdown_contract(void) {
    struct sigaction action = {.sa_handler = pipe_signal}, previous;
    CHECK(!sigemptyset(&action.sa_mask) && !sigaction(SIGPIPE, &action, &previous));
    for (int nonblocking = 0; nonblocking != 2; ++nonblocking) {
        for (int how = SHUT_RD; how <= SHUT_RDWR; ++how) {
            int sockets[2];
            pair(sockets);
            if (!nonblocking)
                CHECK(!fcntl(sockets[1], F_SETFL, fcntl(sockets[1], F_GETFL) & ~O_NONBLOCK));
            struct timeval timeout = {.tv_usec = 200000};
            CHECK(!setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
            CHECK(send(sockets[0], "Q", 1, 0) == 1 && !shutdown(sockets[1], how));
            struct pollfd events[2] = {{.fd = sockets[0], .events = POLLIN | POLLOUT | POLLRDHUP},
                                       {.fd = sockets[1], .events = POLLIN | POLLOUT | POLLRDHUP}};
            CHECK(poll(events, 2, 0) == 2 && events[0].revents == POLLOUT &&
                  events[1].revents == (POLLIN | POLLOUT | (how != SHUT_WR ? POLLRDHUP : 0) |
                                        (how == SHUT_RDWR ? POLLHUP : 0)));
            char byte;
            CHECK(recv(sockets[1], &byte, 1, MSG_PEEK) == 1 && byte == 'Q');
            CHECK(recv(sockets[1], &byte, 1, 0) == 1 && byte == 'Q');
            errno = 0;
            ssize_t empty = recv(sockets[1], &byte, 1, 0);
            CHECK((!nonblocking && how != SHUT_WR) ? empty == 0 : empty == -1 && errno == EAGAIN);
            if (!nonblocking && how != SHUT_WR) {
                struct sockaddr_un source;
                unsigned char control[64];
                struct iovec vector = {&byte, 1};
                struct msghdr message = {.msg_name = &source,
                                         .msg_namelen = sizeof(source),
                                         .msg_iov = &vector,
                                         .msg_iovlen = 1,
                                         .msg_control = control,
                                         .msg_controllen = sizeof(control),
                                         .msg_flags = -1};
                CHECK(!recvmsg(sockets[1], &message, 0) && !message.msg_namelen &&
                      !message.msg_controllen && !message.msg_flags);
            }
            pipe_signals = 0;
            ssize_t sent = send(sockets[0], "P", 1, 0);
            CHECK(how == SHUT_WR ? sent == 1 : sent == -1 && errno == EPIPE);
            sent = send(sockets[1], "O", 1, 0);
            CHECK(how == SHUT_RD ? sent == 1 : sent == -1 && errno == EPIPE);
            CHECK(!pipe_signals);
            finish(sockets);
        }
    }
    CHECK(!sigaction(SIGPIPE, &previous, NULL));
    puts("UNIX_MESSAGES_SHUTDOWN_PASS queued_data asymmetric_shutdown blocking_eof "
         "nonblocking_eagain poll no_sigpipe");
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

static void retained_resize(void) {
    int sockets[2], ready[2], result[2];
    pair(sockets);
    CHECK(!pipe2(ready, O_NONBLOCK | O_CLOEXEC));
    CHECK(!pipe2(result, O_NONBLOCK | O_CLOEXEC));
    int size = 32768;
    CHECK(!setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)));
    char fill[4000], payload[10000], received[10000];
    memset(fill, 'F', sizeof(fill));
    memset(payload, 'P', sizeof(payload));
    unsigned queued = 0;
    while (send(sockets[0], fill, sizeof(fill), MSG_DONTWAIT) == sizeof(fill))
        CHECK(++queued < 10000);
    CHECK(errno == EAGAIN && queued);
    CHECK(!fcntl(sockets[0], F_SETFL, 0));
    struct timeval timeout = {.tv_sec = 5};
    CHECK(!setsockopt(sockets[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(!close(ready[0]) && !close(result[0]) && !close(sockets[1]));
        CHECK(write(ready[1], "R", 1) == 1);
        ssize_t sent = send(sockets[0], payload, sizeof(payload), 0);
        CHECK(write(result[1], &sent, sizeof(sent)) == sizeof(sent));
        _exit(sent == sizeof(payload) ? 0 : 1);
    }
    CHECK(!close(ready[1]) && !close(result[1]));
    readable(ready[0]);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && byte == 'R');
    // The child has no other blocking operation after its nonblocking ready write.
    // Observe the actual sleep before resizing, rather than guessing a delay.
    char path[64], status[2048];
    CHECK(snprintf(path, sizeof(path), "/proc/%ld/stat", (long)child) > 0);
    struct timespec began, now;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &began));
    for (;;) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        CHECK(fd >= 0);
        ssize_t count = read(fd, status, sizeof(status) - 1);
        CHECK(count > 0 && !close(fd));
        status[count] = 0;
        char* state = strrchr(status, ')');
        CHECK(state && state[1] == ' ' && state[2] != 'Z');
        if (state[2] == 'S')
            break;
        CHECK(!clock_gettime(CLOCK_MONOTONIC, &now) && now.tv_sec - began.tv_sec < 3);
        usleep(1000);
    }
    struct pollfd pending = {.fd = result[0], .events = POLLIN};
    CHECK(!poll(&pending, 1, 0));
    size = 0;
    CHECK(!setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)));
    for (unsigned n = 0; n < queued; n++)
        CHECK(recv(sockets[1], received, sizeof(received), 0) == sizeof(fill) &&
              !memcmp(received, fill, sizeof(fill)));
    readable(result[0]);
    ssize_t sent;
    CHECK(read(result[0], &sent, sizeof(sent)) == sizeof(sent) && sent == sizeof(payload));
    readable(sockets[1]);
    CHECK(recv(sockets[1], received, sizeof(received), 0) == sizeof(payload) &&
          !memcmp(received, payload, sizeof(payload)));
    CHECK(send(sockets[0], payload, sizeof(payload), 0) == -1 && errno == EMSGSIZE);
    int exit_status;
    CHECK(waitpid(child, &exit_status, 0) == child && WIFEXITED(exit_status) &&
          !WEXITSTATUS(exit_status));
    CHECK(!close(ready[0]) && !close(result[0]));
    finish(sockets);
    puts("UNIX_MESSAGES_RETAINED_RESIZE_PASS sleeping_sender original_size new_send_limit "
         "exact_bytes");
}

static void fault_consumption(void) {
    int sockets[2];
    pair(sockets);
    CHECK(send(sockets[0], "fault", 5, 0) == 5);
    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    void* inaccessible = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(inaccessible != MAP_FAILED);
    CHECK(recv(sockets[1], inaccessible, 5, MSG_PEEK) == -1 && errno == EFAULT);
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

int main(int argc, char** argv) {
    int ordinary =
        argc == 2 && (!strcmp(argv[1], "--ordinary-data") || !strcmp(argv[1], "--ordinary"));
    int data_only = argc == 2 && strcmp(argv[1], "--ordinary");
    CHECK(argc == 1 || (argc == 2 && (!strcmp(argv[1], "--data-only") || ordinary)));
    if (ordinary) {
        CHECK(!geteuid() && !setgroups(0, NULL));
        CHECK(!setresgid(65534, 65534, 65534) && !setresuid(65534, 65534, 65534));
        CHECK(getuid() == 65534 && geteuid() == 65534 && getgid() == 65534 && getegid() == 65534 &&
              !getgroups(0, NULL));
    }
    printf("UNIX_MESSAGES_IDENTITY pid=%ld uid=%u euid=%u gid=%u egid=%u groups=%d\n",
           (long)getpid(), getuid(), geteuid(), getgid(), getegid(), getgroups(0, NULL));
    boundaries();
    data_vectors();
    buffer_ownership();
    shutdown_contract();
    retained_resize();
    if (data_only) {
        fault_consumption();
        puts("UNIX_MESSAGES_DATA_PASS groups=6");
        return 0;
    }
    credentials();
    peek_rights();
    discarded_rights(0);
    discarded_rights(1);
    unread_close();
    fault_consumption();
    puts("UNIX_MESSAGES_PASS groups=11");
}
