// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pid_t child;

static void fail(int line, const char* expression) {
    int error = errno;
    if (child > 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
    }
    fprintf(stderr, "UNIX_STREAM_WAIT_FAIL line=%d expression=%s errno=%d\n", line, expression,
            error);
    exit(1);
}

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value))                                                                              \
            fail(__LINE__, #value);                                                                \
    } while (0)

enum { bytes = 1024 * 1024 };

struct operation {
    int fd, ready, kind, error, signals, pipe_signals, right;
    ssize_t result;
    uint64_t began, ended;
    atomic_int done;
    struct iovec vectors[2];
    unsigned receive_flags, message_flags;
    size_t control_length;

    union {
        struct cmsghdr aligned;
        unsigned char bytes[128];
    } control;

    unsigned char payload[bytes], wrong[16];
};

static volatile sig_atomic_t caught;
static volatile sig_atomic_t broken;

static void handler(int number) {
    caught += number == SIGUSR1;
    broken += number == SIGPIPE;
}

static uint64_t now(void) {
    struct timespec value;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &value));
    return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}

static int sender(void* pointer) {
    struct operation* operation = pointer;
    CHECK(write(operation->ready, "r", 1) == 1);
    operation->began = now();
    errno = 0;
    if (operation->kind == 0)
        operation->result = write(operation->fd, operation->payload, bytes);
    else if (operation->kind == 1)
        operation->result = writev(operation->fd, operation->vectors, 2);
    else if (operation->kind == 2)
        operation->result = send(operation->fd, operation->payload, bytes, MSG_NOSIGNAL);
    else {
        union {
            struct cmsghdr aligned;
            unsigned char bytes[CMSG_SPACE(sizeof(int))];
        } control = {0};
        struct msghdr message = {.msg_iov = operation->vectors,
                                 .msg_iovlen = 2,
                                 .msg_control = control.bytes,
                                 .msg_controllen = sizeof(control)};
        struct cmsghdr* header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &operation->right, sizeof(int));
        operation->result = sendmsg(operation->fd, &message, MSG_NOSIGNAL);
    }
    operation->error = errno;
    operation->signals = caught;
    operation->pipe_signals = broken;
    operation->ended = now();
    atomic_store(&operation->done, 1);
    return 0;
}

static void sleeping(struct operation* operation, size_t requested) {
    uint64_t began = now();
    char path[64], data[2048];
    CHECK(snprintf(path, sizeof(path), "/proc/%ld/stat", (long)child) > 0);
    for (;;) {
        if (atomic_load(&operation->done)) {
            fprintf(stderr, "UNIX_STREAM_WAIT_PREMATURE result=%ld requested=%zu errno=%d\n",
                    (long)operation->result, requested, operation->error);
            CHECK(!atomic_load(&operation->done));
        }
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        CHECK(fd >= 0);
        ssize_t count = read(fd, data, sizeof(data) - 1);
        CHECK(count > 0 && !close(fd));
        data[count] = 0;
        char* state = strrchr(data, ')');
        CHECK(state && state[1] == ' ' && state[2] != 'Z');
        if (state[2] == 'S')
            return;
        CHECK(now() - began < 2000000000 && !usleep(1000));
    }
}

static ssize_t receive(int fd, unsigned char* buffer, size_t capacity, unsigned* rights) {
    union {
        struct cmsghdr aligned;
        unsigned char bytes[CMSG_SPACE(2 * sizeof(int))];
    } control = {0};
    struct iovec vector = {buffer, capacity};
    struct msghdr message = {.msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control.bytes,
                             .msg_controllen = sizeof(control)};
    ssize_t count = recvmsg(fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (count < 0)
        return count;
    CHECK(!(message.msg_flags & MSG_CTRUNC));
    for (struct cmsghdr* header = CMSG_FIRSTHDR(&message); header;
         header = CMSG_NXTHDR(&message, header)) {
        CHECK(header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
              header->cmsg_len == CMSG_LEN(sizeof(int)) && *rights == 0);
        int file;
        memcpy(&file, CMSG_DATA(header), sizeof(file));
        char token;
        CHECK(fcntl(file, F_GETFD) == FD_CLOEXEC && read(file, &token, 1) == 1 && token == 'R');
        CHECK(!read(file, &token, 1) && !close(file));
        (*rights)++;
    }
    return count;
}

static void one(unsigned kind, unsigned mode) {
    caught = broken = 0;
    int sockets[2], ready[2], replacement[2];
    int rights[2] = {-1, -1};
    CHECK(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets));
    CHECK(!pipe2(ready, O_CLOEXEC) && !pipe2(replacement, O_NONBLOCK | O_CLOEXEC));
    int alias = dup(sockets[0]);
    CHECK(alias >= 0);
    struct operation* operation =
        mmap(NULL, sizeof(*operation), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    void* stack =
        mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    CHECK(operation != MAP_FAILED && stack != MAP_FAILED);
    operation->fd = sockets[0];
    operation->ready = ready[1];
    operation->kind = kind;
    if (kind == 3) {
        CHECK(!pipe2(rights, O_CLOEXEC) && write(rights[1], "R", 1) == 1);
        operation->right = rights[0];
    }
    for (unsigned index = 0; index < bytes; index++)
        operation->payload[index] = (unsigned char)(index * 29 + (index >> 8));
    memset(operation->wrong, 0xe7, sizeof(operation->wrong));
    operation->vectors[0] = (struct iovec){operation->payload, 12345};
    operation->vectors[1] = (struct iovec){operation->payload + 12345, bytes - 12345};
    struct sigaction action = {.sa_handler = handler, .sa_flags = mode == 3 ? SA_RESTART : 0};
    CHECK(!sigemptyset(&action.sa_mask) && !sigaction(SIGUSR1, &action, NULL));
    CHECK(!sigaction(SIGPIPE, &action, NULL));
    if (mode == 1) {
        struct timeval timeout = {0, 200000};
        CHECK(!setsockopt(alias, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));
    }
    size_t queued = 0;
    if (mode == 5) {
        unsigned char filler[4096];
        memset(filler, 0x5a, sizeof(filler));
        for (;;) {
            ssize_t count = send(alias, filler, sizeof(filler), MSG_DONTWAIT | MSG_NOSIGNAL);
            if (count == -1) {
                CHECK(errno == EAGAIN);
                break;
            }
            CHECK(count > 0 && queued < 16 * 1024 * 1024);
            queued += (size_t)count;
        }
        CHECK(queued);
    }
    child = clone(sender, (char*)stack + 65536, CLONE_FILES | SIGCHLD, operation);
    CHECK(child > 0);
    char token;
    CHECK(read(ready[0], &token, 1) == 1 && token == 'r');
    sleeping(operation, bytes);
    if (kind == 3)
        CHECK(!close(rights[0]) && !close(rights[1]));
    CHECK(dup2(replacement[1], operation->fd) == operation->fd);
    operation->vectors[0] = (struct iovec){operation->wrong, 3};
    operation->vectors[1] = (struct iovec){operation->wrong + 3, 13};
    int flags = fcntl(alias, F_GETFL);
    CHECK(flags >= 0 && !fcntl(alias, F_SETFL, flags | O_NONBLOCK));
    if (mode == 1) {
        struct timeval timeout = {5, 0};
        CHECK(!setsockopt(alias, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));
    } else if (mode == 2 || mode == 3)
        CHECK(!kill(child, SIGUSR1));
    else if (mode >= 4)
        CHECK(!shutdown(sockets[1], SHUT_RD));
    size_t drained = 0;
    unsigned received_rights = 0;
    uint64_t deadline = now() + 3000000000;
    unsigned char buffer[4096];
    for (;;) {
        if (mode && atomic_load(&operation->done))
            break;
        if (!mode && drained == bytes)
            break;
        if (!mode) {
            ssize_t count = receive(sockets[1], buffer, sizeof(buffer), &received_rights);
            if (count > 0) {
                CHECK(drained + (size_t)count <= bytes);
                CHECK(!memcmp(buffer, operation->payload + drained, count));
                drained += count;
                continue;
            }
            CHECK(count == -1 && errno == EAGAIN);
        }
        CHECK(now() < deadline && !usleep(1000));
    }
    int status;
    pid_t reaped = waitpid(child, &status, 0);
    child = 0;
    CHECK(reaped > 0 && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(atomic_load(&operation->done));
    CHECK(operation->signals == (mode == 2 || mode == 3));
    unsigned expected_pipe = 0;
    if ((unsigned)operation->pipe_signals != expected_pipe)
        fprintf(stderr, "UNIX_STREAM_WAIT_PIPE kind=%u mode=%u result=%ld expected=%u actual=%d\n",
                kind, mode, (long)operation->result, expected_pipe, operation->pipe_signals);
    CHECK((unsigned)operation->pipe_signals == expected_pipe);
    if (mode == 5)
        CHECK(operation->result == -1 && operation->error == EPIPE);
    else {
        CHECK(operation->error == 0 && operation->result > 0 && operation->result <= bytes);
        CHECK(mode ? operation->result < bytes : operation->result == bytes);
    }
    if (mode == 1)
        CHECK(operation->ended - operation->began >= 200000000 &&
              operation->ended - operation->began < 3000000000);
    if (mode >= 4) {
        errno = 0;
        CHECK(write(alias, "X", 1) == -1 && errno == EPIPE && broken == 1);
    }
    CHECK(!close(alias));
    while (queued) {
        ssize_t count = receive(sockets[1], buffer, sizeof(buffer), &received_rights);
        CHECK(count > 0 && (size_t)count <= queued);
        for (ssize_t index = 0; index < count; index++)
            CHECK(buffer[index] == 0x5a);
        queued -= (size_t)count;
    }
    size_t accepted = operation->result > 0 ? (size_t)operation->result : 0;
    while (drained < accepted) {
        ssize_t count = receive(sockets[1], buffer, sizeof(buffer), &received_rights);
        CHECK(count > 0 && drained + (size_t)count <= (size_t)operation->result);
        CHECK(!memcmp(buffer, operation->payload + drained, count));
        drained += count;
    }
    CHECK(!recv(sockets[1], buffer, 1, MSG_DONTWAIT));
    CHECK(received_rights == (kind == 3 && mode != 5));
    CHECK(read(replacement[0], buffer, 1) == -1 && errno == EAGAIN);
    CHECK(write(operation->fd, "N", 1) == 1 && read(replacement[0], buffer, 1) == 1 &&
          buffer[0] == 'N');
    CHECK(!close(sockets[0]) && !close(sockets[1]) && !close(ready[0]) && !close(ready[1]) &&
          !close(replacement[0]) && !close(replacement[1]));
    CHECK(!munmap(stack, 65536) && !munmap(operation, sizeof(*operation)));
}

enum receive_mode {
    FULL,
    END,
    CLOSE,
    DEADLINE,
    INTERRUPT,
    RESTART,
    FAULT,
    PEEK,
    NONBLOCK,
    RIGHTS,
    CREDENTIALS
};

static int receiver(void* pointer) {
    struct operation* operation = pointer;
    struct msghdr message = {.msg_iov = operation->vectors,
                             .msg_iovlen = 2,
                             .msg_control = operation->control.bytes,
                             .msg_controllen = sizeof(operation->control)};
    CHECK(write(operation->ready, "r", 1) == 1);
    operation->began = now();
    errno = 0;
    operation->result = operation->kind ? recvmsg(operation->fd, &message,
                                                  operation->receive_flags | MSG_CMSG_CLOEXEC)
                                        : recv(operation->fd, operation->vectors[0].iov_base,
                                               operation->control_length, operation->receive_flags);
    operation->error = errno;
    operation->signals = caught;
    operation->ended = now();
    operation->control_length = operation->kind ? message.msg_controllen : 0;
    operation->message_flags = operation->kind ? message.msg_flags : 0;
    atomic_store(&operation->done, 1);
    return 0;
}

static void received(unsigned kind, unsigned mode) {
    caught = broken = 0;
    int sockets[2], replacement[2], ready[2], files[2] = {-1, -1};
    CHECK(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets));
    CHECK(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, replacement));
    CHECK(!pipe2(ready, O_CLOEXEC));
    int alias = dup(sockets[0]), enabled = 1;
    CHECK(alias >= 0 && !setsockopt(alias, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)));
    CHECK(send(sockets[1], "ab", 2, MSG_NOSIGNAL) == 2);
    struct operation* operation =
        mmap(NULL, sizeof(*operation), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    void* stack =
        mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    unsigned char* mapping =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(operation != MAP_FAILED && stack != MAP_FAILED && mapping != MAP_FAILED);
    memset(mapping, 0xe7, 8192);
    unsigned char* output = mapping + 4094;
    if (mode == FAULT)
        CHECK(!mprotect(mapping + 4096, 4096, PROT_NONE));
    size_t requested = mode == RIGHTS ? 6 : 4;
    operation->fd = sockets[0];
    operation->ready = ready[1];
    operation->kind = kind;
    operation->receive_flags =
        MSG_WAITALL | (mode == PEEK ? MSG_PEEK : 0) | (mode == NONBLOCK ? MSG_DONTWAIT : 0);
    operation->control_length = requested;
    operation->vectors[0] = (struct iovec){output, 2};
    operation->vectors[1] = (struct iovec){output + 2, requested - 2};
    memset(operation->wrong, 0xe7, sizeof(operation->wrong));
    struct sigaction action = {.sa_handler = handler, .sa_flags = mode == RESTART ? SA_RESTART : 0};
    CHECK(!sigemptyset(&action.sa_mask) && !sigaction(SIGUSR1, &action, NULL) &&
          !sigaction(SIGPIPE, &action, NULL));
    if (mode == DEADLINE) {
        struct timeval timeout = {0, 200000};
        CHECK(!setsockopt(alias, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    }
    if (mode == RIGHTS)
        CHECK(!pipe2(files, O_CLOEXEC) && write(files[1], "R", 1) == 1);
    child = clone(receiver, (char*)stack + 65536, CLONE_FILES | SIGCHLD, operation);
    CHECK(child > 0);
    char token;
    CHECK(read(ready[0], &token, 1) == 1 && token == 'r');
    if (mode != PEEK && mode != NONBLOCK) {
        sleeping(operation, requested);
        CHECK(dup2(replacement[0], operation->fd) == operation->fd);
        CHECK(send(replacement[1], "WXYZ", 4, MSG_NOSIGNAL) == 4);
        operation->vectors[0] = (struct iovec){operation->wrong, 1};
        operation->vectors[1] = (struct iovec){operation->wrong + 1, 3};
        int flags = fcntl(alias, F_GETFL);
        CHECK(flags >= 0 && !fcntl(alias, F_SETFL, flags | O_NONBLOCK));
    }
    if (mode == DEADLINE) {
        struct timeval timeout = {5, 0};
        CHECK(!setsockopt(alias, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    } else if (mode == END)
        CHECK(!shutdown(sockets[1], SHUT_WR));
    else if (mode == CLOSE) {
        CHECK(!close(sockets[1]));
        sockets[1] = -1;
    } else if (mode == INTERRUPT || mode == RESTART)
        CHECK(!kill(child, SIGUSR1));
    else if (mode == FULL || mode == FAULT)
        CHECK(send(sockets[1], "cd", 2, MSG_NOSIGNAL) == 2);
    else if (mode == RIGHTS) {
        union {
            struct cmsghdr aligned;
            unsigned char bytes[CMSG_SPACE(sizeof(int))];
        } control = {0};
        struct iovec vector = {(void*)"cd", 2};
        struct msghdr message = {.msg_iov = &vector,
                                 .msg_iovlen = 1,
                                 .msg_control = control.bytes,
                                 .msg_controllen = sizeof(control)};
        struct cmsghdr* header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &files[0], sizeof(int));
        CHECK(sendmsg(sockets[1], &message, MSG_NOSIGNAL) == 2 && !close(files[0]));
    } else if (mode == CREDENTIALS) {
        pid_t producer = fork();
        CHECK(producer >= 0);
        if (!producer)
            _exit(send(sockets[1], "cd", 2, MSG_NOSIGNAL) == 2 ? 0 : 1);
        int status;
        CHECK(waitpid(producer, &status, 0) == producer && WIFEXITED(status) &&
              !WEXITSTATUS(status));
    }
    uint64_t deadline = now() + 3000000000;
    while (!atomic_load(&operation->done))
        CHECK(now() < deadline && !usleep(1000));
    int status;
    pid_t reaped = waitpid(child, &status, 0);
    child = 0;
    CHECK(reaped > 0 && WIFEXITED(status) && !WEXITSTATUS(status));
    if (mode == FAULT)
        CHECK(!mprotect(mapping + 4096, 4096, PROT_READ | PROT_WRITE));
    ssize_t expected = mode == FULL || mode == RIGHTS ? 4 : 2;
    CHECK(operation->result == expected && !operation->error && !memcmp(output, "abcd", expected));
    CHECK(output[expected] == 0xe7);
    CHECK(operation->signals == (mode == INTERRUPT || mode == RESTART));
    for (unsigned index = 0; index < sizeof(operation->wrong); index++)
        CHECK(operation->wrong[index] == 0xe7);
    if (mode == DEADLINE)
        CHECK(operation->ended - operation->began >= 200000000 &&
              operation->ended - operation->began < 3000000000);
    if (kind) {
        size_t expected_control =
            mode == INTERRUPT || mode == RESTART ? 0 : CMSG_SPACE(sizeof(struct ucred));
        if (mode == RIGHTS)
            expected_control += CMSG_SPACE(sizeof(int));
        CHECK(operation->control_length == expected_control &&
              operation->message_flags == MSG_CMSG_CLOEXEC);
        struct msghdr message = {.msg_control = operation->control.bytes,
                                 .msg_controllen = operation->control_length};
        unsigned identities = 0, rights = 0;
        for (struct cmsghdr* header = CMSG_FIRSTHDR(&message); header;
             header = CMSG_NXTHDR(&message, header)) {
            CHECK(header->cmsg_level == SOL_SOCKET);
            if (header->cmsg_type == SCM_CREDENTIALS) {
                struct ucred identity;
                CHECK(header->cmsg_len == CMSG_LEN(sizeof(identity)));
                memcpy(&identity, CMSG_DATA(header), sizeof(identity));
                CHECK(identity.pid == getpid() && identity.uid == getuid() &&
                      identity.gid == getgid());
                identities++;
            } else {
                int file;
                CHECK(mode == RIGHTS && header->cmsg_type == SCM_RIGHTS &&
                      header->cmsg_len == CMSG_LEN(sizeof(file)));
                memcpy(&file, CMSG_DATA(header), sizeof(file));
                CHECK(fcntl(file, F_GETFD) == FD_CLOEXEC && read(file, &token, 1) == 1 &&
                      token == 'R' && !close(file));
                rights++;
            }
        }
        CHECK(identities == (expected_control != 0) && rights == (mode == RIGHTS));
    }
    if (mode == RIGHTS) {
        errno = 0;
        CHECK(write(files[1], "L", 1) == -1 && errno == EPIPE && broken == 1 && !close(files[1]));
    }
    char pending[8];
    if (mode == PEEK || mode == FAULT || mode == CREDENTIALS)
        CHECK(recv(alias, pending, sizeof(pending), MSG_DONTWAIT) == 2 &&
              !memcmp(pending, mode == PEEK ? "ab" : "cd", 2));
    ssize_t empty = recv(alias, pending, 1, MSG_DONTWAIT);
    CHECK(mode == END || mode == CLOSE ? empty == 0 : empty == -1 && errno == EAGAIN);
    if (mode != PEEK && mode != NONBLOCK)
        CHECK(recv(replacement[0], pending, sizeof(pending), MSG_DONTWAIT) == 4 &&
              !memcmp(pending, "WXYZ", 4));
    CHECK(!close(sockets[0]) && (sockets[1] < 0 || !close(sockets[1])) && !close(alias) &&
          !close(replacement[0]) && !close(replacement[1]) && !close(ready[0]) && !close(ready[1]));
    CHECK(!munmap(mapping, 8192) && !munmap(stack, 65536) &&
          !munmap(operation, sizeof(*operation)));
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")));
    if (argc == 2)
        CHECK(!geteuid() && !setgroups(0, NULL) && !setresgid(65534, 65534, 65534) &&
              !setresuid(65534, 65534, 65534));
    printf("UNIX_STREAM_WAIT_IDENTITY uid=%u euid=%u gid=%u egid=%u groups=%d\n", getuid(),
           geteuid(), getgid(), getegid(), getgroups(0, NULL));
    for (unsigned kind = 0; kind < 4; kind++)
        for (unsigned mode = 0; mode < 6; mode++)
            one(kind, mode);
    puts("UNIX_STREAM_WAIT_SEND_PASS cases=24 scalar vector message replacement captured_flags "
         "deadline signal restart peer_shutdown sigpipe exact_bytes rights_once");
    for (unsigned kind = 0; kind < 2; kind++)
        for (unsigned mode = FULL; mode <= CREDENTIALS; mode++)
            received(kind, mode);
    puts("UNIX_STREAM_WAIT_RECEIVE_PASS cases=22 waitall peek nonblock credentials rights boundary "
         "replacement vectors signal restart deadline fault prefix");
    puts("UNIX_STREAM_WAIT_PASS groups=2");
    return 0;
}
