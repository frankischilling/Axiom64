// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stddef.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "UNIX_ROUTING_WAIT_FAIL line=%d expression=%s errno=%d\n", __LINE__,   \
                    #value, errno);                                                                \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

struct named {
    int fd;
    struct sockaddr_un address;
    socklen_t length;
};

struct input {
    struct sockaddr_un address;
    socklen_t length;
    char payload[4];
};

struct result {
    ssize_t sent;
    int error;
    uid_t uid, euid;
    gid_t gid, egid;
    int groups;
};

struct held {
    pid_t child;
    int result;
};

static void readable(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    CHECK(poll(&p, 1, 3000) == 1 && (p.revents & POLLIN));
}

static struct named endpoint(char tag, const char* path) {
    struct named value = {.fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0),
                          .address = {.sun_family = AF_UNIX}};
    CHECK(value.fd >= 0);
    if (path) {
        CHECK(strlen(path) < sizeof(value.address.sun_path));
        memcpy(value.address.sun_path, path, strlen(path) + 1);
        value.length = offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;
    } else {
        int n = snprintf(value.address.sun_path + 1, sizeof(value.address.sun_path) - 1,
                         "ax-wait-%ld-%c", (long)getpid(), tag);
        CHECK(n > 0 && n < 100);
        value.length = offsetof(struct sockaddr_un, sun_path) + 1 + n;
    }
    CHECK(!bind(value.fd, (struct sockaddr*)&value.address, value.length));
    return value;
}

static void connect_to(int fd, const struct named* receiver) {
    CHECK(!connect(fd, (const struct sockaddr*)&receiver->address, receiver->length));
}

static void sleeping(pid_t child) {
    char path[64], text[2048];
    CHECK(snprintf(path, sizeof(path), "/proc/%ld/stat", (long)child) > 0);
    struct timespec began, now;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &began));
    for (;;) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        CHECK(fd >= 0);
        ssize_t count = read(fd, text, sizeof(text) - 1);
        CHECK(count > 0 && !close(fd));
        text[count] = 0;
        char* state = strrchr(text, ')');
        CHECK(state && state[1] == ' ' && state[2] != 'Z');
        if (state[2] == 'S')
            return;
        CHECK(!clock_gettime(CLOCK_MONOTONIC, &now) && now.tv_sec - began.tv_sec < 2);
        usleep(1000);
    }
}

static struct held start(int sender, const int* receivers, unsigned count, struct input* input,
                         int named, int ordinary) {
    CHECK(!fcntl(sender, F_SETFL, fcntl(sender, F_GETFL) & ~O_NONBLOCK));
    struct timeval timeout = {.tv_sec = 5};
    CHECK(!setsockopt(sender, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));
    int ready[2], result[2];
    CHECK(!pipe2(ready, O_NONBLOCK | O_CLOEXEC) && !pipe2(result, O_NONBLOCK | O_CLOEXEC));
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(!close(ready[0]) && !close(result[0]));
        for (unsigned n = 0; n < count; n++)
            CHECK(!close(receivers[n]));
        if (ordinary && !geteuid()) {
            CHECK(!setgroups(0, NULL));
            CHECK(!setresgid(65534, 65534, 65534) && !setresuid(65534, 65534, 65534));
        }
        CHECK(write(ready[1], "R", 1) == 1);
        errno = 0;
        ssize_t sent = named ? sendto(sender, input->payload, 4, 0,
                                      (struct sockaddr*)&input->address, input->length)
                             : send(sender, input->payload, 4, 0);
        struct result value = {.sent = sent,
                               .error = errno,
                               .uid = getuid(),
                               .euid = geteuid(),
                               .gid = getgid(),
                               .egid = getegid(),
                               .groups = getgroups(0, NULL)};
        CHECK(write(result[1], &value, sizeof(value)) == sizeof(value));
        _exit(0);
    }
    CHECK(!close(ready[1]) && !close(result[1]));
    readable(ready[0]);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && byte == 'R');
    sleeping(child);
    struct pollfd pending = {.fd = result[0], .events = POLLIN};
    CHECK(!poll(&pending, 1, 0) && !close(ready[0]));
    return (struct held){child, result[0]};
}

static struct result finish(struct held held) {
    readable(held.result);
    struct result result;
    CHECK(read(held.result, &result, sizeof(result)) == sizeof(result) && !close(held.result));
    int status;
    CHECK(waitpid(held.child, &status, 0) == held.child && WIFEXITED(status) &&
          !WEXITSTATUS(status));
    return result;
}

static void drain_empty(int fd, unsigned count) {
    char byte;
    for (unsigned n = 0; n < count; n++)
        CHECK(!recv(fd, &byte, 1, MSG_DONTWAIT));
}

static void held_receiver(unsigned mode) {
    char directory[] = "/tmp/axiom-wait-XXXXXX", path[108];
    if (mode == 2) {
        CHECK(mkdtemp(directory));
        CHECK(snprintf(path, sizeof(path), "%s/peer", directory) > 0);
    }
    struct named sender = endpoint('s', NULL), receiver = endpoint('r', mode == 2 ? path : NULL),
                 alternate = endpoint('t', NULL);
    int connected = mode == 1 || mode == 4;
    if (connected)
        connect_to(sender.fd, &receiver);
    unsigned count = 0;
    while (!sendto(sender.fd, "", 0, MSG_DONTWAIT, (struct sockaddr*)&receiver.address,
                   receiver.length))
        CHECK(++count < 1000);
    CHECK(errno == EAGAIN && count == 11);
    struct input* input =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(input != MAP_FAILED);
    input->address = receiver.address;
    input->length = receiver.length;
    memcpy(input->payload, "held", 4);
    int receivers[] = {receiver.fd, alternate.fd};
    struct held held = start(sender.fd, receivers, 2, input, !connected, 0);
    input->address = alternate.address;
    input->length = alternate.length;
    memcpy(input->payload, "late", 4);
    int replacement = -1;
    if (mode == 0 || mode == 1) {
        if (mode == 1)
            connect_to(sender.fd, &alternate);
        drain_empty(receiver.fd, 1);
    } else if (mode == 2) {
        CHECK(!unlink(path));
        struct named next = endpoint('n', path);
        replacement = next.fd;
        CHECK(!close(receiver.fd));
        receiver.fd = -1;
    } else if (mode == 3) {
        CHECK(!shutdown(receiver.fd, SHUT_RD));
        // Linux need not wake a peer-queue waiter on shutdown alone.
        drain_empty(receiver.fd, 1);
    } else {
        CHECK(!close(receiver.fd));
        receiver.fd = -1;
    }
    struct result result = finish(held);
    if (mode < 3) {
        CHECK(result.sent == 4 && !result.error);
        int destination = mode == 2 ? replacement : receiver.fd;
        if (mode != 2)
            drain_empty(destination, 10);
        char bytes[8];
        CHECK(recv(destination, bytes, sizeof(bytes), MSG_DONTWAIT) == 4 &&
              !memcmp(bytes, "held", 4));
        CHECK(recv(alternate.fd, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 && errno == EAGAIN);
        if (mode == 1) {
            CHECK(send(sender.fd, "new", 3, MSG_DONTWAIT) == 3);
            CHECK(recv(alternate.fd, bytes, sizeof(bytes), MSG_DONTWAIT) == 3 &&
                  !memcmp(bytes, "new", 3));
        }
    } else {
        CHECK(result.sent == -1 && result.error == (mode == 3 ? EPIPE : ECONNREFUSED));
        if (mode == 3)
            drain_empty(receiver.fd, 10);
        else
            CHECK(send(sender.fd, "none", 4, MSG_DONTWAIT) == -1 && errno == ENOTCONN);
    }
    CHECK(!munmap(input, 4096) && !close(sender.fd) && !close(alternate.fd));
    if (receiver.fd >= 0)
        CHECK(!close(receiver.fd));
    if (replacement >= 0)
        CHECK(!close(replacement) && !unlink(path) && !rmdir(directory));
    printf(
        "UNIX_ROUTING_WAIT_RECEIVER_PASS mode=%u actual_sleep copied_input destination_lifetime\n",
        mode);
}

static void budget_wait(int permissions) {
    int pair[2];
    CHECK(!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, pair));
    int size = 0;
    CHECK(!setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)));
    char fill[4000];
    memset(fill, 'F', sizeof(fill));
    unsigned count = 0;
    while (send(pair[0], fill, sizeof(fill), MSG_DONTWAIT) == sizeof(fill))
        CHECK(++count < 1000);
    CHECK(count && errno == EAGAIN);
    char directory[] = "/tmp/axiom-wait-perm-XXXXXX", path[108];
    CHECK(mkdtemp(directory));
    CHECK(snprintf(path, sizeof(path), "%s/peer", directory) > 0);
    struct named receiver = endpoint('p', path);
    CHECK(!chmod(path, 0));
    struct input* input =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(input != MAP_FAILED);
    input->address = receiver.address;
    input->length = receiver.length;
    memcpy(input->payload, "held", 4);
    int receivers[] = {pair[1], receiver.fd};
    struct held held = start(pair[0], receivers, 2, input, permissions, permissions);
    if (permissions) {
        for (unsigned n = 0; n < count; n++)
            CHECK(recv(pair[1], fill, sizeof(fill), MSG_DONTWAIT) == sizeof(fill));
    } else
        CHECK(!shutdown(pair[0], SHUT_WR));
    struct result result = finish(held);
    CHECK(result.sent == -1 && result.error == (permissions ? EACCES : EPIPE));
    if (permissions)
        CHECK(result.uid == 65534 && result.euid == 65534 && result.gid == 65534 &&
              result.egid == 65534 && !result.groups);
    else
        for (unsigned n = 0; n < count; n++)
            CHECK(recv(pair[1], fill, sizeof(fill), MSG_DONTWAIT) == sizeof(fill));
    char byte;
    CHECK(recv(receiver.fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    CHECK(!close(pair[0]) && !close(pair[1]) && !close(receiver.fd));
    CHECK(!chmod(path, 0600) && !unlink(path) && !rmdir(directory) && !munmap(input, 4096));
    printf("UNIX_ROUTING_WAIT_BUDGET_PASS permissions=%d actual_sleep terminal_state "
           "caller_credentials\n",
           permissions);
}

int main(int argc, char** argv) {
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")));
    if (argc == 2) {
        CHECK(!geteuid() && !setgroups(0, NULL));
        CHECK(!setresgid(65534, 65534, 65534) && !setresuid(65534, 65534, 65534));
    }
    printf("UNIX_ROUTING_WAIT_IDENTITY uid=%u euid=%u gid=%u egid=%u groups=%d\n", getuid(),
           geteuid(), getgid(), getegid(), getgroups(0, NULL));
    for (unsigned mode = 0; mode != 5; mode++)
        held_receiver(mode);
    budget_wait(0);
    budget_wait(1);
    puts("UNIX_ROUTING_WAIT_PASS groups=7");
}
