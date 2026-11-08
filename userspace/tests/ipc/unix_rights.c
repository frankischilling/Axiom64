// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "UNIX_RIGHTS_FAIL line=%d expression=%s errno=%d\n", __LINE__, #value, \
                    errno);                                                                        \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

union control {
    struct cmsghdr aligned;
    unsigned char bytes[2048];
};

static void pair(int sockets[2]) {
    CHECK(!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets));
}

static void pipe_pair(int files[2]) {
    CHECK(!pipe2(files, O_NONBLOCK | O_CLOEXEC));
}

static ssize_t send_files(int fd, const int* files, unsigned count, unsigned tail) {
    CHECK(count <= 254 && tail <= 3);
    union control control = {0};
    char byte = 'R';
    struct iovec vector = {&byte, 1};
    struct msghdr message = {.msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control.bytes,
                             .msg_controllen = CMSG_SPACE(count * sizeof(int) + tail)};
    struct cmsghdr* field = CMSG_FIRSTHDR(&message);
    field->cmsg_level = SOL_SOCKET;
    field->cmsg_type = SCM_RIGHTS;
    field->cmsg_len = CMSG_LEN(count * sizeof(int) + tail);
    memcpy(CMSG_DATA(field), files, count * sizeof(int));
    return sendmsg(fd, &message, MSG_DONTWAIT);
}

static unsigned receive_files(int fd, size_t capacity, unsigned flags, int* files, size_t* used,
                              unsigned* returned) {
    union control control;
    memset(&control, 0xa5, sizeof(control));
    CHECK(capacity <= sizeof(control));
    char byte = 0;
    struct iovec vector = {&byte, 1};
    struct msghdr message = {.msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control.bytes,
                             .msg_controllen = capacity};
    CHECK(recvmsg(fd, &message, flags) == 1 && byte == 'R');
    unsigned count = 0;
    for (struct cmsghdr* field = CMSG_FIRSTHDR(&message); field;
         field = CMSG_NXTHDR(&message, field)) {
        CHECK(field->cmsg_level == SOL_SOCKET && field->cmsg_type == SCM_RIGHTS &&
              field->cmsg_len >= CMSG_LEN(0));
        size_t bytes = field->cmsg_len - CMSG_LEN(0);
        CHECK(bytes % sizeof(int) == 0 && count + bytes / sizeof(int) <= 253);
        memcpy(files + count, CMSG_DATA(field), bytes);
        count += bytes / sizeof(int);
    }
    *used = message.msg_controllen;
    *returned = message.msg_flags;
    return count;
}

static void release_files(int* files, unsigned count, int cloexec) {
    for (unsigned index = 0; index < count; index++) {
        CHECK(fcntl(files[index], F_GETFD) == (cloexec ? FD_CLOEXEC : 0));
        CHECK(!close(files[index]));
    }
}

static void empty(int fd) {
    char byte;
    CHECK(recv(fd, &byte, 1, 0) == -1 && errno == EAGAIN);
}

static void eof(int fd) {
    struct pollfd event = {.fd = fd, .events = POLLIN | POLLHUP};
    CHECK(poll(&event, 1, 3000) == 1 && (event.revents & POLLHUP));
    char byte;
    CHECK(read(fd, &byte, 1) == 0);
}

static void alive(int fd) {
    char byte;
    CHECK(read(fd, &byte, 1) == -1 && errno == EAGAIN);
}

static void collect(void) {
    int sockets[2];
    pair(sockets);
    CHECK(!close(sockets[0]) && !close(sockets[1]));
}

static void capacities(void) {
    for (unsigned capacity = 0; capacity <= 33; capacity++) {
        int sockets[2], pipefd[2];
        pair(sockets);
        pipe_pair(pipefd);
        int outgoing[] = {pipefd[1], pipefd[1]};
        CHECK(send_files(sockets[0], outgoing, 2, 0) == 1 && !close(pipefd[1]));
        int files[253];
        size_t used;
        unsigned flags;
        unsigned count =
            receive_files(sockets[1], capacity, MSG_CMSG_CLOEXEC, files, &used, &flags);
        unsigned expected = capacity < CMSG_LEN(sizeof(int))       ? 0
                            : capacity < CMSG_LEN(2 * sizeof(int)) ? 1
                                                                   : 2;
        CHECK(count == expected);
        CHECK(flags == (MSG_CMSG_CLOEXEC | (count < 2 ? MSG_CTRUNC : 0)));
        CHECK(used == (count ? (capacity < CMSG_SPACE(count * sizeof(int))
                                    ? capacity
                                    : CMSG_SPACE(count * sizeof(int)))
                             : 0));
        release_files(files, count, 1);
        eof(pipefd[0]);
        CHECK(!close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
    }
    puts("UNIX_RIGHTS_CAPACITIES_PASS capacities=34 exact_flags discarded_duplicates");
}

static void rollback_and_maximum(void) {
    int sockets[2], pipefd[2];
    pair(sockets);
    pipe_pair(pipefd);
    union control control = {0};
    struct iovec vector = {(void*)"R", 1};
    struct msghdr message = {.msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control.bytes,
                             .msg_controllen = 2 * CMSG_SPACE(sizeof(int))};
    struct cmsghdr* first = CMSG_FIRSTHDR(&message);
    first->cmsg_level = SOL_SOCKET;
    first->cmsg_type = SCM_RIGHTS;
    first->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(first), &pipefd[1], sizeof(int));
    struct cmsghdr* second = CMSG_NXTHDR(&message, first);
    CHECK(second);
    second->cmsg_level = SOL_SOCKET;
    second->cmsg_type = SCM_RIGHTS;
    second->cmsg_len = CMSG_LEN(sizeof(int));
    int bad = -1;
    memcpy(CMSG_DATA(second), &bad, sizeof(bad));
    CHECK(sendmsg(sockets[0], &message, 0) == -1 && errno == EBADF);
    empty(sockets[1]);
    int many[254];
    for (unsigned n = 0; n < 254; n++)
        many[n] = pipefd[1];
    CHECK(send_files(sockets[0], many, 254, 0) == -1 && errno == EINVAL);
    empty(sockets[1]);
    CHECK(!close(pipefd[1]));
    eof(pipefd[0]);
    CHECK(!close(pipefd[0]));
    for (unsigned tail = 0; tail <= 3; tail++) {
        pipe_pair(pipefd);
        CHECK(send_files(sockets[0], &pipefd[1], 1, tail) == 1 && !close(pipefd[1]));
        int files[253];
        size_t used;
        unsigned flags;
        CHECK(receive_files(sockets[1], 64, 0, files, &used, &flags) == 1 &&
              used == CMSG_SPACE(sizeof(int)) && !flags);
        release_files(files, 1, 0);
        eof(pipefd[0]);
        CHECK(!close(pipefd[0]));
    }
    pipe_pair(pipefd);
    for (unsigned n = 0; n < 253; n++)
        many[n] = pipefd[1];
    CHECK(send_files(sockets[0], many, 253, 0) == 1 && !close(pipefd[1]));
    struct rlimit previous, limited;
    CHECK(!getrlimit(RLIMIT_NOFILE, &previous));
    limited = previous;
    limited.rlim_cur = 16;
    unsigned occupied = 0;
    for (int fd = 0; fd < 16; fd++)
        if (fcntl(fd, F_GETFD) >= 0)
            occupied++;
    CHECK(!setrlimit(RLIMIT_NOFILE, &limited));
    int files[253];
    size_t used;
    unsigned flags;
    unsigned count = receive_files(sockets[1], sizeof(control), 0, files, &used, &flags);
    CHECK(!setrlimit(RLIMIT_NOFILE, &previous));
    CHECK(count == 16 - occupied && flags == MSG_CTRUNC);
    release_files(files, count, 0);
    eof(pipefd[0]);
    CHECK(!close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
    puts("UNIX_RIGHTS_ROLLBACK_PASS bad_late_fd maximum=253 tails receiver_limit");
}

static void copy_faults(void) {
    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    unsigned char* memory =
        mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(memory != MAP_FAILED && !mprotect(memory, page, PROT_NONE));
    int sockets[2], pipefd[2];
    pair(sockets);
    pipe_pair(pipefd);
    CHECK(send_files(sockets[0], &pipefd[1], 1, 0) == 1 && !close(pipefd[1]));
    char byte;
    struct iovec vector = {&byte, 1};
    struct msghdr message = {
        .msg_iov = &vector, .msg_iovlen = 1, .msg_control = memory, .msg_controllen = 32};
    CHECK(recvmsg(sockets[1], &message, MSG_PEEK) == 1 && byte == 'R' &&
          message.msg_controllen == 0 && message.msg_flags == MSG_CTRUNC);
    alive(pipefd[0]);
    message.msg_controllen = 32;
    CHECK(recvmsg(sockets[1], &message, 0) == 1 && message.msg_controllen == 0 &&
          message.msg_flags == MSG_CTRUNC);
    eof(pipefd[0]);
    CHECK(!close(pipefd[0]));
    pipe_pair(pipefd);
    CHECK(send_files(sockets[0], &pipefd[1], 1, 0) == 1 && !close(pipefd[1]));
    vector.iov_base = memory;
    message.msg_control = NULL;
    message.msg_controllen = 0;
    CHECK(recvmsg(sockets[1], &message, MSG_PEEK) == -1 && errno == EFAULT);
    alive(pipefd[0]);
    CHECK(recvmsg(sockets[1], &message, 0) == -1 && errno == EFAULT);
    eof(pipefd[0]);
    CHECK(!close(pipefd[0]));
    pipe_pair(pipefd);
    CHECK(send_files(sockets[0], &pipefd[1], 1, 0) == 1 && !close(pipefd[1]));
    vector.iov_base = &byte;
    message.msg_control = memory + page - 16;
    message.msg_controllen = 32;
    CHECK(recvmsg(sockets[1], &message, MSG_CMSG_CLOEXEC) == 1 && byte == 'R' &&
          message.msg_controllen == 0 && message.msg_flags == MSG_CMSG_CLOEXEC);
    int installed;
    memcpy(&installed, memory + page, sizeof(installed));
    CHECK(fcntl(installed, F_GETFD) == FD_CLOEXEC && !close(installed));
    eof(pipefd[0]);
    CHECK(!close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]) &&
          !munmap(memory, 2 * page));
    puts("UNIX_RIGHTS_FAULTS_PASS peek_retains consuming_fault_releases "
         "header_fault_keeps_installed_fd");
}

static void cycles(void) {
    for (unsigned n = 0; n < 160; n++) {
        int sockets[2], pipefd[2];
        pair(sockets);
        pipe_pair(pipefd);
        int files[] = {sockets[1], pipefd[1]};
        CHECK(send_files(sockets[0], files, 2, 0) == 1);
        int alias = dup(sockets[1]);
        CHECK(alias >= 0);
        CHECK(!close(pipefd[1]) && !close(sockets[0]) && !close(sockets[1]));
        collect();
        alive(pipefd[0]);
        CHECK(!close(alias));
        collect();
        eof(pipefd[0]);
        CHECK(!close(pipefd[0]));
    }
    int left[2], right[2], pipefd[2];
    pair(left);
    pair(right);
    pipe_pair(pipefd);
    CHECK(send_files(left[0], &right[1], 1, 0) == 1);
    int files[] = {left[1], pipefd[1]};
    CHECK(send_files(right[0], files, 2, 0) == 1);
    CHECK(!close(pipefd[1]) && !close(left[0]) && !close(right[0]) && !close(left[1]));
    collect();
    alive(pipefd[0]);
    CHECK(!close(right[1]));
    collect();
    eof(pipefd[0]);
    CHECK(!close(pipefd[0]));
    puts("UNIX_RIGHTS_CYCLES_PASS self_cycles=160 rooted_alias two_socket_cycle "
         "requested_collection terminal_pipe_eof");
}

static void quota_child(void) {
    if (!geteuid()) {
        CHECK(!setgroups(0, NULL));
        CHECK(!setresgid(65534, 65534, 65534) && !setresuid(65534, 65534, 65534));
    }
    CHECK(getuid() == 65534 && geteuid() == 65534 && getgid() == 65534 && getegid() == 65534 &&
          !getgroups(0, NULL));
    int sockets[2], pipefd[2];
    pair(sockets);
    pipe_pair(pipefd);
    struct rlimit previous, limited;
    CHECK(!getrlimit(RLIMIT_NOFILE, &previous));
    limited = previous;
    limited.rlim_cur = 16;
    CHECK(!setrlimit(RLIMIT_NOFILE, &limited));
    for (unsigned n = 0; n < 17; n++)
        CHECK(send_files(sockets[0], &pipefd[1], 1, 0) == 1);
    CHECK(send_files(sockets[0], &pipefd[1], 1, 0) == -1 && errno == ETOOMANYREFS);
    int files[253];
    size_t used;
    unsigned flags;
    CHECK(receive_files(sockets[1], 64, MSG_PEEK, files, &used, &flags) == 1 && !flags);
    release_files(files, 1, 0);
    CHECK(send_files(sockets[0], &pipefd[1], 1, 0) == -1 && errno == ETOOMANYREFS);
    CHECK(receive_files(sockets[1], 64, 0, files, &used, &flags) == 1 && !flags);
    release_files(files, 1, 0);
    CHECK(send_files(sockets[0], &pipefd[1], 1, 0) == 1);
    CHECK(send_files(sockets[0], &pipefd[1], 1, 0) == -1 && errno == ETOOMANYREFS);
    CHECK(!close(pipefd[1]) && !close(sockets[0]) && !close(sockets[1]));
    eof(pipefd[0]);
    CHECK(!close(pipefd[0]));
    puts("UNIX_RIGHTS_QUOTA_IDENTITY uid=65534 euid=65534 gid=65534 egid=65534 groups=0 limit=16");
    CHECK(!fflush(stdout));
    _exit(0);
}

static void quota(void) {
    CHECK(!fflush(stdout));
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child)
        quota_child();
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    puts("UNIX_RIGHTS_QUOTA_PASS real_user_inflight strict_limit peek_stays_charged "
         "consume_releases");
}

struct held_input {
    union control control;
    char byte;
    int sender, ready, result;
};

struct held_result {
    ssize_t sent;
    int error;
};

static void interrupted(int signal) {
    CHECK(signal == SIGUSR1);
}

static int held_worker(void* opaque) {
    struct held_input* input = opaque;
    struct sigaction action = {.sa_handler = interrupted};
    CHECK(!sigemptyset(&action.sa_mask) && !sigaction(SIGUSR1, &action, NULL));
    struct iovec vector = {&input->byte, 1};
    struct msghdr message = {.msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = input->control.bytes,
                             .msg_controllen = CMSG_SPACE(sizeof(int))};
    CHECK(write(input->ready, "B", 1) == 1);
    errno = 0;
    struct held_result result = {.sent = sendmsg(input->sender, &message, 0)};
    result.error = errno;
    CHECK(write(input->result, &result, sizeof(result)) == sizeof(result));
    _exit(0);
}

static void readable(int fd) {
    struct pollfd event = {.fd = fd, .events = POLLIN};
    CHECK(poll(&event, 1, 3000) == 1 && (event.revents & POLLIN));
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

static void held_descriptions(unsigned mode) {
    int sockets[2], original[2], replacement[2], ready[2], result[2];
    for (unsigned n = 0; n < 2; n++) {
        sockets[n] = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        CHECK(sockets[n] >= 0);
    }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int count = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                         "ax-rights-held-%ld-%u", (long)getpid(), mode);
    CHECK(count > 0 && count < 100);
    socklen_t length = offsetof(struct sockaddr_un, sun_path) + count + 1;
    CHECK(!bind(sockets[1], (struct sockaddr*)&address, length) &&
          !connect(sockets[0], (struct sockaddr*)&address, length));
    unsigned queued = 0;
    while (!send(sockets[0], "", 0, MSG_DONTWAIT))
        CHECK(++queued < 1000);
    CHECK(errno == EAGAIN && queued == 11);
    CHECK(!fcntl(sockets[0], F_SETFL, fcntl(sockets[0], F_GETFL) & ~O_NONBLOCK));
    struct timeval timeout = {.tv_sec = mode == 3 ? 1 : 5};
    CHECK(!setsockopt(sockets[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));
    pipe_pair(original);
    pipe_pair(replacement);
    pipe_pair(ready);
    pipe_pair(result);
    struct held_input* input =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(input != MAP_FAILED);
    input->byte = 'R';
    input->sender = sockets[0];
    input->ready = ready[1];
    input->result = result[1];
    struct cmsghdr* field = (struct cmsghdr*)input->control.bytes;
    field->cmsg_level = SOL_SOCKET;
    field->cmsg_type = SCM_RIGHTS;
    field->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(field), &original[1], sizeof(int));
    void* stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(stack != MAP_FAILED && !fflush(stdout));
    pid_t child = clone(held_worker, (char*)stack + 65536, CLONE_FILES | SIGCHLD, input);
    CHECK(child >= 0);
    readable(ready[0]);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && byte == 'B');
    sleeping(child);
    struct pollfd pending = {.fd = result[0], .events = POLLIN};
    CHECK(!poll(&pending, 1, 0));
    // Both tasks share the descriptor table. Replace the captured descriptor
    // number, then corrupt the shared original control and payload buffers.
    CHECK(dup2(replacement[1], original[1]) == original[1]);
    CHECK(!close(replacement[1]) && !close(original[1]));
    input->byte = 'L';
    int bad = -1;
    memcpy(CMSG_DATA(field), &bad, sizeof(bad));
    collect();
    alive(original[0]);
    eof(replacement[0]);
    if (!mode)
        CHECK(!recv(sockets[1], &byte, 1, MSG_DONTWAIT));
    else if (mode == 1)
        CHECK(!close(sockets[1]));
    else if (mode == 2)
        CHECK(!kill(child, SIGUSR1));
    readable(result[0]);
    struct held_result observed;
    CHECK(read(result[0], &observed, sizeof(observed)) == sizeof(observed));
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    if (!mode) {
        CHECK(observed.sent == 1 && !observed.error);
        for (unsigned n = 1; n < queued; n++)
            CHECK(!recv(sockets[1], &byte, 1, MSG_DONTWAIT));
        int files[253];
        size_t used;
        unsigned flags;
        CHECK(receive_files(sockets[1], 64, 0, files, &used, &flags) == 1 && !flags);
        CHECK(write(files[0], "K", 1) == 1 && read(original[0], &byte, 1) == 1 && byte == 'K');
        release_files(files, 1, 0);
    } else {
        CHECK(observed.sent == -1 && observed.error == (mode == 1   ? ECONNREFUSED
                                                        : mode == 2 ? EINTR
                                                                    : EAGAIN));
    }
    eof(original[0]);
    CHECK(!close(original[0]) && !close(replacement[0]) && !close(sockets[0]));
    if (mode != 1)
        CHECK(!close(sockets[1]));
    CHECK(!close(ready[0]) && !close(ready[1]) && !close(result[0]) && !close(result[1]) &&
          !munmap(input, 4096) && !munmap(stack, 65536));
}

static void held(void) {
    for (unsigned mode = 0; mode < 4; mode++)
        held_descriptions(mode);
    puts("UNIX_RIGHTS_HELD_PASS shared_fd_reuse copied_control copied_payload pending_root "
         "success peer_close signal timeout terminal_pipe_eof");
}

static int chain_endpoint(unsigned index) {
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int count = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                         "ax-rights-chain-%ld-%u", (long)getpid(), index);
    CHECK(count > 0 && count < 100);
    socklen_t length = offsetof(struct sockaddr_un, sun_path) + count + 1;
    CHECK(!bind(fd, (struct sockaddr*)&address, length));
    return fd;
}

static void chain_send(int sender, int receiver, int file) {
    struct sockaddr_un address;
    socklen_t length = sizeof(address);
    CHECK(!getsockname(receiver, (struct sockaddr*)&address, &length) &&
          !connect(sender, (struct sockaddr*)&address, length));
    CHECK(send_files(sender, &file, 1, 0) == 1);
}

static void chain(void) {
    struct rlimit previous, limited;
    CHECK(!getrlimit(RLIMIT_NOFILE, &previous));
    limited = previous;
    if (limited.rlim_cur > 128)
        limited.rlim_cur = 128;
    CHECK(limited.rlim_cur >= 64 && !setrlimit(RLIMIT_NOFILE, &limited));
    // Inflight references use the real user's limit even though the process
    // keeps only a few descriptor numbers open while building the chain.
    unsigned endpoints = geteuid() ? limited.rlim_cur : 240;
    int sender = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(sender >= 0);
    int pipefd[2];
    pipe_pair(pipefd);
    int first = chain_endpoint(0), current = first;
    for (unsigned index = 1; index < endpoints; index++) {
        int next = chain_endpoint(index);
        chain_send(sender, current, next);
        if (current != first)
            CHECK(!close(current));
        current = next;
    }
    chain_send(sender, current, pipefd[1]);
    CHECK(!close(current) && !close(pipefd[1]) && !close(sender));
    collect();
    alive(pipefd[0]);
    CHECK(!close(first));
    collect();
    eof(pipefd[0]);
    CHECK(!close(pipefd[0]));
    CHECK(!setrlimit(RLIMIT_NOFILE, &previous));
    printf("UNIX_RIGHTS_CHAIN_PASS endpoints=%u limit=%lu constant_descriptor_table "
           "rooted_then_released terminal_pipe_eof\n",
           endpoints, (unsigned long)limited.rlim_cur);
}

int main(int argc, char** argv) {
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")));
    if (argc == 2) {
        CHECK(!geteuid() && !setgroups(0, NULL));
        CHECK(!setresgid(65534, 65534, 65534) && !setresuid(65534, 65534, 65534));
    }
    printf("UNIX_RIGHTS_IDENTITY uid=%u euid=%u gid=%u egid=%u groups=%d\n", getuid(), geteuid(),
           getgid(), getegid(), getgroups(0, NULL));
    capacities();
    rollback_and_maximum();
    copy_faults();
    cycles();
    quota();
    held();
    chain();
    puts("UNIX_RIGHTS_PASS groups=7");
}
