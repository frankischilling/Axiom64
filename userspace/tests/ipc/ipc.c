// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "IPC_FAIL line=%d: %s errno=%d (%s)\n", __LINE__, #expr, errno,        \
                    strerror(errno));                                                              \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
static void reap(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static volatile sig_atomic_t terminal_signals;
static void terminal_handler(int signal) {
    terminal_signals |= signal == SIGINT ? 1 : 2;
}
int main(void) {
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    CHECK(fcntl(pair[0], F_GETFD) == FD_CLOEXEC);
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(pair[0], &readset);
    struct timeval zero_timeout = {0, 0};
    CHECK(select(pair[0] + 1, &readset, 0, 0, &zero_timeout) == 0 && !FD_ISSET(pair[0], &readset));
    FD_SET(pair[0], &readset);
    struct timespec zero_timespec = {0, 0};
    sigset_t select_mask;
    sigemptyset(&select_mask);
    CHECK(pselect(pair[0] + 1, &readset, 0, 0, &zero_timespec, &select_mask) == 0 &&
          !FD_ISSET(pair[0], &readset));
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLET, .data.u64 = 0x12345678};
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, pair[0], &event) == 0);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    CHECK(write(pair[1], "socket", 6) == 6);
    FD_ZERO(&readset);
    FD_SET(pair[0], &readset);
    zero_timeout = (struct timeval){0, 0};
    CHECK(select(pair[0] + 1, &readset, 0, 0, &zero_timeout) == 1 && FD_ISSET(pair[0], &readset));
    struct epoll_event batch[256];
    CHECK(epoll_wait(epoll, batch, 256, 100) == 1 && batch[0].data.u64 == 0x12345678 &&
          (batch[0].events & EPOLLIN));
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    CHECK(read(pair[0], (char[6]){0}, 6) == 6);
    CHECK(write(pair[1], "socket", 6) == 6);
    CHECK(epoll_wait(epoll, &event, 1, 100) == 1 && event.data.u64 == 0x12345678 &&
          (event.events & EPOLLIN));
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    char data[64] = {0};
    CHECK(recv(pair[0], data, 6, MSG_PEEK) == 6 && !strcmp(data, "socket"));
    CHECK(read(pair[0], data, 6) == 6);
    CHECK(write(pair[1], "new", 3) == 3);
    CHECK(epoll_wait(epoll, &event, 1, 100) == 1);
    CHECK(read(pair[0], data, 3) == 3);
    event.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    event.data.u64 = 0x12345678;
    CHECK(epoll_ctl(epoll, EPOLL_CTL_MOD, pair[0], &event) == 0);
    CHECK(write(pair[1], "one", 3) == 3);
    CHECK(epoll_wait(epoll, &event, 1, 100) == 1);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    CHECK(read(pair[0], data, 3) == 3);
    CHECK(write(pair[1], "two", 3) == 3);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    event.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    CHECK(epoll_ctl(epoll, EPOLL_CTL_MOD, pair[0], &event) == 0);
    CHECK(epoll_wait(epoll, &event, 1, 100) == 1);
    CHECK(read(pair[0], data, 3) == 3);
    CHECK(shutdown(pair[1], SHUT_WR) == 0);
    struct pollfd p = {pair[0], POLLIN, 0};
    CHECK(poll(&p, 1, 100) == 1);
    CHECK(read(pair[0], data, 1) == 0);
    close(pair[0]);
    close(pair[1]);
    close(epoll);

    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(server >= 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, "/tmp/ipc-socket");
    CHECK(bind(server, (struct sockaddr*)&address, sizeof(address)) == 0);
    CHECK(listen(server, 8) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(server);
        int client = socket(AF_UNIX, SOCK_STREAM, 0);
        CHECK(client >= 0);
        CHECK(connect(client, (struct sockaddr*)&address, sizeof(address)) == 0);
        CHECK(write(client, "request", 7) == 7);
        CHECK(read(client, data, 5) == 5 && !memcmp(data, "reply", 5));
        close(client);
        _exit(0);
    }
    int client = accept4(server, 0, 0, SOCK_CLOEXEC);
    CHECK(client >= 0);
    CHECK(read(client, data, 7) == 7 && !memcmp(data, "request", 7));
    CHECK(write(client, "reply", 5) == 5);
    close(client);
    close(server);
    reap(child);
    CHECK(unlink(address.sun_path) == 0);

    int* shared = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(shared != MAP_FAILED);
    *shared = 1;
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        *shared = 42;
        _exit(0);
    }
    reap(child);
    CHECK(*shared == 42);
    CHECK(munmap(shared, 4096) == 0);
    int segment = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    CHECK(segment >= 0);
    shared = shmat(segment, 0, 0);
    CHECK(shared != (void*)-1);
    *shared = 7;
    struct shmid_ds info;
    CHECK(shmctl(segment, IPC_STAT, &info) == 0 && info.shm_segsz == 4096 && info.shm_nattch == 1);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        *shared = 99;
        CHECK(shmdt(shared) == 0);
        _exit(0);
    }
    reap(child);
    CHECK(*shared == 99);
    CHECK(shmctl(segment, IPC_RMID, 0) == 0);
    CHECK(shmdt(shared) == 0);
    CHECK(shmat(segment, 0, 0) == (void*)-1 && errno == EINVAL);

    int file = open("/tmp/shared-file", O_CREAT | O_TRUNC | O_RDWR, 0600);
    CHECK(file >= 0);
    CHECK(ftruncate(file, 4096) == 0);
    char* mapped = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
    CHECK(mapped != MAP_FAILED);
    memcpy(mapped, "mapped", 6);
    CHECK(pread(file, data, 6, 0) == 6 && !memcmp(data, "mapped", 6));
    CHECK(pwrite(file, "FILE", 4, 0) == 4 && !memcmp(mapped, "FILE", 4));
    CHECK(msync(mapped, 4096, MS_SYNC) == 0);
    CHECK(munmap(mapped, 4096) == 0);
    close(file);
    unlink("/tmp/shared-file");

    int master = posix_openpt(O_RDWR | O_NOCTTY);
    CHECK(master >= 0);
    unsigned pty_id;
    CHECK(syscall(SYS_ioctl, master, (long)(int32_t)0x80045430, &pty_id) == 0);
    CHECK(grantpt(master) == 0 && unlockpt(master) == 0);
    char* slave_name = ptsname(master);
    CHECK(slave_name != 0);
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    CHECK(slave >= 0);
    struct termios term;
    CHECK(tcgetattr(slave, &term) == 0);
    cfmakeraw(&term);
    CHECK(tcsetattr(slave, TCSANOW, &term) == 0);
    CHECK(write(master, "pty-input", 9) == 9);
    CHECK(read(slave, data, 9) == 9 && !memcmp(data, "pty-input", 9));
    CHECK(write(slave, "pty-output", 10) == 10);
    CHECK(read(master, data, 10) == 10 && !memcmp(data, "pty-output", 10));
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(master);
        CHECK(setsid() == getpid());
        CHECK(ioctl(slave, TIOCSCTTY, 0) == 0);
        int tty = open("/dev/tty", O_RDWR);
        CHECK(tty >= 0 && tcgetpgrp(tty) == getpgrp());
        CHECK(tcgetattr(tty, &term) == 0 && !(term.c_lflag & ICANON));
        term.c_lflag |= ISIG;
        term.c_cc[VINTR] = 3;
        CHECK(tcsetattr(tty, TCSANOW, &term) == 0);
        struct sigaction action = {.sa_handler = terminal_handler};
        CHECK(sigaction(SIGINT, &action, 0) == 0 && sigaction(SIGWINCH, &action, 0) == 0);
        sigset_t mask, empty;
        sigemptyset(&mask);
        sigemptyset(&empty);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGWINCH);
        CHECK(sigprocmask(SIG_BLOCK, &mask, 0) == 0);
        CHECK(write(tty, "ready", 5) == 5);
        while (terminal_signals != 3)
            sigsuspend(&empty);
        close(tty);
        close(slave);
        _exit(0);
    }
    CHECK(read(master, data, 5) == 5 && !memcmp(data, "ready", 5));
    struct winsize size = {.ws_row = 40, .ws_col = 100};
    CHECK(ioctl(slave, TIOCSWINSZ, &size) == 0);
    CHECK(write(master, "\003", 1) == 1);
    reap(child);
    close(master);
    close(slave);
    puts("IPC_TESTS_PASS");
    return 0;
}
