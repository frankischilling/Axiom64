// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <mqueue.h>
#include <poll.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void check(int ok, const char* message) {
    if (!ok) {
        fprintf(stderr, "POSIX_MQ_FAIL %s errno=%d\n", message, errno);
        _exit(1);
    }
}

#define fails(call, error) check((call) == -1 && errno == (error), #call)

static void ordinary(void) {
    check(!setgroups(0, NULL) && !setgid(65534) && !setuid(65534), "ordinary credentials");
}

static void wait_ok(pid_t child) {
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child completed its queue operation");
}

static void wait_sleeping(pid_t child) {
    char path[64], status[1024];
    check(snprintf(path, sizeof(path), "/proc/%d/status", (int)child) > 0, "proc path");
    for (unsigned attempt = 0; attempt < 200; ++attempt) {
        int fd = open(path, O_RDONLY);
        check(fd >= 0, "open child status");
        ssize_t bytes = read(fd, status, sizeof(status) - 1);
        check(bytes > 0 && !close(fd), "read child status");
        status[bytes] = 0;
        if (strstr(status, "\nState:\tS"))
            return;
        check(!strstr(status, "\nState:\tZ"), "waiter remains live");
        check(!nanosleep(&(struct timespec){.tv_nsec = 5000000}, NULL), "waiter observation");
    }
    check(0, "child reached queue wait");
}

static void name_for(char name[64], const char* test) {
    int length = snprintf(name, 64, "/axiom-mq-%u-%s", (unsigned)getpid(), test);
    check(length > 0 && length < 64, "message queue name fits");
}

static mqd_t create_queue(char name[64], const char* test, int flags, long count) {
    name_for(name, test);
    struct mq_attr limits = {.mq_maxmsg = count, .mq_msgsize = 8};
    mqd_t queue = mq_open(name, O_CREAT | O_EXCL | O_RDWR | flags, 0600, &limits);
    check(queue != (mqd_t)-1, "create named queue");
    return queue;
}

static void receive(mqd_t queue, const char* value, unsigned expected_priority) {
    char text[8];
    unsigned priority;
    size_t length = strlen(value);
    check(mq_receive(queue, text, sizeof(text), &priority) == (ssize_t)length &&
              priority == expected_priority && !memcmp(text, value, length),
          "priority and payload");
}

static void priority_and_names(void) {
    char name[64], path[96], text[128] = {0};
    mqd_t queue = create_queue(name, "priority", O_NONBLOCK, 3);
    int alias = dup(queue);
    check(fcntl(queue, F_GETFD) == FD_CLOEXEC && alias >= 0 && fcntl(alias, F_GETFD) == 0,
          "queue descriptors default to close-on-exec");
    fails(mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0600, NULL), EEXIST);
    check(snprintf(path, sizeof(path), "/dev/mqueue%s", name) > 0, "visible queue path");
    struct stat identity, visible;
    check(!fstat(queue, &identity) && !stat(path, &visible) && S_ISREG(identity.st_mode) &&
              (identity.st_mode & 0777) == 0600 && identity.st_ino == visible.st_ino &&
              identity.st_dev == visible.st_dev,
          "same inode in the mqueue mount");
    struct mq_attr attr, change = {.mq_flags = 0};
    check(!mq_setattr(alias, &change, &attr) && attr.mq_flags == O_NONBLOCK &&
              attr.mq_maxmsg == 3 && attr.mq_msgsize == 8 && !attr.mq_curmsgs &&
              !(fcntl(queue, F_GETFL) & O_NONBLOCK),
          "nonblocking is shared by descriptor aliases");
    check(!fcntl(queue, F_SETFL, O_NONBLOCK) && !mq_getattr(alias, &attr) &&
              attr.mq_flags == O_NONBLOCK,
          "fcntl and mq_getattr agree");
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event = {.events = EPOLLIN | EPOLLET, .data.fd = queue};
    check(epoll >= 0 && !epoll_ctl(epoll, EPOLL_CTL_ADD, queue, &event) &&
              epoll_wait(epoll, &event, 1, 0) == 0,
          "edge observer initially quiet");
    struct pollfd poller = {.fd = queue, .events = POLLIN | POLLOUT};
    check(poll(&poller, 1, 0) == 1 && poller.revents == POLLOUT, "empty queue readiness");
    fails(mq_receive(queue, text, sizeof(text), NULL), EAGAIN);
    check(!mq_send(queue, "old", 3, 77) && !mq_send(queue, "max", 3, 32767) &&
              !mq_send(queue, "new", 3, 77),
          "fill queue with different and equal priorities");
    check(epoll_wait(epoll, &event, 1, 0) == 1 && event.data.fd == queue &&
              (event.events & EPOLLIN) && epoll_wait(epoll, &event, 1, 0) == 0,
          "one readable transition");
    fails(mq_send(queue, "x", 1, 32768), EINVAL);
    fails(mq_send(queue, "x", 1, 0), EAGAIN);
    fails(mq_receive(queue, text, 7, NULL), EMSGSIZE);
    check(poll(&poller, 1, 0) == 1 && poller.revents == POLLIN && close(epoll) == 0,
          "full queue readiness");
    check(read(queue, text, sizeof(text) - 1) > 0 && !memcmp(text, "QSIZE:9", 7),
          "metadata read does not consume messages");
    check(!unlink(path), "filesystem unlink hides queue name");
    fails(mq_open(name, O_RDONLY), ENOENT);
    receive(alias, "max", 32767);
    receive(alias, "old", 77);
    receive(alias, "new", 77);
    check(!mq_close(alias) && !mq_close(queue), "release old queue descriptions");
}

static void blocking(void) {
    char name[64];
    mqd_t queue = create_queue(name, "blocking", 0, 1);
    pid_t child = fork();
    check(child >= 0, "fork waiting receiver");
    if (!child) {
        receive(queue, "direct", 8);
        _exit(0);
    }
    wait_sleeping(child);
    check(!mq_send(queue, "direct", 6, 8), "hand off to waiting receiver");
    wait_ok(child);
    check(!mq_send(queue, "first", 5, 0), "fill single slot");
    child = fork();
    check(child >= 0, "fork waiting sender");
    if (!child) {
        check(!mq_send(queue, "second", 6, 9), "wait for sender capacity");
        _exit(0);
    }
    wait_sleeping(child);
    check(!mq_unlink(name), "unlink while sender is blocked");
    receive(queue, "first", 0);
    wait_ok(child);
    receive(queue, "second", 9);
    struct timespec deadline, returned;
    check(!clock_gettime(CLOCK_REALTIME, &deadline), "realtime before receive");
    deadline.tv_nsec += 150000000;
    if (deadline.tv_nsec >= 1000000000) {
        deadline.tv_nsec -= 1000000000;
        ++deadline.tv_sec;
    }
    char buffer[8];
    fails(mq_timedreceive(queue, buffer, sizeof(buffer), NULL, &deadline), ETIMEDOUT);
    check(!clock_gettime(CLOCK_REALTIME, &returned) &&
              (returned.tv_sec > deadline.tv_sec ||
               (returned.tv_sec == deadline.tv_sec && returned.tv_nsec >= deadline.tv_nsec)),
          "absolute realtime deadline elapsed");
    check(!mq_send(queue, "", 0, 0), "zero-byte message occupies a slot");
    fails(mq_timedsend(queue, "x", 1, 0, &deadline), ETIMEDOUT);
    receive(queue, "", 0);
    check(!mq_close(queue), "release unlinked queue");
}

static sem_t thread_done;

static void callback(union sigval value) {
    if (value.sival_int != 331 || sem_post(&thread_done))
        _exit(4);
}

static void notifications(void) {
    char name[64];
    mqd_t queue = create_queue(name, "notification", 0, 3);
    sigset_t mask;
    check(!sigemptyset(&mask) && !sigaddset(&mask, SIGUSR1) && !sigprocmask(SIG_BLOCK, &mask, NULL),
          "block notification signal");
    struct sigevent event = {
        .sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGUSR1, .sigev_value.sival_int = 902};
    check(!mq_notify(queue, &event), "register signal notification");
    fails(mq_notify(queue, &event), EBUSY);
    check(!mq_send(queue, "ready", 5, 0), "signal transition message");
    siginfo_t info;
    check(sigtimedwait(&mask, &info, &(struct timespec){.tv_sec = 2}) == SIGUSR1 &&
              info.si_code == SI_MESGQ && info.si_pid == getpid() && info.si_uid == getuid() &&
              info.si_value.sival_int == 902,
          "one-shot signal payload and sender");
    receive(queue, "ready", 0);
    check(!mq_notify(queue, &event), "register while empty again");
    pid_t child = fork();
    check(child >= 0, "fork receiver before notification");
    if (!child) {
        receive(queue, "direct", 0);
        _exit(0);
    }
    wait_sleeping(child);
    check(!mq_send(queue, "direct", 6, 0), "waiting receiver takes the first message");
    wait_ok(child);
    fails(sigtimedwait(&mask, &info, &(struct timespec){0}), EAGAIN);
    check(!mq_send(queue, "ready", 5, 0) &&
              sigtimedwait(&mask, &info, &(struct timespec){.tv_sec = 2}) == SIGUSR1 &&
              info.si_value.sival_int == 902,
          "direct handoff preserves the one-shot registration");
    receive(queue, "ready", 0);
    check(!sem_init(&thread_done, 0, 0), "prepare thread callback");
    event = (struct sigevent){.sigev_notify = SIGEV_THREAD,
                              .sigev_notify_function = callback,
                              .sigev_value.sival_int = 331};
    check(!mq_notify(queue, &event) && !mq_send(queue, "thread", 6, 0),
          "request actual libc thread notification");
    struct timespec deadline;
    check(!clock_gettime(CLOCK_REALTIME, &deadline), "callback deadline");
    deadline.tv_sec += 3;
    check(!sem_timedwait(&thread_done, &deadline) && !sem_destroy(&thread_done),
          "libc invoked the thread callback");
    receive(queue, "thread", 0);

    int socket_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 0);

    enum { cookie_size = 32, notification_removed = 2 };

    unsigned char cookie[cookie_size] = "cancel me", output[cookie_size];
    event = (struct sigevent){
        .sigev_notify = SIGEV_THREAD, .sigev_signo = socket_fd, .sigev_value.sival_ptr = cookie};
    check(socket_fd >= 0 && !syscall(SYS_mq_notify, queue, &event), "register raw cookie");
    int alias = dup(queue);
    check(alias >= 0 && !mq_close(alias), "owner closes a queue alias");
    check(recv(socket_fd, output, sizeof(output), MSG_DONTWAIT) == (ssize_t)sizeof(output) &&
              !memcmp(output, cookie, sizeof(output) - 1) &&
              output[sizeof(output) - 1] == notification_removed,
          "close delivers notification cancellation");
    check(!close(socket_fd) && !mq_close(queue) && !mq_unlink(name), "notification cleanup");
}

static void permissions_and_limits(void) {
    char name[64];
    mqd_t queue = create_queue(name, "permissions", 0, 1);
    if (!getuid()) {
        pid_t child = fork();
        check(child >= 0, "fork nonowner");
        if (!child) {
            check(!mq_close(queue), "close inherited descriptor");
            ordinary();
            fails(mq_open(name, O_RDONLY), EACCES);
            check(mq_unlink(name) == -1 && (errno == EPERM || errno == EACCES),
                  "sticky directory prevents foreign unlink");
            _exit(0);
        }
        wait_ok(child);
    }
    struct rlimit previous, small = {.rlim_cur = 128};
    check(!getrlimit(RLIMIT_MSGQUEUE, &previous), "read queue budget");
    small.rlim_max = previous.rlim_max;
    check(!setrlimit(RLIMIT_MSGQUEUE, &small), "lower message queue budget");
    char denied[64];
    name_for(denied, "over-budget");
    fails(mq_open(denied, O_CREAT | O_EXCL | O_RDWR, 0600, NULL), EMFILE);
    struct mq_attr small_queue = {.mq_maxmsg = 1, .mq_msgsize = 8};
    check(!mq_unlink(name), "unlink a charged queue");
    fails(mq_open(denied, O_CREAT | O_EXCL | O_RDWR, 0600, &small_queue), EMFILE);
    fails(mq_open(denied, O_RDONLY), ENOENT);
    check(!mq_close(queue), "release the last charged description");
    queue = mq_open(denied, O_CREAT | O_EXCL | O_RDWR, 0600, &small_queue);
    check(queue >= 0 && !mq_close(queue) && !mq_unlink(denied) &&
              !setrlimit(RLIMIT_MSGQUEUE, &previous),
          "final close releases the unlinked queue budget");
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(20);
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")), "arguments");
    if (argc == 2)
        ordinary();
    priority_and_names();
    puts("POSIX_MQ_CASE priority-names");
    blocking();
    puts("POSIX_MQ_CASE blocking");
    notifications();
    puts("POSIX_MQ_CASE notifications");
    permissions_and_limits();
    puts("POSIX_MQ_CASE permissions-limits");
    printf("POSIX_MQ_PASS uid=%u\n", (unsigned)getuid());
    return 0;
}
