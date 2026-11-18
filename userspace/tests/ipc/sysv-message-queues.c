// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// Older libc headers omit this Linux msgrcv option.
#ifndef MSG_COPY
#define MSG_COPY 040000
#endif

struct message {
    long type;
    char data[8];
};

static void check(int success, const char* operation) {
    if (!success) {
        fprintf(stderr, "SYSV_MSG_FAIL %s errno=%d\n", operation, errno);
        _exit(1);
    }
}

#define fails(call, expected) check((call) == -1 && errno == (expected), #call)

static void ordinary(void) {
    check(!setgroups(0, NULL) && !setgid(65534) && !setuid(65534), "ordinary credentials");
}

static void wait_ok(pid_t child) {
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child completion");
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
        check(!strstr(status, "\nState:\tZ"), "child must still be waiting");
        struct timespec delay = {.tv_nsec = 5000000};
        check(!nanosleep(&delay, NULL), "waiter observation");
    }
    check(0, "child reached the blocking call");
}

static int queue(unsigned mode) {
    int id = msgget(IPC_PRIVATE, mode);
    check(id >= 0, "private queue");
    return id;
}

static struct msqid_ds status_of(int id) {
    struct msqid_ds info;
    check(!msgctl(id, IPC_STAT, &info), "IPC_STAT");
    return info;
}

static void set_limit(int id, size_t size) {
    struct msqid_ds info = status_of(id);
    info.msg_qbytes = size;
    check(!msgctl(id, IPC_SET, &info) && status_of(id).msg_qbytes == size, "change queue limit");
}

static void send_value(int id, long type, const char* value) {
    struct message msg = {.type = type};
    size_t size = strlen(value);
    check(size <= sizeof(msg.data), "test message size");
    memcpy(msg.data, value, size);
    check(!msgsnd(id, &msg, size, IPC_NOWAIT), "send value");
}

static void receive_value(int id, long selector, int flags, long type, const char* value) {
    struct message msg = {0};
    size_t size = strlen(value);
    check(msgrcv(id, &msg, sizeof(msg.data), selector, flags) == (ssize_t)size &&
              msg.type == type && !memcmp(msg.data, value, size),
          "selected message type and bytes");
}

static void identity(void) {
    key_t key = 0x6b000000 | getpid();
    fails(msgget(key, 0600), ENOENT);
    int id = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
    check(id >= 0 && msgget(key, 0400) == id, "lookup existing key");
    fails(msgget(key, IPC_CREAT | IPC_EXCL | 0600), EEXIST);
    struct msqid_ds info = status_of(id);
    check(info.msg_perm.uid == getuid() && info.msg_perm.cuid == getuid() &&
              info.msg_perm.gid == getgid() && info.msg_perm.cgid == getgid() &&
              (info.msg_perm.mode & 0777) == 0600 && info.msg_qbytes == 16384 && !info.msg_stime &&
              !info.msg_rtime && info.msg_ctime > 0 && !info.msg_lspid && !info.msg_lrpid &&
              !info.msg_qnum && !info.msg_cbytes,
          "initial ABI metadata");
    struct msginfo usage, limits;
    int last = msgctl(0, MSG_INFO, (struct msqid_ds*)&usage);
    check(last >= 0 && usage.msgpool == 1 && !usage.msgmap && !usage.msgtql, "initial usage");
    check(msgctl(0, IPC_INFO, (struct msqid_ds*)&limits) == last && limits.msgmni == 32000 &&
              limits.msgmax == 8192 && limits.msgmnb == 16384,
          "configured limits");
    check(msgctl(last, MSG_STAT, &info) == id && msgctl(last, MSG_STAT_ANY, &info) == id,
          "indexed status returns queue identifier");
    send_value(id, 1, "abc");
    check(msgctl(0, MSG_INFO, (struct msqid_ds*)&usage) == last && usage.msgpool == 1 &&
              usage.msgmap == 1 && usage.msgtql == 3,
          "live headers and bytes");
    info = status_of(id);
    check(info.msg_qnum == 1 && info.msg_cbytes == 3 && info.msg_lspid == getpid() &&
              info.msg_stime >= info.msg_ctime && !info.msg_lrpid,
          "send updates status");
    receive_value(id, 0, IPC_NOWAIT, 1, "abc");
    info = status_of(id);
    check(!info.msg_qnum && !info.msg_cbytes && info.msg_lrpid == getpid() &&
              info.msg_rtime >= info.msg_stime,
          "receive updates status");
    check(!msgctl(id, IPC_RMID, NULL), "remove named queue");
    int replacement = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
    check(replacement >= 0 && replacement != id, "new identifier after removal");
    fails(msgctl(id, IPC_STAT, &info), EINVAL);
    check(!msgctl(replacement, IPC_RMID, NULL), "remove replacement");
}

static void selection(void) {
    int id = queue(0600);
    send_value(id, 5, "first");
    send_value(id, 3, "old");
    send_value(id, 7, "except");
    send_value(id, 3, "new");
    send_value(id, LONG_MAX, "max");
    struct message msg;
    fails(msgrcv(id, &msg, sizeof(msg.data), 0, MSG_COPY), EINVAL);
    fails(msgrcv(id, &msg, sizeof(msg.data), 0, IPC_NOWAIT | MSG_COPY | MSG_EXCEPT), EINVAL);
    receive_value(id, 2, IPC_NOWAIT | MSG_COPY, 7, "except");
    fails(msgrcv(id, &msg, 1, 2, IPC_NOWAIT | MSG_COPY), E2BIG);
    fails(msgrcv(id, &msg, 1, 2, IPC_NOWAIT | MSG_COPY | MSG_NOERROR), EINVAL);
    fails(msgrcv(id, &msg, sizeof(msg.data), -1, IPC_NOWAIT | MSG_COPY), ENOMSG);
    struct msqid_ds info = status_of(id);
    check(info.msg_qnum == 5 && !info.msg_lrpid && !info.msg_rtime, "copy preserves status");
    receive_value(id, -7, IPC_NOWAIT, 3, "old");
    receive_value(id, 3, IPC_NOWAIT, 3, "new");
    receive_value(id, 5, IPC_NOWAIT | MSG_EXCEPT, 7, "except");
    receive_value(id, 0, IPC_NOWAIT, 5, "first");
    receive_value(id, LONG_MIN, IPC_NOWAIT, LONG_MAX, "max");
    fails(msgrcv(id, &msg, sizeof(msg.data), 0, IPC_NOWAIT), ENOMSG);
    check(!msgctl(id, IPC_RMID, NULL), "remove selection queue");
}

static void capacity_and_faults(void) {
    int id = queue(0600);
    struct message msg = {.type = 0};
    fails(msgsnd(id, &msg, 0, IPC_NOWAIT), EINVAL);
    msg.type = 1;
    fails(syscall(SYS_msgsnd, id, &msg, 8193, IPC_NOWAIT), EINVAL);
    fails(syscall(SYS_msgsnd, id, 1, 0, IPC_NOWAIT), EFAULT);
    char* guarded = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(guarded != MAP_FAILED && !mprotect(guarded + 4096, 4096, PROT_NONE), "guard page");
    *(long*)(guarded + 4096 - sizeof(long)) = 1;
    fails(syscall(SYS_msgsnd, id, guarded + 4096 - sizeof(long), 1, IPC_NOWAIT), EFAULT);
    check(!status_of(id).msg_qnum, "failed send changes no queue state");

    send_value(id, 5, "four");
    fails(msgrcv(id, &msg, 2, 0, IPC_NOWAIT), E2BIG);
    check(status_of(id).msg_cbytes == 4, "short receive retains payload");
    check(msgrcv(id, &msg, 2, 0, IPC_NOWAIT | MSG_NOERROR) == 2 && msg.type == 5 &&
              !memcmp(msg.data, "fo", 2),
          "truncate copies prefix and consumes message");
    send_value(id, 3, "fault");
    fails(syscall(SYS_msgrcv, id, guarded + 4096 - sizeof(long), 8, 0, IPC_NOWAIT), EFAULT);
    check(*(long*)(guarded + 4096 - sizeof(long)) == 3 && !status_of(id).msg_qnum,
          "destructive copy fault consumes the message after copying type");
    check(!munmap(guarded, 8192), "unmap guard");

    struct {
        long type;
        unsigned char data[8192];
    } sent = {.type = 29}, received = {0};

    for (size_t i = 0; i < sizeof(sent.data); ++i)
        sent.data[i] = (unsigned char)(i ^ (i >> 8));
    check(!msgsnd(id, &sent, sizeof(sent.data), IPC_NOWAIT) &&
              !msgsnd(id, &sent, sizeof(sent.data), IPC_NOWAIT),
          "two maximum-sized messages fit in the default queue");
    fails(msgsnd(id, &msg, 1, IPC_NOWAIT), EAGAIN);
    check(status_of(id).msg_cbytes == 16384, "default byte limit accounted");
    for (unsigned i = 0; i < 2; ++i)
        check(msgrcv(id, &received, sizeof(received.data), 0, IPC_NOWAIT) ==
                      (ssize_t)sizeof(sent.data) &&
                  received.type == sent.type &&
                  !memcmp(received.data, sent.data, sizeof(sent.data)),
              "maximum-sized message crosses page boundaries intact");

    set_limit(id, 2);
    send_value(id, 1, "ab");
    fails(msgsnd(id, &msg, 1, IPC_NOWAIT), EAGAIN);
    send_value(id, 2, "");
    fails(msgsnd(id, &msg, 0, IPC_NOWAIT), EAGAIN);
    set_limit(id, 1);
    fails(msgsnd(id, &msg, 0, IPC_NOWAIT), EAGAIN);
    receive_value(id, 1, IPC_NOWAIT, 1, "ab");
    receive_value(id, 2, IPC_NOWAIT, 2, "");
    check(!msgctl(id, IPC_RMID, NULL), "remove capacity queue");
}

static void direct_delivery(void) {
    int id = queue(0600);
    pid_t short_reader = fork();
    check(short_reader >= 0, "fork short reader");
    if (!short_reader) {
        struct message msg;
        fails(msgrcv(id, &msg, 1, 7, 0), E2BIG);
        _exit(0);
    }
    wait_sleeping(short_reader);
    pid_t reader = fork();
    check(reader >= 0, "fork matching reader");
    if (!reader) {
        receive_value(id, -7, 0, 7, "direct");
        _exit(0);
    }
    wait_sleeping(reader);
    send_value(id, 8, "queued");
    send_value(id, 7, "direct");
    wait_ok(short_reader);
    wait_ok(reader);
    struct msqid_ds info = status_of(id);
    check(info.msg_qnum == 1 && info.msg_cbytes == 6 && info.msg_lrpid == reader &&
              info.msg_lspid == getpid(),
          "handoff skips unrelated message and does not charge queue capacity");
    receive_value(id, 0, IPC_NOWAIT, 8, "queued");
    check(!msgctl(id, IPC_RMID, NULL), "remove delivery queue");
}

struct blocked_send {
    int id;
    struct message msg;
};

static int shared_sender(void* pointer) {
    struct blocked_send* request = pointer;
    check(!msgsnd(request->id, &request->msg, 4, 0), "retained blocking send");
    return 0;
}

static void blocked_senders(void) {
    int id = queue(0600);
    set_limit(id, 4);
    send_value(id, 3, "full");
    struct blocked_send request = {id, {5, "keep"}};
    void* stack = malloc(65536);
    check(stack != NULL, "clone stack");
    pid_t sender = clone(shared_sender, (char*)stack + 65536, CLONE_VM | SIGCHLD, &request);
    check(sender >= 0, "shared VM sender");
    wait_sleeping(sender);
    request.msg.type = 9;
    memcpy(request.msg.data, "edit", 4);
    receive_value(id, 0, IPC_NOWAIT, 3, "full");
    wait_ok(sender);
    free(stack);
    check(status_of(id).msg_lspid == sender, "sender pid recorded after wakeup");
    receive_value(id, 0, IPC_NOWAIT, 5, "keep");

    set_limit(id, 0);
    sender = fork();
    check(sender >= 0, "fork capacity waiter");
    if (!sender) {
        struct message message = {4, "grow"};
        check(!msgsnd(id, &message, 4, 0), "IPC_SET wakes fitting sender");
        _exit(0);
    }
    wait_sleeping(sender);
    set_limit(id, 4);
    wait_ok(sender);
    receive_value(id, 0, IPC_NOWAIT, 4, "grow");
    check(!msgctl(id, IPC_RMID, NULL), "remove sender queue");
}

static void handle(int signal) {
    (void)signal;
}

static void waiter_error(int id, int sending, int expected) {
    struct message msg = {1, "wait"};
    if (expected == EINTR) {
        struct sigaction action = {.sa_handler = handle, .sa_flags = SA_RESTART};
        check(!sigemptyset(&action.sa_mask) && !sigaction(SIGUSR1, &action, NULL), "caught signal");
    }
    if (sending)
        fails(msgsnd(id, &msg, 4, 0), expected);
    else
        fails(msgrcv(id, &msg, sizeof(msg.data), 1, 0), expected);
}

static void interrupted_and_removed(void) {
    for (unsigned sending = 0; sending < 2; ++sending) {
        for (unsigned remove = 0; remove < 2; ++remove) {
            int id = queue(0600);
            if (sending)
                set_limit(id, 0);
            pid_t waiter = fork();
            check(waiter >= 0, "fork cleanup waiter");
            if (!waiter) {
                waiter_error(id, sending, remove ? EIDRM : EINTR);
                _exit(0);
            }
            wait_sleeping(waiter);
            if (remove)
                check(!msgctl(id, IPC_RMID, NULL), "remove queue with waiter");
            else
                check(!kill(waiter, SIGUSR1), "interrupt actual waiter");
            wait_ok(waiter);
            if (!remove) {
                set_limit(id, 4);
                send_value(id, 1, "live");
                receive_value(id, 0, IPC_NOWAIT, 1, "live");
                check(!msgctl(id, IPC_RMID, NULL), "remove interrupted queue");
            }
        }
    }
    int id = queue(0600);
    pid_t waiter = fork();
    check(waiter >= 0, "fork exited waiter");
    if (!waiter) {
        receive_value(id, 0, 0, 1, "never");
        _exit(1);
    }
    wait_sleeping(waiter);
    int status;
    check(!kill(waiter, SIGKILL) && waitpid(waiter, &status, 0) == waiter && WIFSIGNALED(status) &&
              WTERMSIG(status) == SIGKILL,
          "killed receiver exit");
    send_value(id, 1, "live");
    receive_value(id, 0, IPC_NOWAIT, 1, "live");
    check(!msgctl(id, IPC_RMID, NULL), "remove exit queue");
}

static void permissions(void) {
    if (getuid()) {
        int id = queue(0600);
        struct msqid_ds info = status_of(id);
        info.msg_qbytes = 16385;
        fails(msgctl(id, IPC_SET, &info), EPERM);
        check(status_of(id).msg_qbytes == 16384, "rejected limit is unchanged");
        check(!msgctl(id, IPC_RMID, NULL), "ordinary owner removes queue");
        return;
    }
    int id = queue(0640);
    struct msqid_ds info = status_of(id);
    info.msg_perm.gid = 65534;
    check(!msgctl(id, IPC_SET, &info), "set group metadata");
    pid_t reader = fork();
    check(reader >= 0, "fork group reader");
    if (!reader) {
        ordinary();
        struct msqid_ds allowed = status_of(id);
        check(allowed.msg_perm.gid == getgid() && !allowed.msg_perm.cgid,
              "owner and creator group");
        struct message msg = {1, "no"};
        fails(msgsnd(id, &msg, 2, IPC_NOWAIT), EACCES);
        fails(msgctl(id, IPC_RMID, NULL), EPERM);
        waiter_error(id, 0, EACCES);
        _exit(0);
    }
    wait_sleeping(reader);
    info.msg_perm.mode = 0600;
    check(!msgctl(id, IPC_SET, &info), "revoke access from blocked reader");
    wait_ok(reader);
    info.msg_perm.mode = 0666;
    info.msg_qbytes = 0;
    check(!msgctl(id, IPC_SET, &info), "allow ordinary sender on zero capacity");
    pid_t sender = fork();
    check(sender >= 0, "fork permission sender");
    if (!sender) {
        ordinary();
        waiter_error(id, 1, EACCES);
        _exit(0);
    }
    wait_sleeping(sender);
    info.msg_perm.mode = 0600;
    info.msg_qbytes = 4;
    check(!msgctl(id, IPC_SET, &info), "recheck permissions when capacity wakes sender");
    wait_ok(sender);
    check(!status_of(id).msg_qnum && !msgctl(id, IPC_RMID, NULL),
          "permission change sends nothing");
}

static void across_exec(const char* program) {
    int id = queue(0600);
    pid_t producer = fork();
    check(producer >= 0, "fork producer");
    if (!producer) {
        send_value(id, 2, "persist");
        _exit(0);
    }
    wait_ok(producer);
    check(status_of(id).msg_lspid == producer, "dead sender pid remains observable");
    pid_t consumer = fork();
    check(consumer >= 0, "fork exec consumer");
    if (!consumer) {
        char number[16];
        check(snprintf(number, sizeof(number), "%d", id) > 0, "format queue identifier");
        execl(program, program, "--receive", number, (char*)NULL);
        check(0, "exec same client");
    }
    wait_ok(consumer);
    check(status_of(id).msg_lrpid == consumer && !msgctl(id, IPC_RMID, NULL),
          "executed receiver consumed retained message");
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(20);
    if (argc == 3 && !strcmp(argv[1], "--receive")) {
        receive_value(atoi(argv[2]), 0, IPC_NOWAIT, 2, "persist");
        return 0;
    }
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")), "arguments");
    if (argc == 2)
        ordinary();
    identity();
    puts("SYSV_MSG_CASE identity");
    selection();
    puts("SYSV_MSG_CASE selection");
    capacity_and_faults();
    puts("SYSV_MSG_CASE capacity-faults");
    direct_delivery();
    puts("SYSV_MSG_CASE direct-delivery");
    blocked_senders();
    puts("SYSV_MSG_CASE blocked-senders");
    interrupted_and_removed();
    puts("SYSV_MSG_CASE interruption-removal");
    permissions();
    puts("SYSV_MSG_CASE permissions");
    across_exec(argv[0]);
    puts("SYSV_MSG_CASE exec");
    printf("SYSV_MSG_PASS uid=%u\n", (unsigned)getuid());
    return 0;
}
