// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            dprintf(2, "WAITID_FAIL line=%d errno=%d check=%s\n", __LINE__, errno, #expression);   \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned observations;
static volatile sig_atomic_t caught;
static int notified_fd;

static void notified(int number) {
    (void)number;
    caught++;
    char value = 'x';
    ssize_t result = write(notified_fd, &value, 1);
    (void)result;
}

static void observed(const char* label) {
    printf("WAITID_OBSERVATION %s\n", label);
    fflush(stdout);
    observations++;
}

static void byte(int fd, int writing) {
    char value = 'x';
    CHECK((writing ? write(fd, &value, 1) : read(fd, &value, 1)) == 1 && value == 'x');
}

static pid_t child(int ready, int finish, int group) {
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (!pid) {
        if (group)
            CHECK(setpgid(0, 0) == 0);
        byte(ready, 1);
        byte(finish, 0);
        _exit(41);
    }
    return pid;
}

static void detail(const siginfo_t* info, pid_t pid, int code, int status) {
    CHECK(info->si_signo == SIGCHLD && info->si_errno == 0 && info->si_code == code &&
          info->si_pid == pid && info->si_uid == getuid() && info->si_status == status);
}

static void repeated(pid_t pid, int options, int code, int status) {
    for (unsigned i = 0; i < 3; i++) {
        siginfo_t info;
        memset(&info, 0xa5, sizeof(info));
        CHECK(waitid(P_PID, pid, &info, options | WNOWAIT) == 0);
        detail(&info, pid, code, status);
    }
}

static void blocked(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    for (unsigned attempt = 0; attempt < 4000; attempt++) {
        int fd = open(path, O_RDONLY);
        CHECK(fd >= 0);
        char bytes[8192];
        ssize_t size = read(fd, bytes, sizeof(bytes) - 1);
        CHECK(size > 0);
        bytes[size] = 0;
        close(fd);
        if (strstr(bytes, "\nState:\tS"))
            return;
        usleep(1000);
    }
    CHECK(0);
}

int main(void) {
    alarm(40);
    int ready[2], finish[2], status;
    CHECK(pipe(ready) == 0 && pipe(finish) == 0);
    pid_t pid = child(ready[1], finish[0], 0);
    byte(ready[0], 0);
    siginfo_t info;
    memset(&info, 0xa5, sizeof(info));
    CHECK(waitid(P_PID, pid, &info, WEXITED | WNOHANG) == 0);
    CHECK(info.si_signo == 0 && info.si_pid == 0);
    byte(finish[1], 1);
    repeated(pid, WEXITED, CLD_EXITED, 41);
    CHECK(kill(pid, 0) == 0);
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 41);
    CHECK(waitid(P_PID, pid, &info, WEXITED | WNOHANG) == -1 && errno == ECHILD);
    observed("nohang_repeatable_exit_and_waitpid_reap");

    pid = child(ready[1], finish[0], 0);
    byte(ready[0], 0);
    CHECK(kill(pid, SIGKILL) == 0);
    repeated(pid, WEXITED, CLD_KILLED, SIGKILL);
    CHECK(waitid(P_PID, pid, &info, WEXITED) == 0);
    detail(&info, pid, CLD_KILLED, SIGKILL);
    CHECK(waitpid(pid, &status, WNOHANG) == -1 && errno == ECHILD);
    observed("fatal_signal_details_and_consumption");

    pid = child(ready[1], finish[0], 0);
    byte(ready[0], 0);
    CHECK(kill(pid, SIGSTOP) == 0);
    repeated(pid, WSTOPPED, CLD_STOPPED, SIGSTOP);
    CHECK(waitid(P_PID, pid, &info, WSTOPPED) == 0);
    detail(&info, pid, CLD_STOPPED, SIGSTOP);
    CHECK(waitid(P_PID, pid, &info, WSTOPPED | WNOHANG) == 0 && info.si_pid == 0);
    CHECK(kill(pid, SIGCONT) == 0);
    repeated(pid, WCONTINUED, CLD_CONTINUED, SIGCONT);
    CHECK(waitid(P_PID, pid, &info, WCONTINUED) == 0);
    detail(&info, pid, CLD_CONTINUED, SIGCONT);
    CHECK(waitid(P_PID, pid, &info, WCONTINUED | WNOHANG) == 0 && info.si_pid == 0);
    byte(finish[1], 1);
    CHECK(waitid(P_PID, pid, &info, WEXITED) == 0);
    detail(&info, pid, CLD_EXITED, 41);
    observed("stopped_continued_events_remain_waitable_until_consumed");

    pid_t foreign = child(ready[1], finish[0], 1);
    byte(ready[0], 0);
    pid_t ordinary = child(ready[1], finish[0], 0);
    byte(ready[0], 0);
    CHECK(waitid(P_PGID, 0, &info, WEXITED | WNOHANG) == 0 && info.si_pid == 0);
    CHECK(kill(foreign, SIGKILL) == 0);
    CHECK(waitid(P_PGID, foreign, &info, WEXITED | WNOWAIT) == 0);
    detail(&info, foreign, CLD_KILLED, SIGKILL);
    CHECK(waitid(P_PGID, 0, &info, WEXITED | WNOHANG) == 0 && info.si_pid == 0);
    CHECK(waitid(P_ALL, 1234567, &info, WEXITED) == 0);
    detail(&info, foreign, CLD_KILLED, SIGKILL);
    byte(finish[1], 1);
    CHECK(waitid(P_PGID, 0, &info, WEXITED) == 0);
    detail(&info, ordinary, CLD_EXITED, 41);
    observed("all_and_exact_group_selectors");

    CHECK(waitid(P_PID, 0, &info, WEXITED) == -1 && errno == EINVAL);
    CHECK(waitid((idtype_t)99, 0, &info, WEXITED) == -1 && errno == EINVAL);
    CHECK(waitid(P_ALL, 0, &info, WNOHANG) == -1 && errno == EINVAL);
    CHECK(waitid(P_ALL, 0, &info, WEXITED | 0x100) == -1 && errno == EINVAL);
    CHECK(waitid(P_ALL, 0, &info, WEXITED) == -1 && errno == ECHILD);
    observed("invalid_selection_options_and_no_children");

    // Native Linux consumes an exit event before copying its result to userspace.
    // WNOWAIT deliberately retains the same event even after a copy fault.
    void* denied = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(denied != MAP_FAILED);
    for (unsigned keep = 0; keep < 2; keep++) {
        pid = child(ready[1], finish[0], 0);
        byte(ready[0], 0);
        byte(finish[1], 1);
        repeated(pid, WEXITED, CLD_EXITED, 41);
        CHECK(syscall(SYS_waitid, P_PID, pid, denied, WEXITED | (keep ? WNOWAIT : 0), NULL) == -1 &&
              errno == EFAULT);
        if (keep) {
            CHECK(waitid(P_PID, pid, &info, WEXITED) == 0);
            detail(&info, pid, CLD_EXITED, 41);
        } else
            CHECK(waitpid(pid, &status, WNOHANG) == -1 && errno == ECHILD);
    }
    CHECK(munmap(denied, 4096) == 0);
    observed("failed_result_copy_consumption_and_nowait_retention");

    // Only waitid's documented child fields are output. The unused union tail
    // may cross an inaccessible page without invalidating the actual result.
    char* pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED && mprotect(pages + 4096, 4096, PROT_NONE) == 0);
    siginfo_t* prefix = (siginfo_t*)(pages + 4096 - 32);
    pid = child(ready[1], finish[0], 0);
    byte(ready[0], 0);
    CHECK(waitid(P_PID, pid, prefix, WEXITED | WNOHANG) == 0 && prefix->si_pid == 0);
    byte(finish[1], 1);
    CHECK(waitid(P_PID, pid, prefix, WEXITED | WNOWAIT) == 0);
    detail(prefix, pid, CLD_EXITED, 41);
    CHECK(waitpid(pid, &status, 0) == pid && WEXITSTATUS(status) == 41);
    CHECK(munmap(pages, 8192) == 0);
    observed("accessible_result_fields_with_inaccessible_unused_siginfo_tail");

    pid = child(ready[1], finish[0], 0);
    byte(ready[0], 0);
    byte(finish[1], 1);
    repeated(pid, WEXITED, CLD_EXITED, 41);
    CHECK(syscall(SYS_waitid, P_PID, pid, &info, WEXITED, (struct rusage*)1) == -1 &&
          errno == EFAULT);
    CHECK(waitpid(pid, &status, WNOHANG) == -1 && errno == ECHILD);
    observed("failed_resource_output_copy_consumes_exit_event");

    for (unsigned restart = 0; restart < 2; restart++) {
        int go[2], notification[2];
        CHECK(pipe(go) == 0 && pipe(notification) == 0);
        notified_fd = notification[1];
        caught = 0;
        struct sigaction action = {.sa_handler = notified, .sa_flags = restart ? SA_RESTART : 0};
        CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        pid = child(ready[1], finish[0], 0);
        byte(ready[0], 0);
        pid_t caller = getpid(), sender = fork();
        CHECK(sender >= 0);
        if (!sender) {
            byte(go[0], 0);
            // The caller has no blocking operation between the go byte and
            // waitid, so procfs S establishes this actual wait before signaling.
            blocked(caller);
            CHECK(kill(caller, SIGUSR1) == 0);
            byte(notification[0], 0);
            if (restart)
                byte(finish[1], 1);
            _exit(0);
        }
        byte(go[1], 1);
        int result = waitid(P_PID, pid, &info, WEXITED);
        CHECK(caught == 1);
        if (restart) {
            CHECK(result == 0);
            detail(&info, pid, CLD_EXITED, 41);
        } else {
            CHECK(result == -1 && errno == EINTR);
            byte(finish[1], 1);
            CHECK(waitid(P_PID, pid, &info, WEXITED) == 0);
            detail(&info, pid, CLD_EXITED, 41);
        }
        CHECK(waitpid(sender, &status, 0) == sender && WIFEXITED(status) &&
              WEXITSTATUS(status) == 0);
        close(go[0]);
        close(go[1]);
        close(notification[0]);
        close(notification[1]);
    }
    observed("actual_blocked_wait_interruption_and_sa_restart");

    pid = child(ready[1], finish[0], 0);
    byte(ready[0], 0);
    byte(finish[1], 1);
    repeated(pid, WEXITED, CLD_EXITED, 41);
    CHECK(syscall(SYS_waitid, P_PID, pid, NULL, WEXITED, NULL) == 0);
    CHECK(waitpid(pid, &status, WNOHANG) == -1 && errno == ECHILD);
    observed("linux_null_information_consumes_event");
    close(ready[0]);
    close(ready[1]);
    close(finish[0]);
    close(finish[1]);
    printf("WAITID_PASS observations=%u\n", observations);
    return 0;
}
