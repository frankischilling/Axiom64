// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/busy.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "PROC_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,         \
                    #expression);                                                                  \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned observations;

static void observed(const char* name) {
    printf("PROC_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static int status_file(pid_t pid, int thread) {
    char path[96];
    CHECK(snprintf(path, sizeof(path), thread ? "/proc/%d/task/%d/status" : "/proc/%d/status",
                   thread ? getpid() : pid, pid) < (int)sizeof(path));
    return open(path, O_RDONLY | O_CLOEXEC);
}

static char* read_all(int fd, size_t chunk) {
    size_t used = 0, capacity = 1024;
    char* result = malloc(capacity);
    CHECK(result);
    for (;;) {
        if (capacity - used <= chunk) {
            capacity *= 2;
            CHECK(capacity <= 2 * 1024 * 1024);
            char* next = realloc(result, capacity);
            CHECK(next);
            result = next;
        }
        ssize_t count = read(fd, result + used, chunk);
        CHECK(count >= 0);
        if (!count)
            break;
        used += (size_t)count;
    }
    result[used] = 0;
    return result;
}

static void identity(const char* text, const char* field, unsigned a, unsigned b, unsigned c,
                     unsigned d) {
    const char* line = strstr(text, field);
    unsigned values[4];
    CHECK(line && sscanf(line + strlen(field), "%u %u %u %u", &values[0], &values[1], &values[2],
                         &values[3]) == 4);
    CHECK(values[0] == a && values[1] == b && values[2] == c && values[3] == d);
}

static unsigned field(const char* text, const char* name) {
    const char* line = strstr(text, name);
    unsigned value;
    CHECK(line && sscanf(line + strlen(name), "%u", &value) == 1);
    return value;
}

static int listed(const char* directory, pid_t pid) {
    DIR* stream = opendir(directory);
    CHECK(stream);
    char name[24];
    snprintf(name, sizeof(name), "%d", pid);
    unsigned matches = 0;
    struct dirent* entry;
    while ((entry = readdir(stream)))
        matches += !strcmp(entry->d_name, name);
    CHECK(closedir(stream) == 0 && matches <= 1);
    return (int)matches;
}

static void byte(int fd, int writing) {
    char value = 'x';
    CHECK((writing ? write(fd, &value, 1) : read(fd, &value, 1)) == 1 && value == 'x');
}

static void reap(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
}

struct member {
    int ready, finish;
};

static void* member(void* opaque) {
    struct member* context = opaque;
    gid_t groups[] = {70001, 80002};
    CHECK(syscall(SYS_setgroups, 2, groups) == 0);
    CHECK(syscall(SYS_setresgid, 1013, 0, 1014) == 0 && setfsgid(1015) == 0);
    CHECK(syscall(SYS_setresuid, 1010, 0, 1011) == 0 && setfsuid(1012) == 0);
    pid_t tid = (pid_t)syscall(SYS_gettid);
    char target[64], expected[64];
    ssize_t size = readlink("/proc/thread-self", target, sizeof(target) - 1);
    CHECK(size > 0);
    target[size] = 0;
    snprintf(expected, sizeof(expected), "%d/task/%d", getpid(), tid);
    CHECK(!strcmp(target, expected));
    CHECK(write(context->ready, &tid, sizeof(tid)) == (ssize_t)sizeof(tid));
    byte(context->finish, 0);
    return NULL;
}

int main(void) {
    CHECK(!getuid() && !geteuid() && !getegid());
    struct statfs filesystem;
    CHECK(statfs("/proc", &filesystem) == 0 && filesystem.f_type == 0x9fa0);
    char target[64], expected[64];
    ssize_t size = readlink("/proc/self", target, sizeof(target) - 1);
    CHECK(size > 0);
    target[size] = 0;
    snprintf(expected, sizeof(expected), "%d", getpid());
    CHECK(!strcmp(target, expected) && listed("/proc", getpid()));
    int fd = status_file(getpid(), 0);
    CHECK(fd >= 0);
    struct stat metadata;
    CHECK(fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode) && metadata.st_size == 0);
    char* text = read_all(fd, 7);
    identity(text, "Uid:", 0, 0, 0, 0);
    identity(text, "Gid:", 0, 0, 0, 0);
    CHECK(field(text, "Pid:") == (unsigned)getpid() && field(text, "Tgid:") == (unsigned)getpid());
    CHECK(field(text, "PPid:") == (unsigned)getppid() && field(text, "Threads:") == 1);
    free(text);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    text = read_all(fd, 1);
    identity(text, "Uid:", 0, 0, 0, 0);
    free(text);
    CHECK(close(fd) == 0);
    CHECK(account_process_busy(0, (gid_t)-1) == 1);
    CHECK(account_process_busy((uid_t)-1, 0) == 1);
    CHECK(account_process_busy(4294967294u, (gid_t)-1) == 0);
    CHECK(account_process_busy((uid_t)-1, 4294967294u) == 0);
    observed("actual_proc_mount_self_symlink_pid_enumeration_status_and_rewind");
    fd = open("/proc/self/status", O_WRONLY);
    CHECK(fd >= 0 && write(fd, "x", 1) == -1 && errno == EINVAL && close(fd) == 0);
    CHECK(open("/proc/0/status", O_RDONLY) == -1 && errno == ENOENT);
    CHECK(open("/proc/01/status", O_RDONLY) == -1 && errno == ENOENT);
    fd = status_file(getpid(), 0);
    CHECK(fd >= 0 && mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED &&
          errno == ENODEV);
    close(fd);
    observed("read_only_status_invalid_pid_and_unmappable_metadata");
    int ready[2], finish[2];
    CHECK(pipe(ready) == 0 && pipe(finish) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(ready[0]);
        close(finish[1]);
        gid_t groups[] = {70000, 80000};
        CHECK(setgroups(2, groups) == 0 && setresgid(1004, 0, 1005) == 0 && setfsgid(1006) == 0);
        CHECK(setresuid(1000, 0, 1002) == 0 && setfsuid(1003) == 0);
        byte(ready[1], 1);
        byte(finish[0], 0);
        _exit(0);
    }
    close(ready[1]);
    close(finish[0]);
    byte(ready[0], 0);
    fd = status_file(child, 0);
    CHECK(fd >= 0);
    text = read_all(fd, 13);
    identity(text, "Uid:", 1000, 0, 1002, 1003);
    identity(text, "Gid:", 1004, 0, 1005, 1006);
    CHECK(strstr(text, "Groups:\t70000 80000 ") && field(text, "PPid:") == (unsigned)getpid());
    unsigned user_ids[] = {1000, 1002, 1003}, group_ids[] = {1004, 1005, 1006, 70000, 80000};
    for (size_t i = 0; i < sizeof(user_ids) / sizeof(*user_ids); i++)
        CHECK(account_process_busy(user_ids[i], (gid_t)-1) == 1);
    for (size_t i = 0; i < sizeof(group_ids) / sizeof(*group_ids); i++)
        CHECK(account_process_busy((uid_t)-1, group_ids[i]) == 1);
    free(text);
    close(fd);
    byte(finish[1], 1);
    reap(child);
    close(ready[0]);
    close(finish[1]);
    CHECK(account_process_busy(1000, (gid_t)-1) == 0);
    observed("other_process_full_identity_and_supplementary_groups_are_kernel_values");
    CHECK(pipe(ready) == 0 && pipe(finish) == 0);
    struct member context = {ready[1], finish[0]};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, member, &context) == 0);
    pid_t tid;
    CHECK(read(ready[0], &tid, sizeof(tid)) == (ssize_t)sizeof(tid) && tid != getpid());
    char directory[64];
    snprintf(directory, sizeof(directory), "/proc/%d/task", getpid());
    CHECK(listed(directory, tid) && listed(directory, getpid()) && !listed("/proc", tid));
    int populated = status_file(tid, 1), untouched = status_file(tid, 0);
    CHECK(populated >= 0 && untouched >= 0);
    text = read_all(populated, 31);
    identity(text, "Uid:", 1010, 0, 1011, 1012);
    identity(text, "Gid:", 1013, 0, 1014, 1015);
    CHECK(field(text, "Pid:") == (unsigned)tid && field(text, "Tgid:") == (unsigned)getpid());
    CHECK(field(text, "Threads:") == 2 && strstr(text, "Groups:\t70001 80002 "));
    CHECK(account_process_busy(1010, (gid_t)-1) == 1);
    CHECK(account_process_busy(1011, (gid_t)-1) == 1);
    CHECK(account_process_busy(1012, (gid_t)-1) == 1);
    CHECK(account_process_busy((uid_t)-1, 1013) == 1);
    CHECK(account_process_busy((uid_t)-1, 1014) == 1);
    CHECK(account_process_busy((uid_t)-1, 1015) == 1);
    CHECK(account_process_busy((uid_t)-1, 80002) == 1);
    free(text);
    CHECK(lseek(populated, 0, SEEK_SET) == 0 && read(populated, target, 1) == 1);
    observed("thread_directory_direct_tid_lookup_and_independent_thread_credentials");
    byte(finish[1], 1);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(account_process_busy(1010, (gid_t)-1) == 0);
    text = read_all(populated, 31);
    CHECK(*text && strstr(text, "Uid:\t1010\t0\t1011\t1012"));
    free(text);
    CHECK(read(untouched, target, sizeof(target)) == -1 && errno == ESRCH);
    CHECK(status_file(tid, 0) == -1 && errno == ENOENT);
    close(populated);
    close(untouched);
    for (unsigned i = 0; i < 2; i++) {
        close(ready[i]);
        close(finish[i]);
    }
    observed("exited_thread_retains_only_buffered_status_and_unread_description_reports_esrch");
    unsigned long before = 0;
    CHECK(statfs("/proc", &filesystem) == 0);
    before = filesystem.f_files;
    for (unsigned i = 0; i < 256; i++) {
        CHECK(pipe(finish) == 0);
        child = fork();
        CHECK(child >= 0);
        if (!child) {
            close(finish[1]);
            byte(finish[0], 0);
            _exit(0);
        }
        close(finish[0]);
        fd = status_file(child, 0);
        CHECK(fd >= 0);
        text = read_all(fd, 512);
        CHECK(field(text, "Pid:") == (unsigned)child);
        free(text);
        close(fd);
        byte(finish[1], 1);
        reap(child);
        close(finish[1]);
    }
    fd = status_file(getpid(), 0);
    CHECK(fd >= 0);
    close(fd);
#ifdef PROC_GUEST
    CHECK(statfs("/proc", &filesystem) == 0 && filesystem.f_files <= before + 4);
#else
    (void)before;
#endif
    observed("256_process_slot_recycles_keep_distinct_pid_status_and_bounded_inode_cache");
    CHECK(pipe(ready) == 0 && pipe(finish) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(ready[0]);
        close(finish[1]);
        gid_t* groups = malloc(65536 * sizeof(*groups));
        CHECK(groups);
        for (unsigned i = 0; i < 65536; i++)
            groups[i] = 70000 + i;
        CHECK(setgroups(65536, groups) == 0);
        free(groups);
        byte(ready[1], 1);
        byte(finish[0], 0);
        _exit(0);
    }
    close(ready[1]);
    close(finish[0]);
    byte(ready[0], 0);
    CHECK(account_process_busy((uid_t)-1, 135535) == 1);
    CHECK(account_process_busy((uid_t)-1, 135536) == 0);
    byte(finish[1], 1);
    reap(child);
    close(ready[0]);
    close(finish[1]);
    CHECK(account_process_busy((uid_t)-1, 135535) == 0);
    observed("complete_65536_group_status_finds_final_gid_without_truncation");
    char fake[] = "/tmp/axiom-proc-missing-XXXXXX", fake_proc[96];
    CHECK(mkdtemp(fake));
    snprintf(fake_proc, sizeof(fake_proc), "%s/proc", fake);
    CHECK(mkdir(fake_proc, 0555) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(chroot(fake) == 0 && chdir("/") == 0);
        CHECK(account_process_busy(1000, (gid_t)-1) == -1 && errno == ENODEV);
        _exit(0);
    }
    reap(child);
    CHECK(rmdir(fake_proc) == 0 && rmdir(fake) == 0);
    observed("missing_real_procfs_fails_closed_in_account_process_guard");
    puts("PROC_PASS observations=8");
    return 0;
}
