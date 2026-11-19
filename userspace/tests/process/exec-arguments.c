// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/process/exec-arguments.c
 * @brief   Exec argument ABI test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks argument and environment transfer and errors at the userspace
 * boundary.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "EXEC_ARGUMENTS_FAIL line=%d errno=%d check=%s\n", __LINE__, errno,    \
                    #expression);                                                                  \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

enum { string_limit = 131072, aggregate_limit = 6 * 1024 * 1024 };

static const char* executable;
static unsigned observations;
static volatile sig_atomic_t signal_received;
extern char** environ;

static void observed(const char* name) {
    printf("EXEC_ARGUMENTS_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static void signal_action(int number) {
    signal_received = number;
}

static void filled(const char* value, size_t length, char byte) {
    CHECK(strlen(value) == length);
    for (size_t i = 0; i < length; i++)
        CHECK(value[i] == byte);
}

static int verify(int argc, char** argv) {
    if (getenv("EMPTY_ARGV_EXPECTED")) {
        CHECK(argc == 1 && argv[0] && !*argv[0] && !argv[1]);
        return 73;
    }
    CHECK(argc >= 6 && !strcmp(argv[1], "--verify"));
    int wanted = atoi(argv[2]), envc = atoi(argv[3]);
    size_t length = (size_t)strtoul(argv[5], NULL, 10);
    CHECK(argc == wanted && !argv[argc]);
    size_t count = 0;
    while (environ[count])
        count++;
    CHECK(count == (size_t)envc && environ == argv + argc + 1);
    CHECK(((uintptr_t)argv - sizeof(uintptr_t)) % 16 == 0);
    CHECK(getauxval(AT_PAGESZ) == 4096 && getauxval(AT_CLKTCK) == 100);
    CHECK(getauxval(AT_PHDR) && getauxval(AT_PHNUM) && getauxval(AT_ENTRY));
    CHECK(getauxval(AT_UID) == getuid() && getauxval(AT_EUID) == geteuid());
    CHECK(getauxval(AT_GID) == getgid() && getauxval(AT_EGID) == getegid());
    CHECK(!strcmp((const char*)getauxval(AT_PLATFORM), "x86_64"));
    CHECK(getauxval(AT_EXECFN) && *(const char*)getauxval(AT_EXECFN));
    const unsigned char* random = (const unsigned char*)getauxval(AT_RANDOM);
    unsigned present = 0;
    for (size_t i = 0; i < 16; i++)
        present |= random[i];
    CHECK(present);
    if (!strcmp(argv[4], "environment")) {
        CHECK(envc == 1 && !strncmp(environ[0], "P=", 2));
        filled(environ[0] + 2, length - 2, 'v');
    } else if (!strcmp(argv[4], "many")) {
        for (int i = 6; i < argc; i++)
            CHECK(!*argv[i]);
        for (size_t i = 0; i < count; i++)
            CHECK(!strcmp(environ[i], "V=a"));
    } else
        for (int i = 6; i < argc; i++)
            filled(argv[i], length, 'a');
    return 73;
}

static void child_status(pid_t pid) {
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 73);
}

struct worker {
    atomic_uint stop, cycles;
};

static void* worker(void* opaque) {
    struct worker* state = opaque;
    while (!atomic_load(&state->stop)) {
        atomic_fetch_add(&state->cycles, 1);
        sched_yield();
    }
    return NULL;
}

static void worker_progress(struct worker* state, unsigned before) {
    for (unsigned attempt = 0; attempt < 10000; attempt++) {
        if (atomic_load(&state->cycles) != before)
            return;
        sched_yield();
    }
    CHECK(atomic_load(&state->cycles) != before);
}

static void success(size_t length, size_t payloads, size_t envc, const char* mode) {
    size_t argc = 6 + payloads;
    char** argv = calloc(argc + 1, sizeof(*argv));
    char** env = calloc(envc + 1, sizeof(*env));
    char* text = malloc(length + 1);
    char count[32], environment_count[32], size[32];
    CHECK(argv && env && text);
    memset(text, !strcmp(mode, "environment") ? 'v' : 'a', length);
    text[length] = 0;
    snprintf(count, sizeof(count), "%zu", argc);
    snprintf(environment_count, sizeof(environment_count), "%zu", envc);
    snprintf(size, sizeof(size), "%zu", length);
    argv[0] = "exec-arguments";
    argv[1] = "--verify";
    argv[2] = count;
    argv[3] = environment_count;
    argv[4] = (char*)mode;
    argv[5] = size;
    for (size_t i = 6; i < argc; i++)
        argv[i] = text;
    for (size_t i = 0; i < envc; i++)
        env[i] = "V=a";
    char* environment = NULL;
    if (!strcmp(mode, "environment")) {
        CHECK(length >= 2 && envc == 1);
        environment = malloc(length + 1);
        CHECK(environment);
        memcpy(environment, "P=", 2);
        memset(environment + 2, 'v', length - 2);
        environment[length] = 0;
        env[0] = environment;
    }
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (!pid) {
        syscall(SYS_execve, executable, argv, env);
        perror("exec-arguments successful exec");
        _exit(99);
    }
    child_status(pid);
    free(environment);
    free(text);
    free(env);
    free(argv);
}

static void failed(const char* const* argv, const char* const* env, int error) {
    uint64_t stack_marker = UINT64_C(0x52455441494e4544);
    char* heap = malloc(4096);
    CHECK(heap);
    memset(heap, 0x57, 4096);
    int channel[2];
    CHECK(pipe2(channel, O_CLOEXEC) == 0);
    uid_t real, effective, saved;
    gid_t group_real, group_effective, group_saved;
    CHECK(getresuid(&real, &effective, &saved) == 0 &&
          getresgid(&group_real, &group_effective, &group_saved) == 0);
    struct sigaction action = {.sa_handler = signal_action}, previous;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, &previous) == 0);
    struct worker state;
    atomic_init(&state.stop, 0);
    atomic_init(&state.cycles, 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, worker, &state) == 0);
    worker_progress(&state, 0);
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        unsigned before = atomic_load(&state.cycles);
        errno = 0;
        CHECK(syscall(SYS_execve, executable, argv, env) == -1 && errno == error);
        worker_progress(&state, before);
        CHECK(stack_marker == UINT64_C(0x52455441494e4544));
        for (size_t i = 0; i < 4096; i++)
            CHECK((unsigned char)heap[i] == 0x57);
        CHECK(getuid() == real && geteuid() == effective && getgid() == group_real &&
              getegid() == group_effective);
        uid_t after_real, after_effective, after_saved;
        gid_t after_group_real, after_group_effective, after_group_saved;
        CHECK(getresuid(&after_real, &after_effective, &after_saved) == 0 &&
              getresgid(&after_group_real, &after_group_effective, &after_group_saved) == 0);
        CHECK(after_saved == saved && after_group_saved == group_saved);
        CHECK(fcntl(channel[0], F_GETFD) == FD_CLOEXEC && fcntl(channel[1], F_GETFD) == FD_CLOEXEC);
        CHECK(write(channel[1], "x", 1) == 1);
        char byte = 0;
        CHECK(read(channel[0], &byte, 1) == 1 && byte == 'x');
        signal_received = 0;
        CHECK(raise(SIGUSR1) == 0 && signal_received == SIGUSR1);
    }
    atomic_store(&state.stop, 1);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
    close(channel[0]);
    close(channel[1]);
    free(heap);
}

static void negative_strings(void) {
    char* text = malloc(string_limit + 1);
    CHECK(text);
    memset(text, 'a', string_limit);
    text[string_limit] = 0;
    const char* argv[] = {"probe", text, NULL};
    const char* env[] = {text, NULL};
    const char* valid[] = {"probe", NULL};
    failed(argv, NULL, E2BIG);
    failed(valid, env, E2BIG);
    free(text);
    observed("per_string_arg_and_environment_e2big_preserve_old_space_ids_fds_signals");
}

static void negative_pointers(void) {
    const char* valid[] = {"probe", NULL};
    const char* bad[] = {(const char*)1, NULL};
    failed((const char* const*)(uintptr_t)(UINTPTR_MAX - 3), NULL, EFAULT);
    failed(valid, (const char* const*)(uintptr_t)(UINTPTR_MAX - 3), EFAULT);
    failed(bad, NULL, EFAULT);
    failed(valid, bad, EFAULT);
    char* pages = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED && mprotect(pages + 4096, 4096, PROT_NONE) == 0);
    memset(pages + 4096 - 7, 'a', 7);
    const char* crossing[] = {pages + 4096 - 7, NULL};
    failed(crossing, NULL, EFAULT);
    const char** vector = (const char**)(pages + 4096 - sizeof(char*));
    *vector = "probe";
    failed(vector, NULL, EFAULT);
    CHECK(munmap(pages, 8192) == 0);
    observed("unmapped_vectors_strings_cross_page_and_pointer_wrap_efault_preserve_process");
}

static void aggregate(void) {
    success(string_limit - 1, 47, 0, "aggregate");
    char* text = malloc(string_limit);
    CHECK(text);
    memset(text, 'a', string_limit - 1);
    text[string_limit - 1] = 0;
    const char* argv[49];
    for (size_t i = 0; i < 48; i++)
        argv[i] = text;
    argv[48] = NULL;
    failed(argv, NULL, E2BIG);
    const char** many = calloc(700001, sizeof(*many));
    CHECK(many);
    for (size_t i = 0; i < 700000; i++)
        many[i] = "";
    failed(many, NULL, E2BIG);
    free(many);
    free(text);
    observed("six_mib_combined_argument_pointer_budget_acceptance_and_overflow_denial");
}

static void copy_executable(int destination) {
    int source = open(executable, O_RDONLY | O_CLOEXEC);
    CHECK(source >= 0);
    char buffer[8192];
    for (;;) {
        ssize_t length = read(source, buffer, sizeof(buffer));
        CHECK(length >= 0);
        if (!length)
            break;
        size_t written = 0;
        while (written < (size_t)length) {
            ssize_t count = write(destination, buffer + written, (size_t)length - written);
            CHECK(count > 0);
            written += (size_t)count;
        }
    }
    CHECK(close(source) == 0);
}

static void fd_display(char* output, size_t size, int fd, const char* tail) {
    int length = snprintf(output, size, "/dev/fd/%d%s%s", fd, *tail ? "/" : "", tail);
    CHECK(length > 0 && (size_t)length < size);
}

static int fd_child(int argc, char** argv) {
    CHECK(argc == 7 && !strcmp(argv[0], "argv-zero-kept"));
    CHECK(!strcmp((const char*)getauxval(AT_EXECFN), argv[2]));
    CHECK(getenv("EXEC_FD_ENV") && !strcmp(getenv("EXEC_FD_ENV"), "owned"));
    int gone = atoi(argv[3]);
    if (gone >= 0)
        CHECK(fcntl(gone, F_GETFD) == -1 && errno == EBADF);
    int ready = atoi(argv[4]), resume = atoi(argv[5]);
    if (ready >= 0) {
        char byte;
        CHECK(write(ready, "r", 1) == 1);
        CHECK(read(resume, &byte, 1) == 1 && byte == 'g');
    }
    CHECK((unsigned)getuid() == (unsigned)strtoul(argv[6], NULL, 10));
    return 73;
}

static void replace_from_fd(int fd, const char* path, int flags, char* display, int dropped,
                            int ready, int resume, int use_fexecve) {
    char a[16], b[16], c[16], uid[16];
    CHECK(snprintf(a, sizeof(a), "%d", dropped) > 0);
    CHECK(snprintf(b, sizeof(b), "%d", ready) > 0);
    CHECK(snprintf(c, sizeof(c), "%d", resume) > 0);
    CHECK(snprintf(uid, sizeof(uid), "%u", (unsigned)getuid()) > 0);
    char* args[] = {"argv-zero-kept", "--fd-child", display, a, b, c, uid, NULL};
    char* environment[] = {"EXEC_FD_ENV=owned", NULL};
    if (use_fexecve)
        fexecve(fd, args, environment);
    else
        syscall(SYS_execveat, fd, path, args, environment, flags);
    CHECK(0);
}

static void child_exec_at(int fd, const char* path, int flags, char* display, int dropped) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child)
        replace_from_fd(fd, path, flags, display, dropped, -1, -1, 0);
    child_status(child);
}

static void exec_at_paths(int modern) {
    char directory[] = "/tmp/axiom-execveat-XXXXXX";
    CHECK(mkdtemp(directory));
    char path[sizeof(directory) + 32], alias[sizeof(path)], linkname[sizeof(path)];
    CHECK(snprintf(path, sizeof(path), "%s/program", directory) > 0);
    CHECK(snprintf(alias, sizeof(alias), "%s/alias", directory) > 0);
    CHECK(snprintf(linkname, sizeof(linkname), "%s/symlink", directory) > 0);
    int writer = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0700);
    int dir = open(directory, O_PATH | O_DIRECTORY | O_CLOEXEC);
    CHECK(writer >= 0 && dir >= 0);
    copy_executable(writer);
    CHECK(link(path, alias) == 0 && symlink("program", linkname) == 0);
    int image = open(alias, O_PATH | O_CLOEXEC);
    CHECK(image >= 0);
    char* args[] = {"never-executed", NULL};
    char* environment[] = {NULL};
    CHECK(syscall(SYS_execveat, image, "", args, environment, AT_EMPTY_PATH) == -1 &&
          errno == ETXTBSY);
    CHECK(close(writer) == 0);

    CHECK(syscall(SYS_execveat, -1, "program", args, environment, 0) == -1 && errno == EBADF);
    CHECK(syscall(SYS_execveat, dir, (void*)(uintptr_t)1, args, environment, 0) == -1 &&
          errno == EFAULT);
    CHECK(syscall(SYS_execveat, image, "", args, environment, 0) == -1 && errno == ENOENT);
    CHECK(syscall(SYS_execveat, dir, "", args, environment, AT_EMPTY_PATH) == -1 &&
          errno == EACCES);
    CHECK(syscall(SYS_execveat, image, "program", args, environment, 0) == -1 && errno == ENOTDIR);
    CHECK(syscall(SYS_execveat, dir, "program", args, environment, 0x4000) == -1 &&
          errno == EINVAL);
    CHECK(syscall(SYS_execveat, dir, "symlink", args, environment, AT_SYMLINK_NOFOLLOW) == -1 &&
          errno == ELOOP);
    int symlink_fd = open(linkname, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    CHECK(symlink_fd >= 0);
    CHECK(syscall(SYS_execveat, symlink_fd, "", args, environment, AT_EMPTY_PATH) == -1 &&
          errno == ELOOP);
    CHECK(close(symlink_fd) == 0);
    observed("execveat_argument_errors_and_writer_conflict");

    char display[sizeof(path) + 32];
    fd_display(display, sizeof(display), dir, "symlink");
    child_exec_at(dir, "symlink", 0, display, dir);
    child_exec_at(-1, path, 0, path, -1);
    fd_display(display, sizeof(display), image, "");
    child_exec_at(image, "", AT_EMPTY_PATH, display, image);
    observed("execveat_directory_relative_absolute_and_path_descriptor");

    // The executing inode stays deny-write until its last executing process exits.
    int ready[2], resume[2];
    CHECK(pipe(ready) == 0 && pipe(resume) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child)
        replace_from_fd(image, "", AT_EMPTY_PATH, display, image, ready[1], resume[0], 0);
    CHECK(close(ready[1]) == 0 && close(resume[0]) == 0);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && byte == 'r');
    CHECK(open(path, O_WRONLY) == -1 && errno == ETXTBSY);
    CHECK(open(alias, O_RDONLY | O_TRUNC) == -1 && errno == ETXTBSY);
    CHECK(truncate(alias, 0) == -1 && errno == ETXTBSY);
    CHECK(write(resume[1], "g", 1) == 1);
    child_status(child);
    CHECK(close(resume[1]) == 0 && close(ready[0]) == 0);
    writer = open(path, O_WRONLY);
    CHECK(writer >= 0 && close(writer) == 0);
    CHECK(unlink(path) == 0 && unlink(alias) == 0 && unlink(linkname) == 0);
    child_exec_at(image, "", AT_EMPTY_PATH, display, image);
    CHECK(close(image) == 0 && close(dir) == 0);
    observed("execveat_unlinked_inode_and_running_image_writer_exclusion");

    CHECK(mount("none", directory, "ramfs", MS_NOEXEC, NULL) == 0);
    writer = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0700);
    CHECK(writer >= 0);
    copy_executable(writer);
    CHECK(close(writer) == 0);
    image = open(path, O_PATH | O_CLOEXEC);
    CHECK(image >= 0);
    CHECK(syscall(SYS_execveat, image, "", args, environment, AT_EMPTY_PATH) == -1 &&
          errno == EACCES);
    CHECK(close(image) == 0 && unlink(path) == 0);
    CHECK(umount(directory) == 0 && rmdir(directory) == 0);

    image = memfd_create("format-check", MFD_CLOEXEC);
    CHECK(image >= 0);
    CHECK(syscall(SYS_execveat, image, "", args, environment, AT_EMPTY_PATH) == -1 &&
          errno == ENOEXEC);
    int flags = AT_EMPTY_PATH | 0x10000;
    if (modern) {
        CHECK(syscall(SYS_execveat, image, "", args, environment, flags) == 0);
        CHECK(syscall(SYS_execveat, image, "", (void*)(uintptr_t)1, environment, flags) == -1 &&
              errno == EFAULT);
        CHECK(fchmod(image, 0600) == 0);
        CHECK(syscall(SYS_execveat, image, "", args, environment, flags) == -1 && errno == EACCES);
    } else
        CHECK(syscall(SYS_execveat, image, "", args, environment, flags) == -1 && errno == EINVAL);
    CHECK(fcntl(image, F_GETFD) == FD_CLOEXEC && close(image) == 0);
    observed("execveat_permission_only_check_and_failed_exec_descriptor_state");
}

static void memfd_exec(void) {
    for (unsigned identity = 0; identity < 2; ++identity) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            if (identity)
                CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
            int image = memfd_create("compiler-output", MFD_CLOEXEC | MFD_ALLOW_SEALING);
            CHECK(image >= 0);
            copy_executable(image);
            CHECK(fchmod(image, 0600) == 0);
            char* args[] = {"never-executed", NULL};
            CHECK(syscall(SYS_execveat, image, "", args, NULL, AT_EMPTY_PATH) == -1 &&
                  errno == EACCES);
            CHECK(fchmod(image, 0755) == 0);
            CHECK(fcntl(image, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW) == 0);
            char display[48];
            fd_display(display, sizeof(display), image, "");
            replace_from_fd(image, "", AT_EMPTY_PATH, display, image, -1, -1, 1);
        }
        child_status(child);
    }
    observed("libc_fexecve_runs_sealed_memfd_as_root_and_ordinary_user");
}

static int script_child(int argc, char** argv) {
    const char* name = getenv("SCRIPT_NAME");
    const char* option = getenv("SCRIPT_OPTION");
    const char* inner = getenv("SCRIPT_INNER");
    CHECK(!strcmp(name, (const char*)getauxval(AT_EXECFN)));
    CHECK(!strcmp(argv[0], getenv("SCRIPT_INTERPRETER")));
    CHECK(argc == 3 + (option != NULL) + (inner ? 2 : 0));
    int next = 1;
    if (inner) {
        CHECK(!strcmp(argv[next++], "inner"));
        CHECK(!strcmp(argv[next++], inner));
    }
    if (option)
        CHECK(!strcmp(argv[next++], option));
    CHECK(!strcmp(argv[next++], name) && !strcmp(argv[next], "original argument"));
    CHECK(geteuid() == (uid_t)atoi(getenv("SCRIPT_UID")));
    int fd = open(name, O_RDONLY | O_CLOEXEC);
    char prefix[2];
    CHECK(fd >= 0 && read(fd, prefix, sizeof(prefix)) == sizeof(prefix) &&
          !memcmp(prefix, "#!", sizeof(prefix)) && close(fd) == 0);
    return 73;
}

static void script_run(const char* path, const char* name, const char* option, const char* inner,
                       int fd, int flags, int ordinary) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        if (ordinary)
            CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
        CHECK(setenv("SCRIPT_UID", ordinary ? "65534" : "0", 1) == 0 &&
              setenv("SCRIPT_NAME", name, 1) == 0 &&
              setenv("SCRIPT_INTERPRETER", executable, 1) == 0);
        if (option)
            CHECK(setenv("SCRIPT_OPTION", option, 1) == 0);
        if (inner)
            CHECK(setenv("SCRIPT_INNER", inner, 1) == 0);
        char* args[] = {"discarded", "original argument", NULL};
        if (fd == -1)
            syscall(SYS_execve, path, args, environ);
        else
            syscall(SYS_execveat, fd, path, args, environ, flags);
        CHECK(0);
    }
    child_status(child);
}

static void write_script(int fd, const char* text) {
    CHECK(fd >= 0 && write(fd, text, strlen(text)) == (ssize_t)strlen(text));
}

static void script_file(const char* path, const char* contents, mode_t mode) {
    int fd = open(path, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0600);
    write_script(fd, contents);
    CHECK(fchmod(fd, mode) == 0 && close(fd) == 0);
}

static void interpreter_scripts(int modern) {
    char directory[] = "/tmp/axiom-script-XXXXXX";
    CHECK(mkdtemp(directory) && chmod(directory, 0755) == 0);
    char outer[128], inner[128], line[1024];
    CHECK(snprintf(outer, sizeof(outer), "%s/outer", directory) > 0);
    CHECK(snprintf(inner, sizeof(inner), "%s/inner", directory) > 0);
    CHECK(snprintf(line, sizeof(line), "#! \t %s\t  one \t option   \t\nbody\n", executable) > 0);
    script_file(outer, line, 04755);
    script_run(outer, outer, "one \t option", NULL, -1, 0, 0);
    script_run(outer, outer, "one \t option", NULL, -1, 0, 1);
    CHECK(snprintf(line, sizeof(line), "#!%s inner\n", executable) > 0);
    script_file(inner, line, 0755);
    CHECK(snprintf(line, sizeof(line), "#!%s outer\n", inner) > 0);
    script_file(outer, line, 0755);
    script_run(outer, outer, "outer", inner, -1, 0, 0);
    CHECK(snprintf(line, sizeof(line), "#!%s", executable) > 0);
    script_file(inner, line, 0755);
    script_run(inner, inner, NULL, NULL, -1, 0, 0);
    int start = snprintf(line, sizeof(line), "#!%s ", executable);
    CHECK(start > 0 && start < 255);
    memset(line + start, 'z', 300);
    line[start + 300] = 0;
    script_file(inner, line, 0755);
    char truncated[256];
    memset(truncated, 'z', (size_t)(255 - start));
    truncated[255 - start] = 0;
    script_run(inner, inner, truncated, NULL, -1, 0, 0);
    const char* shell_script =
        access("/bin/busybox", X_OK) == 0 ? "#!/bin/busybox sh\nexit 73\n" : "#!/bin/sh\nexit 73\n";
    script_file(inner, shell_script, 0755);
    pid_t shell = fork();
    CHECK(shell >= 0);
    if (!shell) {
        char* shell_args[] = {inner, NULL};
        syscall(SYS_execve, inner, shell_args, environ);
        CHECK(0);
    }
    child_status(shell);
    observed("shebang_literal_option_nested_arguments_bounds_and_credentials");

    char* args[] = {"unreachable", NULL};
    CHECK(snprintf(line, sizeof(line), "#!%s\n", outer) > 0);
    script_file(outer, line, 0755);
    CHECK(syscall(SYS_execve, outer, args, NULL) == -1 && errno == ELOOP);
    script_file(outer, "#! \t\n", 0755);
    CHECK(syscall(SYS_execve, outer, args, NULL) == -1 && errno == ENOEXEC);
    memset(line, 'a', 256);
    line[0] = '#';
    line[1] = '!';
    line[256] = 0;
    script_file(outer, line, 0755);
    CHECK(syscall(SYS_execve, outer, args, NULL) == -1 && errno == ENOEXEC);
    CHECK(snprintf(line, sizeof(line), "#!%s\r\n", executable) > 0);
    script_file(outer, line, 0755);
    CHECK(syscall(SYS_execve, outer, args, NULL) == -1 && errno == ENOENT);
    script_file(outer, line, 0600);
    CHECK(syscall(SYS_execve, outer, args, NULL) == -1 && errno == EACCES);
    observed("shebang_format_recursion_and_interpreter_errors");

    CHECK(snprintf(line, sizeof(line), "#!%s\n", executable) > 0);
    script_file(outer, line, 0755);
    int dir = open(directory, O_PATH | O_DIRECTORY | O_CLOEXEC);
    int file = open(outer, O_RDONLY | O_CLOEXEC);
    CHECK(dir >= 0 && file >= 0);
    CHECK(syscall(SYS_execveat, dir, "outer", args, NULL, 0) == -1 && errno == ENOENT);
    CHECK(syscall(SYS_execveat, file, "", args, NULL, AT_EMPTY_PATH) == -1 && errno == ENOENT);
    if (modern)
        CHECK(syscall(SYS_execveat, file, "", args, NULL, AT_EMPTY_PATH | 0x10000) == 0);
    CHECK(fcntl(dir, F_SETFD, 0) == 0 && fcntl(file, F_SETFD, 0) == 0);
    char display[128];
    fd_display(display, sizeof(display), dir, "outer");
    script_run("outer", display, NULL, NULL, dir, 0, 0);
    CHECK(unlink(outer) == 0);
    fd_display(display, sizeof(display), file, "");
    script_run("", display, NULL, NULL, file, AT_EMPTY_PATH, 0);
    CHECK(close(file) == 0 && close(dir) == 0 && unlink(inner) == 0 && rmdir(directory) == 0);
    observed("shebang_execveat_dirfd_unlinked_file_and_cloexec");

    file = memfd_create("interpreter-script", MFD_ALLOW_SEALING);
    write_script(file, line);
    CHECK(fchmod(file, 0755) == 0);
    CHECK(fcntl(file, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK) == 0);
    fd_display(display, sizeof(display), file, "");
    script_run("", display, NULL, NULL, file, AT_EMPTY_PATH, 0);
    char buffer[256];
    const char label[] = "/memfd:interpreter-script (deleted)";
    CHECK(readlink(display, buffer, sizeof(buffer)) == sizeof(label) - 1 &&
          !memcmp(buffer, label, sizeof(label) - 1));
    int reopened = open(display, O_RDONLY | O_CLOEXEC);
    CHECK(reopened >= 0 && lseek(reopened, 0, SEEK_CUR) == 0 && close(file) == 0);
    CHECK(read(reopened, buffer, sizeof(buffer)) == (ssize_t)strlen(line) &&
          !memcmp(buffer, line, strlen(line)) && close(reopened) == 0);
    observed("shebang_sealed_memfd_and_independent_reopen_lifetime");
}

static void proc_descriptor_links(void) {
    char file[] = "/tmp/axiom-procfd-XXXXXX";
    int fd = mkstemp(file);
    CHECK(fd >= 0);
    char name[16], link[64], target[256];
    CHECK(snprintf(name, sizeof(name), "%d", fd) > 0);
    CHECK(snprintf(link, sizeof(link), "/proc/self/fd/%d", fd) > 0);
    CHECK(readlink(link, target, sizeof(target)) == (ssize_t)strlen(file) &&
          !memcmp(target, file, strlen(file)));
    struct stat first, second;
    CHECK(fstat(fd, &first) == 0 && stat(link, &second) == 0 && first.st_dev == second.st_dev &&
          first.st_ino == second.st_ino);
    CHECK(lstat(link, &second) == 0 && S_ISLNK(second.st_mode) && (second.st_mode & 0777) == 0700);
    DIR* directory = opendir("/proc/thread-self/fd");
    CHECK(directory);
    struct dirent* entry;
    while ((entry = readdir(directory)) && strcmp(entry->d_name, name)) {
    }
    CHECK(entry && entry->d_type == DT_LNK && closedir(directory) == 0);
    CHECK(open(link, O_NOFOLLOW | O_RDONLY) == -1 && errno == ELOOP);
    int saved = open(link, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    CHECK(saved >= 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(snprintf(link, sizeof(link), "/proc/%d/fd/%d", getppid(), fd) > 0);
        CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
        CHECK(readlink(link, target, sizeof(target)) == -1 && errno == EACCES);
        fd_display(link, sizeof(link), fd, "");
        CHECK(readlink(link, target, sizeof(target)) == (ssize_t)strlen(file));
        CHECK(open(link, O_RDONLY) == -1 && errno == EACCES);
        _exit(73);
    }
    child_status(child);
    CHECK(close(fd) == 0 && unlink(file) == 0);
    CHECK(readlinkat(saved, "", target, sizeof(target)) == -1 && errno == ENOENT);
    CHECK(fstat(saved, &second) == 0 && (second.st_mode & 0777) == 0700);
    int replacement = open("/dev/null", O_RDONLY);
    CHECK(replacement == fd);
    CHECK(readlinkat(saved, "", target, sizeof(target)) == 9 && !memcmp(target, "/dev/null", 9));
    CHECK(lstat(link, &second) == 0 && (second.st_mode & 0777) == 0500);
    CHECK(fstat(saved, &second) == 0 && (second.st_mode & 0777) == 0500);
    CHECK(close(replacement) == 0 && close(saved) == 0);
    observed("proc_fd_magic_links_follow_list_reuse_and_restrict_credentials");
}

static void expect_link(const char* path, const char* target) {
    char buffer[128];
    CHECK(readlink(path, buffer, sizeof(buffer)) == (ssize_t)strlen(target));
    CHECK(!memcmp(buffer, target, strlen(target)));
}

static void same_descriptor_inode(int fd, const char* path, uint64_t filesystem) {
    struct stat original, linked;
    struct statfs mount;
    CHECK(fstat(fd, &original) == 0 && stat(path, &linked) == 0);
    CHECK(original.st_ino && linked.st_ino == original.st_ino && linked.st_dev == original.st_dev &&
          linked.st_mode == original.st_mode);
    CHECK(fstatfs(fd, &mount) == 0 && (uint64_t)mount.f_type == filesystem);
    CHECK(statfs(path, &mount) == 0 && (uint64_t)mount.f_type == filesystem);
}

static void anonymous_pipe_links(void) {
    int ends[2];
    CHECK(pipe2(ends, O_CLOEXEC) == 0);
    char reader[64], writer[64], label[64], path[64];
    fd_display(reader, sizeof(reader), ends[0], "");
    fd_display(writer, sizeof(writer), ends[1], "");
    struct stat info;
    CHECK(fstat(ends[0], &info) == 0 && S_ISFIFO(info.st_mode));
    CHECK(snprintf(label, sizeof(label), "pipe:[%llu]", (unsigned long long)info.st_ino) > 0);
    expect_link(reader, label);
    expect_link(writer, label);
    same_descriptor_inode(ends[0], writer, 0x50495045);
    same_descriptor_inode(ends[1], reader, 0x50495045);
    int duplicate = open(reader, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    CHECK(duplicate >= 0 && (fcntl(duplicate, F_GETFL) & O_NONBLOCK));
    CHECK(!(fcntl(ends[0], F_GETFL) & O_NONBLOCK));
    char data;
    CHECK(read(duplicate, &data, 1) == -1 && errno == EAGAIN);
    CHECK(write(ends[1], "s", 1) == 1);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(dup2(ends[0], STDIN_FILENO) == STDIN_FILENO);
        int input = open("/dev/stdin", O_RDONLY);
        CHECK(input >= 0 && read(input, &data, 1) == 1 && data == 's');
        _exit(73);
    }
    child_status(child);
    int anchor = open(writer, O_PATH | O_CLOEXEC);
    CHECK(anchor >= 0);
    fd_display(path, sizeof(path), anchor, "");
    expect_link(path, label);
    CHECK(close(duplicate) == 0 && close(ends[0]) == 0);
    int alone = open(writer, O_WRONLY | O_NONBLOCK);
    CHECK(alone >= 0 && close(alone) == 0);
    CHECK(close(ends[1]) == 0);
    alone = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(alone >= 0 && read(alone, &data, 1) == 0 && close(alone) == 0);
    int both = open(path, O_RDWR | O_CLOEXEC);
    CHECK(both >= 0 && close(anchor) == 0);
    CHECK(write(both, "n", 1) == 1 && read(both, &data, 1) == 1 && data == 'n');
    CHECK(fstat(both, &info) == 0 && S_ISFIFO(info.st_mode) && close(both) == 0);
    observed("proc_pipe_links_reopen_live_endpoints_and_retain_inode_without_peers");
}

static void anonymous_object_links(void) {
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    char path[64], label[64];
    struct stat socket_info, retained;
    CHECK(fstat(pair[0], &socket_info) == 0 && S_ISSOCK(socket_info.st_mode));
    fd_display(path, sizeof(path), pair[0], "");
    CHECK(snprintf(label, sizeof(label), "socket:[%llu]", (unsigned long long)socket_info.st_ino) >
          0);
    expect_link(path, label);
    same_descriptor_inode(pair[0], path, 0x534f434b);
    CHECK(open(path, O_RDONLY | O_NONBLOCK) == -1 && errno == ENXIO);
    int anchor = open(path, O_PATH | O_CLOEXEC);
    CHECK(anchor >= 0 && close(pair[0]) == 0);
    char data;
    CHECK(read(pair[1], &data, 1) == 0 && close(pair[1]) == 0);
    CHECK(fstat(anchor, &retained) == 0 && retained.st_ino == socket_info.st_ino &&
          retained.st_dev == socket_info.st_dev && S_ISSOCK(retained.st_mode));
    fd_display(path, sizeof(path), anchor, "");
    expect_link(path, label);
    CHECK(close(anchor) == 0);

    sigset_t signals;
    CHECK(sigemptyset(&signals) == 0 && sigaddset(&signals, SIGUSR1) == 0);
    int descriptors[] = {epoll_create1(EPOLL_CLOEXEC), eventfd(2, EFD_CLOEXEC),
                         timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC),
                         signalfd(-1, &signals, SFD_CLOEXEC), inotify_init1(IN_CLOEXEC)};
    const char* targets[] = {"anon_inode:[eventpoll]", "anon_inode:[eventfd]",
                             "anon_inode:[timerfd]", "anon_inode:[signalfd]", "anon_inode:inotify"};
    struct stat shared;
    CHECK(fstat(descriptors[0], &shared) == 0);
    for (unsigned i = 0; i < sizeof(descriptors) / sizeof(*descriptors); i++) {
        int fd = descriptors[i];
        CHECK(fd >= 0);
        fd_display(path, sizeof(path), fd, "");
        expect_link(path, targets[i]);
        same_descriptor_inode(fd, path, 0x09041934);
        CHECK(open(path, O_RDWR | O_NONBLOCK) == -1 && errno == ENXIO);
        anchor = open(path, O_PATH | O_CLOEXEC);
        CHECK(anchor >= 0 && close(fd) == 0);
        CHECK(fstat(anchor, &retained) == 0 && retained.st_ino == shared.st_ino &&
              retained.st_dev == shared.st_dev && (retained.st_mode & S_IFMT) == 0);
        fd_display(path, sizeof(path), anchor, "");
        expect_link(path, targets[i]);
        CHECK(close(anchor) == 0);
    }
    observed("proc_anonymous_object_links_supply_metadata_without_reopening_events_or_sockets");
}

int main(int argc, char** argv) {
    if (getenv("SCRIPT_NAME"))
        return script_child(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "--fd-child"))
        return fd_child(argc, argv);
    if (getenv("EMPTY_ARGV_EXPECTED") || (argc > 1 && !strcmp(argv[1], "--verify")))
        return verify(argc, argv);
    executable = argv[0];
    struct rlimit limit = {RLIM_INFINITY, RLIM_INFINITY};
    CHECK(setrlimit(RLIMIT_STACK, &limit) == 0);
    success(1023, 1, 0, "argument");
    success(1024, 1, 0, "argument");
    success(1054, 1, 0, "argument");
    success(4096, 1, 0, "argument");
    observed("actual_reexec_exact_argument_bytes_across_former_1024_byte_limit");
    success(string_limit - 1, 1, 0, "argument");
    observed("actual_reexec_131071_argument_bytes_plus_terminating_nul");
    success(string_limit - 1, 0, 1, "environment");
    observed("actual_reexec_131071_environment_bytes_plus_terminating_nul");
    success(0, 2048 - 6, 0, "many");
    success(0, 0, 2048, "many");
    observed("actual_reexec_2048_argument_and_environment_entries");
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        char* env[] = {"EMPTY_ARGV_EXPECTED=1", NULL};
        syscall(SYS_execve, executable, NULL, env);
        _exit(99);
    }
    child_status(child);
    observed("null_argument_vector_normalizes_to_one_empty_argument");
    negative_strings();
    negative_pointers();
    aggregate();
    observed("successful_reexec_initial_stack_alignment_auxiliary_vectors_and_owned_string_bytes");
    int modern = argc == 1 || strcmp(argv[1], "--legacy-execveat");
    exec_at_paths(modern);
    memfd_exec();
    interpreter_scripts(modern);
    proc_descriptor_links();
    anonymous_pipe_links();
    anonymous_object_links();
    printf("EXEC_ARGUMENTS_PASS observations=%u\n", observations);
    return 0;
}
