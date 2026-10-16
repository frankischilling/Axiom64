// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
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

int main(int argc, char** argv) {
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
    printf("EXEC_ARGUMENTS_PASS observations=%u\n", observations);
    return 0;
}
