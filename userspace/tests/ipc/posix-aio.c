// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file
 */
#define _GNU_SOURCE
#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "POSIX_AIO_FAIL line=%d %s errno=%d\n", __LINE__, #condition, errno);  \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static const struct timespec timeout = {.tv_sec = 3};
static const struct timespec short_wait = {.tv_nsec = 100000000};

static struct aiocb request(int fd, int operation, void* buffer, size_t length, off_t offset) {
    return (struct aiocb){
        .aio_fildes = fd,
        .aio_lio_opcode = operation,
        .aio_buf = buffer,
        .aio_nbytes = length,
        .aio_offset = offset,
        .aio_sigevent.sigev_notify = SIGEV_NONE,
    };
}

static void finish(struct aiocb* control, int error, ssize_t count) {
    const struct aiocb* list[] = {control};
    while (aio_error(control) == EINPROGRESS)
        CHECK(aio_suspend(list, 1, &timeout) == 0 || errno == EINTR);
    CHECK(aio_error(control) == error);
    CHECK(aio_return(control) == count);
}

static void require_pending(struct aiocb* control) {
    const struct aiocb* list[] = {NULL, control};
    CHECK(aio_error(control) == EINPROGRESS);
    CHECK(aio_suspend(list, 2, &short_wait) == -1 && errno == EAGAIN);
    CHECK(aio_error(control) == EINPROGRESS);
}

static void positioned_io(int fd, const char* executable) {
    char bytes[] = "0123456789";
    char result[sizeof(bytes) - 1] = {0};
    struct aiocb store = request(fd, LIO_WRITE, bytes, sizeof(result), 0);
    struct aiocb fetch = request(fd, LIO_READ, result, 4, 3);
    CHECK(lseek(fd, 120, SEEK_SET) == 120);
    CHECK(aio_write(&store) == 0);
    finish(&store, 0, sizeof(result));
    CHECK(aio_read(&fetch) == 0);
    finish(&fetch, 0, 4);
    CHECK(memcmp(result, "3456", 4) == 0);
    CHECK(lseek(fd, 0, SEEK_CUR) == 120);

    struct aiocb sync = request(fd, LIO_NOP, NULL, 0, 0);
    CHECK(aio_fsync(0, &sync) == -1 && errno == EINVAL);
    CHECK(aio_fsync(O_SYNC, &sync) == 0);
    finish(&sync, 0, 0);
    sync = request(fd, LIO_NOP, NULL, 0, 0);
    CHECK(aio_fsync(O_DSYNC, &sync) == 0);
    finish(&sync, 0, 0);
    CHECK(pread(fd, result, sizeof(result), 0) == (ssize_t)sizeof(result));
    CHECK(memcmp(result, bytes, sizeof(result)) == 0);

    int readonly = open(executable, O_RDONLY | O_CLOEXEC);
    CHECK(readonly >= 0);
    fetch = request(readonly, LIO_READ, result, 4, 0);
    CHECK(aio_read(&fetch) == 0);
    finish(&fetch, 0, 4);
    CHECK(memcmp(result, "\177ELF", 4) == 0);
    store = request(readonly, LIO_WRITE, bytes, 1, 0);
    fetch = request(fd, LIO_READ, result, 1, 9);
    struct aiocb* mixed[] = {&store, &fetch};
    CHECK(lio_listio(LIO_WAIT, mixed, 2, NULL) == -1 && errno == EIO);
    finish(&store, EBADF, -1);
    finish(&fetch, 0, 1);
    CHECK(result[0] == '9');
    CHECK(close(readonly) == 0);
    puts("POSIX_AIO_CASE positioned-sync-errors");
}

static void block_completion_signal(sigset_t* mask, sigset_t* original) {
    CHECK(sigemptyset(mask) == 0 && sigaddset(mask, SIGUSR1) == 0);
    CHECK(pthread_sigmask(SIG_BLOCK, mask, original) == 0);
}

static struct sigevent completion_signal(int tag) {
    return (struct sigevent){
        .sigev_notify = SIGEV_SIGNAL,
        .sigev_signo = SIGUSR1,
        .sigev_value.sival_int = tag,
    };
}

static void receive_signal(const sigset_t* mask, int tag) {
    siginfo_t info;
    CHECK(sigtimedwait(mask, &info, &timeout) == SIGUSR1);
    CHECK(info.si_code == SI_ASYNCIO && info.si_value.sival_int == tag);
    CHECK(sigtimedwait(mask, &info, &(struct timespec){0}) == -1 && errno == EAGAIN);
}

static void signal_delivery(int fd) {
    sigset_t mask, original;
    block_completion_signal(&mask, &original);
    char byte = 0;
    struct aiocb fetch = request(fd, LIO_READ, &byte, 1, 2);
    fetch.aio_sigevent = completion_signal(73);
    CHECK(aio_read(&fetch) == 0);
    receive_signal(&mask, 73);
    finish(&fetch, 0, 1);
    CHECK(byte == '2');
    CHECK(pthread_sigmask(SIG_SETMASK, &original, NULL) == 0);
    puts("POSIX_AIO_CASE signal");
}

struct notification {
    pthread_t submitter;
    const struct aiocb* first;
    const struct aiocb* second;
    int writer;
    atomic_int calls;
};

static void notify(union sigval value) {
    struct notification* state = value.sival_ptr;
    CHECK(!pthread_equal(pthread_self(), state->submitter));
    CHECK(aio_error(state->first) == 0);
    CHECK(state->second == NULL || aio_error(state->second) == 0);
    CHECK(atomic_fetch_add_explicit(&state->calls, 1, memory_order_relaxed) == 0);
    CHECK(write(state->writer, "!", 1) == 1);
}

static void receive_callback(int reader, const struct notification* state) {
    struct pollfd ready = {.fd = reader, .events = POLLIN};
    char byte = 0;
    CHECK(poll(&ready, 1, 3000) == 1 && (ready.revents & POLLIN));
    CHECK(read(reader, &byte, 1) == 1 && byte == '!');
    CHECK(atomic_load_explicit(&state->calls, memory_order_relaxed) == 1);
    CHECK(poll(&ready, 1, 0) == 0);
}

static void lists_and_callbacks(int fd) {
    char from_file = 0, replacement = 'X', ignored = 'Z';
    struct aiocb fetch = request(fd, LIO_READ, &from_file, 1, 1);
    struct aiocb store = request(fd, LIO_WRITE, &replacement, 1, 8);
    struct aiocb nop = request(fd, LIO_NOP, &ignored, 1, 0);
    struct aiocb* wait[] = {&fetch, NULL, &store, &nop};
    CHECK(lio_listio(LIO_WAIT, wait, 4, NULL) == 0);
    finish(&fetch, 0, 1);
    finish(&store, 0, 1);
    CHECK(from_file == '1' && ignored == 'Z');
    CHECK(pread(fd, &from_file, 1, 0) == 1 && from_file == '0');
    CHECK(pread(fd, &from_file, 1, 8) == 1 && from_file == 'X');

    int data[2], notice[2];
    CHECK(pipe(data) == 0 && pipe(notice) == 0);
    char from_pipe = 0;
    struct aiocb blocked = request(data[0], LIO_READ, &from_pipe, 1, 0);
    fetch = request(fd, LIO_READ, &from_file, 1, 8);
    struct notification group = {
        .submitter = pthread_self(),
        .first = &blocked,
        .second = &fetch,
        .writer = notice[1],
    };
    struct sigevent event = {
        .sigev_notify = SIGEV_THREAD,
        .sigev_notify_function = notify,
        .sigev_value.sival_ptr = &group,
    };
    struct aiocb* nowait[] = {&blocked, NULL, &fetch};
    CHECK(lio_listio(LIO_NOWAIT, nowait, 3, &event) == 0);
    require_pending(&blocked);
    CHECK(poll(&(struct pollfd){.fd = notice[0], .events = POLLIN}, 1, 0) == 0);
    CHECK(write(data[1], "P", 1) == 1);
    receive_callback(notice[0], &group);
    finish(&fetch, 0, 1);
    finish(&blocked, 0, 1);
    CHECK(from_file == 'X' && from_pipe == 'P');

    struct aiocb individual = request(fd, LIO_READ, &from_file, 1, 4);
    struct notification single = {
        .submitter = pthread_self(),
        .first = &individual,
        .writer = notice[1],
    };
    event.sigev_value.sival_ptr = &single;
    individual.aio_sigevent = event;
    CHECK(aio_read(&individual) == 0);
    receive_callback(notice[0], &single);
    finish(&individual, 0, 1);
    CHECK(from_file == '4');
    CHECK(close(data[0]) == 0 && close(data[1]) == 0);
    CHECK(close(notice[0]) == 0 && close(notice[1]) == 0);
    puts("POSIX_AIO_CASE lists-thread");
}

static volatile sig_atomic_t interrupted;

static void mark_interruption(int signal) {
    interrupted = signal;
}

struct interruption {
    pthread_t target;
    atomic_int done;
};

static void* interrupt_wait(void* argument) {
    struct interruption* state = argument;
    while (!atomic_load_explicit(&state->done, memory_order_relaxed)) {
        CHECK(nanosleep(&short_wait, NULL) == 0);
        CHECK(pthread_kill(state->target, SIGUSR2) == 0);
    }
    return NULL;
}

static void require_interruption(struct aiocb* read_op) {
    struct sigaction action = {.sa_handler = mark_interruption}, saved;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR2, &action, &saved) == 0);
    struct interruption state = {.target = pthread_self()};
    pthread_t sender;
    CHECK(pthread_create(&sender, NULL, interrupt_wait, &state) == 0);
    const struct aiocb* list[] = {NULL, read_op};
    CHECK(aio_suspend(list, 2, &timeout) == -1 && errno == EINTR);
    CHECK(interrupted == SIGUSR2 && aio_error(read_op) == EINPROGRESS);
    atomic_store_explicit(&state.done, 1, memory_order_relaxed);
    CHECK(pthread_join(sender, NULL) == 0);
    CHECK(sigaction(SIGUSR2, &saved, NULL) == 0);
}

static void cancel_pipe(void) {
    int tube[2];
    CHECK(pipe(tube) == 0);
    char byte = 0;
    sigset_t mask, original;
    block_completion_signal(&mask, &original);
    struct aiocb read_op = request(tube[0], LIO_READ, &byte, 1, 0);
    read_op.aio_sigevent = completion_signal(74);
    CHECK(aio_read(&read_op) == 0);
    require_pending(&read_op);
    require_interruption(&read_op);
    int cancelled = aio_cancel(tube[0], &read_op);
    if (cancelled == AIO_CANCELED) {
        finish(&read_op, ECANCELED, -1);
        CHECK(byte == 0);
        puts("POSIX_AIO_OUTCOME cancel=cancelled");
    } else {
        CHECK(cancelled == AIO_NOTCANCELED && aio_error(&read_op) == EINPROGRESS);
        CHECK(write(tube[1], "C", 1) == 1);
        finish(&read_op, 0, 1);
        CHECK(byte == 'C');
        puts("POSIX_AIO_OUTCOME cancel=completed");
    }
    receive_signal(&mask, 74);
    CHECK(pthread_sigmask(SIG_SETMASK, &original, NULL) == 0);
    CHECK(aio_cancel(tube[0], NULL) == AIO_ALLDONE);
    CHECK(close(tube[0]) == 0 && close(tube[1]) == 0);
    puts("POSIX_AIO_CASE timeout-interrupt-cancel");
}

static void descriptor_reuse(void) {
    int old[2], next[2];
    CHECK(pipe(old) == 0 && pipe(next) == 0);
    int alias = dup(old[0]);
    CHECK(alias >= 0);
    char original = 0, current = 0;
    struct aiocb read_old = request(old[0], LIO_READ, &original, 1, 0);
    CHECK(aio_read(&read_old) == 0);
    require_pending(&read_old);
    CHECK(close(old[0]) == 0);
    CHECK(dup2(next[0], old[0]) == old[0]);
    struct aiocb read_next = request(old[0], LIO_READ, &current, 1, 0);
    CHECK(aio_read(&read_next) == 0);
    CHECK(write(old[1], "O", 1) == 1 && write(next[1], "N", 1) == 1);
    finish(&read_next, 0, 1);
    CHECK(current == 'N');
    if (aio_error(&read_old) == ECANCELED) {
        finish(&read_old, ECANCELED, -1);
        CHECK(original == 0 && read(alias, &original, 1) == 1 && original == 'O');
        puts("POSIX_AIO_OUTCOME close=cancelled");
    } else {
        finish(&read_old, 0, 1);
        CHECK(original == 'O');
        CHECK(poll(&(struct pollfd){.fd = alias, .events = POLLIN}, 1, 0) == 0);
        puts("POSIX_AIO_OUTCOME close=completed");
    }
    CHECK(close(alias) == 0 && close(old[0]) == 0 && close(old[1]) == 0);
    CHECK(close(next[0]) == 0 && close(next[1]) == 0);
    puts("POSIX_AIO_CASE descriptor-reuse");
}

int main(int argc, char** argv) {
    CHECK(setvbuf(stdout, NULL, _IOLBF, 0) == 0);
    alarm(20);
    if (argc == 2 && strcmp(argv[1], "--ordinary") == 0) {
        CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
    } else {
        CHECK(argc == 1);
    }
    char path[] = "/dev/shm/axiom-posix-aio-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0 && unlink(path) == 0);
    positioned_io(fd, argv[0]);
    signal_delivery(fd);
    lists_and_callbacks(fd);
    CHECK(close(fd) == 0);
    cancel_pipe();
    descriptor_reuse();
    printf("POSIX_AIO_PASS uid=%lu\n", (unsigned long)getuid());
    return 0;
}
