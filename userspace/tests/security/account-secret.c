// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/secret.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "ACCOUNT_SECRET_FAIL line=%d errno=%d expression=%s\n", __LINE__,      \
                    errno, #expression);                                                           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

enum kind { good, empty, overlong, nul, eof, interrupt, terminate, hangup };

static unsigned observations;

static void observed(const char* name) {
    printf("ACCOUNT_SECRET_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static int cleared(const char* data) {
    for (size_t i = 0; i <= ACCOUNT_PASSWORD_MAX; i++)
        if (data[i])
            return 0;
    return 1;
}

static int same_term(const struct termios* first, const struct termios* second) {
    return first->c_iflag == second->c_iflag && first->c_oflag == second->c_oflag &&
           first->c_cflag == second->c_cflag && first->c_lflag == second->c_lflag &&
           memcmp(first->c_cc, second->c_cc, NCCS) == 0 &&
           cfgetispeed(first) == cfgetispeed(second) && cfgetospeed(first) == cfgetospeed(second);
}

static void read_exact(int fd, void* data, size_t size) {
    size_t done = 0;
    while (done < size) {
        struct pollfd item = {fd, POLLIN, 0};
        CHECK(poll(&item, 1, 5000) == 1 && (item.revents & POLLIN));
        ssize_t count = read(fd, (char*)data + done, size - done);
        CHECK(count > 0);
        done += (size_t)count;
    }
}

static void reap(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void run(enum kind kind, const char* name) {
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    CHECK(master >= 0 && grantpt(master) == 0 && unlockpt(master) == 0);
    char path[64];
    CHECK(ptsname_r(master, path, sizeof(path)) == 0);
    int slave = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    CHECK(slave >= 0);
    struct termios before = {0};
    CHECK(tcgetattr(slave, &before) == 0);
    before.c_lflag |= ICANON | ECHO | ECHONL | ISIG;
    before.c_iflag &= ~(IGNCR | INLCR);
    before.c_iflag |= ICRNL;
    before.c_cc[VEOF] = 4;
    CHECK(tcsetattr(slave, TCSANOW, &before) == 0 && tcgetattr(slave, &before) == 0);
    int result[2];
    CHECK(pipe(result) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(master);
        close(result[0]);
        CHECK(setsid() == getpid() && ioctl(slave, TIOCSCTTY, 0) == 0);
        if (kind == hangup)
            CHECK(signal(SIGHUP, SIG_IGN) != SIG_ERR);
        if (kind == good) {
            pid_t background = fork();
            CHECK(background >= 0);
            if (!background) {
                CHECK(setpgid(0, 0) == 0);
                char denied[ACCOUNT_PASSWORD_MAX + 1];
                memset(denied, 'z', sizeof(denied));
                CHECK(account_secret_read(slave, "Background: ", denied) == -1 && errno == ENOTTY);
                CHECK(cleared(denied));
                _exit(0);
            }
            reap(background);
        }
        char secret[ACCOUNT_PASSWORD_MAX + 1];
        memset(secret, 'z', sizeof(secret));
        int status = account_secret_read(slave, "Password: ", secret);
        if (kind == good) {
            CHECK(status == 0 && strlen(secret) == ACCOUNT_PASSWORD_MAX);
            for (size_t i = 0; i < ACCOUNT_PASSWORD_MAX; i++)
                CHECK(secret[i] == 'F');
        } else {
            int expected = kind == overlong ? EMSGSIZE
                           : kind == eof    ? ENODATA
                           : kind == hangup ? ECANCELED
                                            : EINVAL;
            CHECK(status == -1 && errno == expected && cleared(secret));
        }
        account_password_clear(secret, sizeof(secret));
        struct termios after = {0};
        CHECK(tcgetattr(slave, &after) == 0 && same_term(&before, &after));
        char byte = 'x';
        CHECK(write(result[1], &byte, 1) == 1);
        close(slave);
        _exit(0);
    }
    close(result[1]);
    char prompt[10] = {0};
    read_exact(master, prompt, 10);
    CHECK(memcmp(prompt, "Password: ", 10) == 0);
    struct termios hidden = {0};
    CHECK(tcgetattr(slave, &hidden) == 0 && !(hidden.c_lflag & (ECHO | ECHONL)));
    if (kind == good || kind == overlong) {
        char input[ACCOUNT_PASSWORD_MAX + 2];
        size_t size = ACCOUNT_PASSWORD_MAX + (kind == overlong ? 1u : 0u);
        memset(input, 'F', size);
        input[size++] = '\n';
        CHECK(write(master, input, size) == (ssize_t)size);
    } else if (kind == empty)
        CHECK(write(master, "\n", 1) == 1);
    else if (kind == nul) {
        const char input[] = {'a', 0, 'b', '\n'};
        CHECK(write(master, input, sizeof(input)) == sizeof(input));
    } else if (kind == eof)
        CHECK(write(master, "\004", 1) == 1);
    else
        CHECK(kill(child, kind == interrupt ? SIGINT : kind == terminate ? SIGTERM : SIGHUP) == 0);
    int status;
    if (kind == interrupt || kind == terminate) {
        CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
        CHECK(WTERMSIG(status) == (kind == interrupt ? SIGINT : SIGTERM));
    } else {
        char byte;
        read_exact(result[0], &byte, 1);
        CHECK(byte == 'x');
        reap(child);
    }
    struct termios after = {0};
    CHECK(tcgetattr(slave, &after) == 0 && same_term(&before, &after));
    // The master transcript may contain only the explicit final line ending.
    // It must contain no input bytes, including invalid or overlong passwords.
    CHECK(fcntl(master, F_SETFL, O_NONBLOCK) == 0);
    char transcript[1024];
    ssize_t count = read(master, transcript, sizeof(transcript));
    if (kind == interrupt || kind == terminate || kind == hangup)
        CHECK(count == -1 && errno == EAGAIN);
    else
        CHECK((count == 1 && transcript[0] == '\n') ||
              (count == 2 && transcript[0] == '\r' && transcript[1] == '\n'));
    close(slave);
    close(master);
    close(result[0]);
    observed(name);
}

int main(void) {
    CHECK(!getuid() && !geteuid());
    int descriptors[2];
    CHECK(pipe(descriptors) == 0);
    char secret[ACCOUNT_PASSWORD_MAX + 1];
    memset(secret, 'z', sizeof(secret));
    CHECK(account_secret_read(descriptors[0], "Password: ", secret) == -1 && errno == ENOTTY);
    CHECK(cleared(secret));
    close(descriptors[0]);
    close(descriptors[1]);
    observed("nonterminal_rejected_and_output_cleared");
    run(good, "511_byte_private_input_echo_restored_background_denied");
    run(empty, "empty_input_denied_cleared_echo_restored");
    run(overlong, "512_byte_input_drained_denied_cleared_echo_restored");
    run(nul, "nul_input_drained_denied_cleared_echo_restored");
    run(eof, "terminal_eof_denied_cleared_echo_restored");
    run(interrupt, "sigint_original_action_after_echo_restored");
    run(terminate, "sigterm_original_action_after_echo_restored");
    run(hangup, "ignored_hangup_returns_cancelled_cleared_echo_restored");
    printf("ACCOUNT_SECRET_PASS observations=%u\n", observations);
    return 0;
}
