// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "secret.h"
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static volatile sig_atomic_t cancelled;
static const int caught[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU};

static int failed(int error) {
    errno = error;
    return -1;
}

static void cancel(int number) {
    if (!cancelled)
        cancelled = number;
}

static int text(int terminal, const char* value) {
    size_t size = strlen(value), done = 0;
    while (done < size) {
        if (cancelled)
            return failed(ECANCELED);
        ssize_t count = write(terminal, value + done, size - done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return failed(count < 0 ? errno : EIO);
        done += (size_t)count;
    }
    return 0;
}

int account_secret_read(int terminal, const char* prompt, char output[ACCOUNT_PASSWORD_MAX + 1]) {
    if (!output)
        return failed(EINVAL);
    account_password_clear(output, ACCOUNT_PASSWORD_MAX + 1);
    if (!prompt)
        return failed(EINVAL);
    struct termios original = {0};
    if (tcgetattr(terminal, &original) < 0)
        return -1;
    if (tcgetsid(terminal) != getsid(0) || tcgetpgrp(terminal) != getpgrp())
        return failed(ENOTTY);
    if (!(original.c_lflag & ICANON))
        return failed(EINVAL);
    sigset_t blocked, previous_mask;
    sigemptyset(&blocked);
    for (size_t i = 0; i < sizeof(caught) / sizeof(caught[0]); i++)
        sigaddset(&blocked, caught[i]);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous_mask) < 0)
        return -1;
    struct sigaction previous[sizeof(caught) / sizeof(caught[0])];
    struct sigaction action = {.sa_handler = cancel};
    sigemptyset(&action.sa_mask);
    cancelled = 0;
    size_t installed = 0;
    int error = 0, quiet = 0;
    for (; installed < sizeof(caught) / sizeof(caught[0]); installed++)
        if (sigaction(caught[installed], &action, &previous[installed]) < 0) {
            error = errno;
            break;
        }
    if (!error) {
        struct termios hidden = original;
        hidden.c_lflag &= ~(ECHO | ECHONL);
        if (tcsetattr(terminal, TCSANOW, &hidden) < 0)
            error = errno;
        else
            quiet = 1;
    }
    if (sigprocmask(SIG_SETMASK, &previous_mask, NULL) < 0 && !error)
        error = errno;
    if (!error && text(terminal, prompt) < 0)
        error = errno;
    size_t used = 0;
    int input_error = 0;
    while (!error) {
        if (cancelled) {
            error = ECANCELED;
            break;
        }
        char byte;
        ssize_t count = read(terminal, &byte, 1);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            error = count < 0 ? errno : ENODATA;
            break;
        }
        if (byte == '\n') {
            error = input_error;
            break;
        }
        if (!byte || byte == '\r') {
            input_error = EINVAL;
            continue;
        }
        if (used == ACCOUNT_PASSWORD_MAX) {
            input_error = EMSGSIZE;
            continue;
        }
        if (!input_error)
            output[used++] = byte;
    }
    if (!error && !used)
        error = EINVAL;
    if (quiet && !cancelled && text(terminal, "\n") < 0 && !error)
        error = errno;
    if (sigprocmask(SIG_BLOCK, &blocked, NULL) < 0 && !error)
        error = errno;
    if (quiet && tcsetattr(terminal, TCSANOW, &original) < 0 && !error)
        error = errno;
    for (size_t i = installed; i > 0; i--)
        if (sigaction(caught[i - 1], &previous[i - 1], NULL) < 0 && !error)
            error = errno;
    int signal = cancelled;
    cancelled = 0;
    if (error || signal)
        account_password_clear(output, ACCOUNT_PASSWORD_MAX + 1);
    if (sigprocmask(SIG_SETMASK, &previous_mask, NULL) < 0 && !error)
        error = errno;
    if (signal) {
        // Deliver cancellation through the caller's original action only after
        // the terminal has its original echo and foreground behavior again.
        raise(signal);
        error = ECANCELED;
    }
    if (error)
        account_password_clear(output, ACCOUNT_PASSWORD_MAX + 1);
    return error ? failed(error) : 0;
}
