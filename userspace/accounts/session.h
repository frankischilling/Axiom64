// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_SESSION_H
#define AXIOM64_ACCOUNTS_SESSION_H

#include "auth.h"

struct account_session_events {
    // Called in the privileged supervisor after the child has installed its
    // complete credentials and before it can exec. A failure prevents exec.
    int (*begin)(void*, pid_t child, const char* terminal);
    int (*end)(void*, pid_t child, int wait_status);
    void* context;
    // Optional service-lifetime observation while the ordinary shell runs.
    // A failure terminates this session and still invokes end for cleanup.
    int (*observe)(void*);
};

// Run a command on a private, owned PTY in a new session. Relay the caller's
// foreground controlling terminal without changing its ownership. Restore its
// flags, termios and signal actions on every return, and close the private
// master at logout or failure. The returned status uses waitpid encoding.
// This is a single-threaded privileged frontend operation. events may be NULL
// for an isolated fixture; production frontends must supply durable records.
int account_session_run(const struct account_profile*, int terminal, const char* terminal_type,
                        char* const command[], const struct account_session_events*, int* status);

// Bits 0/1/2 select standard descriptors to replace with the private terminal.
// Unselected streams retain the caller's pipes/files. The command still owns
// a private controlling terminal, including for separate /dev/tty prompts.
int account_session_run_stdio(const struct account_profile*, int terminal,
                              const char* terminal_type, unsigned terminal_streams,
                              char* const command[], const struct account_session_events*,
                              int* status);

#endif
