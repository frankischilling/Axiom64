// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/session.h
 * @brief   Account session interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the routines that create and operate sessions under account
 * credentials.
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
