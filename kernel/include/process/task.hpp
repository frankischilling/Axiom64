// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/process/task.hpp
 * @brief   Kernel task and process state.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines task register frames, process resources, scheduling state, and
 * lifecycle entry points.
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
#pragma once
#include "arch/x86_64/cpu_local.hpp"
#include "fs/vfs.hpp"
#include "security/credentials.hpp"
#include "process/limits.hpp"
#include "process/pending_signals.hpp"

namespace ax {
constexpr unsigned max_tasks = 256, max_fds = 1024;
enum class State { empty, runnable, blocked, zombie, stopped };
enum class Wait {
    none,
    read,
    write,
    child,
    sleep,
    descriptor,
    vfork,
    signal,
    signal_queue,
    futex,
    file_lock,
    random,
    semaphore,
    message_queue,
    posix_queue,
    fifo_open,
    epoll_wait,
    pcm_drain,
    alsa_write
};

struct Descriptor {
    Handle* handle;
    bool cloexec;
    bool reserved = false;
};

struct SharedMemoryMapping;

struct MemoryContext {
    unsigned references = 1;
    bool dumpable = true;
    uint32_t barrier_registrations = 0;
    AddressSpace space;
    uint64_t brk_base = 0, brk_end = 0;
    uint64_t initial_data_size = 0;

    struct {
        uint64_t begin, end, environment_end;
    } arguments{};

    SharedMemoryMapping* shared = nullptr;
    Node* exec_file = nullptr;
    Node* exec_dentry = nullptr;
};

struct FileTable {
    unsigned references = 1;
    // select copies a bitmap only as far as the expanded descriptor table.
    unsigned capacity = 64;
    Descriptor entries[max_fds]{};

    void expand(unsigned fd) {
        while (fd >= capacity)
            capacity *= 2;
    }
};

struct FsContext {
    unsigned references = 1;
    char cwd[1024]{};
    Node* cwd_node = nullptr;
    Node* root_node = nullptr;
    uint32_t umask = 0022;
};

struct SignalHandlers {
    unsigned references = 1;
    uint64_t descriptor_wait_queue = 0;
    uint64_t signal_actions[64][4]{};
};
struct Task;
struct IoRequest;
struct DescriptorWait;

struct Process {
    ProcessLimits limits{max_fds};
    int pid = 0, parent = 0, pgid = 0, sid = 0, exit_status = 0, stop_signal = 0;
    unsigned live_threads = 1;
    unsigned running_cpu = ~0u;
    Task* leader = nullptr;
    Pty* controlling_pty = nullptr;
    bool controlling_console = false, stop_reported = false, continued = false, stopped = false;
    bool executed = false;
    uint64_t exec_generation = 0;
    char executable[1024]{};
    uint64_t start_ticks = 0;
    uint64_t cpu_user_ticks = 0, cpu_system_ticks = 0;
    uint64_t children_user_ticks = 0, children_system_ticks = 0;
    uint64_t alarm_deadline = 0, alarm_interval = 0;
    PendingSignals pending_signals;
};

struct FutexWait {
    MemoryContext* domain = nullptr;
    uint64_t identity = 0, pinned_page = 0, deadline = 0;
    uint32_t bitset = 0;
    bool queued = false;
};

struct SemaphoreRequest;
struct SemaphoreUndo;
struct MessageQueueRequest;
struct PosixQueueRequest;

struct FifoOpen {
    Handle* handle;
    int fd;
    uint64_t peer_generation;
};

struct Task {
    State state;
    int pid; // Kernel TID; process->pid is the userspace thread-group ID.
    Process* process;
    int real_parent_tid;
    int parent_death_signal;
    bool process_limit_exceeded;
    uint64_t start_ticks;
    uint64_t cpu_user_ticks, cpu_system_ticks;
    char name[16];

    void set_name(const char* value, size_t length);

    struct {
        uint64_t mask, information, deadline;
        bool finite;
    } signal_wait;

    Frame frame;
    MemoryContext* memory;
    FileTable* files;
    FsContext* fs;
    SignalHandlers* handlers;
    Credentials credentials;
    uint64_t fs_base, gs_base, tid_address, signal_mask;
    uint64_t altstack_base, altstack_size;
    PendingSignals pending_signals;
    uint64_t suspend_saved_mask;
    bool suspend_mask;
    Wait wait;
    int wait_fd, wait_pid;
    uint64_t deadline, wait_generation;
    int vfork_parent;
    FutexWait futex;
    IoRequest* io;
    DescriptorWait* descriptor_wait;
    SemaphoreRequest* semaphore_request;
    SemaphoreUndo* semaphore_undo;
    MessageQueueRequest* message_queue_request;
    PosixQueueRequest* posix_queue_request;
    FifoOpen fifo_open;
    Handle* epoll_wait_handle;
    alignas(16) uint8_t fpu[512];
};

extern Task tasks[max_tasks];
extern uint64_t ticks;
extern bool trace_syscalls, test_mode;
extern const char* test_suite;
extern const char* test_phase;

Task* new_task();
Task* task(int pid);

uint64_t task_user_count(uint32_t);

int process_exec_limit(Task&);

int fork_task(Frame*, bool share = false, uint64_t stack = 0);

int clone_task(Frame*, uint64_t flags, uint64_t stack, uint64_t parent_tid, uint64_t child_tid,
               uint64_t tls);

class ExecArguments;

int executable_access(const Task&, Node*);
int exec_task(Task*, ExecArguments&, Node* file = nullptr, bool path_inaccessible = false);

void exit_task(Task*, int);

void exit_thread(Task*, int);

void reap_task(Task*, Process&);

int allocate_fd(Task*, Handle*, int start = 0, bool cloexec = false);

Frame* schedule(Frame*, bool yield = false);

int close_task_descriptors(Task&, unsigned first, unsigned last, unsigned flags);
void start_init(const char*, bool debug_ssh, bool text_console);

constexpr int64_t would_block = -4096;
} // namespace ax
