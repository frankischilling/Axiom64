// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vfs.hpp"

namespace ax {
constexpr unsigned max_tasks = 64, max_fds = 128;
enum class State { empty, runnable, blocked, zombie, stopped };
enum class Wait { none, read, write, child, sleep, poll, vfork, signal };
struct Descriptor {
    Handle* handle;
    bool cloexec;
};
struct SharedAttachment {
    int id;
    uint64_t base, length;
};
struct SignalData {
    int sender, code, status;
    uint64_t address;
};
struct Task {
    State state;
    int pid, parent, pgid, sid, exit_status;
    Pty* controlling_pty;
    bool controlling_console;
    Frame frame;
    AddressSpace memory;
    Descriptor fds[max_fds];
    char cwd[1024], executable[1024];
    uint64_t fs_base, brk_base, brk_end, tid_address, signal_mask;
    uint64_t signal_actions[64][4];
    uint64_t pending_signals, altstack_base, altstack_size;
    SignalData signal_data[64];
    bool stop_reported, continued;
    uint64_t alarm_deadline, alarm_interval, suspend_saved_mask;
    bool suspend_mask;
    Wait wait;
    int wait_fd, wait_pid;
    uint64_t deadline;
    uint32_t umask;
    bool memory_shared;
    int vfork_parent;
    SharedAttachment shared[64];
    alignas(16) uint8_t fpu[512];
};
extern Task tasks[max_tasks];
extern Task* current;
extern uint64_t ticks;
extern bool trace_syscalls, test_mode;
extern const char* test_suite;
Task* new_task();
int fork_task(Frame*, bool share = false, uint64_t stack = 0);
int exec_task(Task*, const char*, const char* const*, const char* const*);
void exit_task(Task*, int);
int allocate_fd(Task*, Handle*, int start = 0, bool cloexec = false);
Frame* schedule(Frame*, bool yield = false);
void start_init(const char*);
constexpr int64_t would_block = -4096;
} // namespace ax
