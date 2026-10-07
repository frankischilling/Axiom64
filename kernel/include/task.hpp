// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vfs.hpp"

namespace ax {
constexpr unsigned max_tasks = 64, max_fds = 128;
enum class State { empty, runnable, blocked, zombie, stopped };
enum class Wait { none, read, write, child, sleep, poll, vfork, signal, futex };
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
struct MemoryContext {
    unsigned references = 1;
    AddressSpace space;
    uint64_t brk_base = 0, brk_end = 0;
    SharedAttachment shared[64]{};
};
struct FileTable {
    unsigned references = 1;
    Descriptor entries[max_fds]{};
};
struct FsContext {
    unsigned references = 1;
    char cwd[1024]{};
    Node* cwd_node = nullptr;
    uint32_t umask = 0022;
};
struct SignalHandlers {
    unsigned references = 1;
    uint64_t signal_actions[64][4]{};
};
struct Task;
struct IoRequest;
struct Process {
    int pid = 0, parent = 0, pgid = 0, sid = 0, exit_status = 0, stop_signal = 0;
    unsigned live_threads = 1;
    Task* leader = nullptr;
    Pty* controlling_pty = nullptr;
    bool controlling_console = false, stop_reported = false, continued = false, stopped = false;
    char executable[1024]{};
    uint64_t alarm_deadline = 0, alarm_interval = 0, pending_signals = 0;
    SignalData signal_data[64]{};
};
struct FutexWait {
    MemoryContext* domain = nullptr;
    uint64_t identity = 0, pinned_page = 0, deadline = 0;
    uint32_t bitset = 0;
    bool queued = false;
};
struct Task {
    State state;
    int pid; // Kernel TID; process->pid is the userspace thread-group ID.
    Process* process;
    Frame frame;
    MemoryContext* memory;
    FileTable* files;
    FsContext* fs;
    SignalHandlers* handlers;
    uint64_t fs_base, tid_address, signal_mask;
    uint64_t pending_signals, altstack_base, altstack_size;
    SignalData signal_data[64];
    uint64_t suspend_saved_mask;
    bool suspend_mask;
    Wait wait;
    int wait_fd, wait_pid;
    uint64_t deadline;
    int vfork_parent;
    FutexWait futex;
    IoRequest* io;
    alignas(16) uint8_t fpu[512];
};
extern Task tasks[max_tasks];
extern Task* current;
extern uint64_t ticks;
extern bool trace_syscalls, test_mode;
extern const char* test_suite;
extern const char* test_phase;
Task* new_task();
int fork_task(Frame*, bool share = false, uint64_t stack = 0);
int clone_task(Frame*, uint64_t flags, uint64_t stack, uint64_t parent_tid,
               uint64_t child_tid, uint64_t tls);
int exec_task(Task*, const char*, const char* const*, const char* const*);
void exit_task(Task*, int);
void exit_thread(Task*, int);
void reap_task(Task*);
int allocate_fd(Task*, Handle*, int start = 0, bool cloexec = false);
Frame* schedule(Frame*, bool yield = false);
void start_init(const char*);
constexpr int64_t would_block = -4096;
} // namespace ax
