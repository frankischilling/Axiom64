// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int recovery_open(const char*, int, ...);
static int recovery_ioctl(int, unsigned long, ...);

#ifndef DESKTOP_DIRECTORY
#define DESKTOP_DIRECTORY "/tmp/axiom64-seat-recovery"
#endif

// Only the unavailable native framebuffer adapter is replaced. Recovery reads
// real procfs, protected files, open-description locks and Unix sockets.
#define open recovery_open
#define ioctl recovery_ioctl
#include "../../desktop/seat.c"
#undef open
#undef ioctl

static unsigned observations, clear_calls;
static int framebuffer_error;
static const char pixels_path[] = "/tmp/axiom64-seat-recovery-pixels";

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            dprintf(2, "seat-recovery: line=%d errno=%d check=%s\n", __LINE__, errno,              \
                    #expression);                                                                  \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static int recovery_open(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }
    return open(!strcmp(path, "/dev/fb0") ? pixels_path : path, flags, mode);
}

static int recovery_ioctl(int fd, unsigned long request, ...) {
    va_list arguments;
    va_start(arguments, request);
    void* output = va_arg(arguments, void*);
    va_end(arguments);
    struct stat value, expected;
    CHECK(fstat(fd, &value) == 0 && stat(pixels_path, &expected) == 0);
    CHECK(value.st_dev == expected.st_dev && value.st_ino == expected.st_ino);
    if (request == 0x4600) {
        clear_calls++;
        if (framebuffer_error)
            return failed(EIO);
        uint32_t* variable = output;
        variable[0] = variable[1] = 32;
        variable[6] = 32;
    } else {
        CHECK(request == 0x4602);
        uint32_t size = 4096;
        memcpy((char*)output + 24, &size, sizeof(size));
    }
    return 0;
}

int account_profile_enter(const struct account_profile* profile, int service) {
    (void)profile;
    (void)service;
    return failed(ENOSYS);
}

int account_profile_environment(const struct account_profile* profile, const char* terminal) {
    (void)profile;
    (void)terminal;
    return failed(ENOSYS);
}

static void observed(const char* name) {
    dprintf(1, "SEAT_RECOVERY_OBSERVED %s\n", name);
    observations++;
}

static void write_file(const char* name, const char* bytes, size_t size, mode_t mode, uid_t uid,
                       gid_t gid) {
    char path[256];
    if (*name == '/')
        snprintf(path, sizeof(path), "%s", name);
    else
        snprintf(path, sizeof(path), "%s/%s", DESKTOP_DIRECTORY, name);
    int fd = open(path, O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT)
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    size_t used = 0;
    while (used < size) {
        ssize_t count = write(fd, bytes + used, size - used);
        CHECK(count > 0);
        used += (size_t)count;
    }
    CHECK(fchown(fd, uid, gid) == 0 && fchmod(fd, mode) == 0 && fsync(fd) == 0);
    CHECK(close(fd) == 0);
}

static void erase(const char* name) {
    char path[256];
    if (*name == '/')
        snprintf(path, sizeof(path), "%s", name);
    else
        snprintf(path, sizeof(path), "%s/%s", DESKTOP_DIRECTORY, name);
    CHECK(unlink(path) == 0);
}

static void state_file(struct desktop_seat* seat) {
    char bytes[state_limit];
    size_t length;
    CHECK(state_encode(seat, bytes, &length) == 0);
    write_file("state", bytes, length, 0600, 0, 0);
}

static void rejected(int error) {
    unsigned before = clear_calls;
    errno = 0;
    CHECK(desktop_seat_recover() == -1 && errno == error);
    CHECK(clear_calls == before);
    CHECK(access(DESKTOP_DIRECTORY "/state", F_OK) == 0);
}

static void codec(struct desktop_seat* seat) {
    char bytes[state_limit], changed[state_limit];
    size_t length;
    struct desktop_seat parsed;
    CHECK(state_encode(seat, bytes, &length) == 0);
    CHECK(state_decode(bytes, length, &parsed) == 0);
    CHECK(parsed.owner == seat->owner && parsed.owner_start == seat->owner_start &&
          parsed.uid == seat->uid && parsed.gid == seat->gid && !strcmp(parsed.boot, seat->boot));
    for (size_t size = 0; size < length; size++)
        CHECK(state_decode(bytes, size, &parsed) == -1 && errno == EUCLEAN);
    for (size_t at = 0; at < length; at++)
        for (unsigned bit = 0; bit < 8; bit++) {
            memcpy(changed, bytes, length);
            changed[at] ^= (char)(1u << bit);
            CHECK(state_decode(changed, length, &parsed) == -1 && errno == EUCLEAN);
        }
    memcpy(changed, bytes, length);
    changed[length] = '\n';
    CHECK(state_decode(changed, length + 1, &parsed) == -1);
    seat->owner_start = 0;
    CHECK(state_encode(seat, bytes, &length) == 0 && state_decode(bytes, length, &parsed) == 0);
    seat->server = 0;
    seat->server_start = 1;
    CHECK(state_encode(seat, bytes, &length) == 0 && state_decode(bytes, length, &parsed) == -1);
    seat->server_start = 0;
    CHECK(process_start(seat->owner, &seat->owner_start) == 1);
    observed("canonical_state_exact_eof_every_truncation_every_bit_and_zero_birth_tick");
}

static void noncanonical(struct desktop_seat* seat) {
    const char* invalid[] = {"owner=01:0",
                             "owner=+1:0",
                             "owner=-1:0",
                             "owner=2147483648:0",
                             "owner=1:18446744073709551616",
                             "server=0:1",
                             "uid=0",
                             "uid=4294967295",
                             "gid=4294967295",
                             "gid=01"};
    char valid[state_limit];
    size_t length;
    CHECK(state_encode(seat, valid, &length) == 0);
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        char changed[state_limit];
        const char* equal = strchr(invalid[i], '=');
        size_t key = (size_t)(equal - invalid[i]) + 1;
        const char* line = valid;
        while (strncmp(line, invalid[i], key)) {
            line = strchr(line, '\n');
            CHECK(line);
            line++;
        }
        const char* tail = strchr(line, '\n');
        CHECK(tail);
        int size = snprintf(changed, sizeof(changed), "%.*s%s%s", (int)(line - valid), valid,
                            invalid[i], tail);
        CHECK(size > 0 && size < state_limit);
        char* seal = strstr(changed, "crc=");
        CHECK(seal);
        CHECK(snprintf(seal, (size_t)(changed + state_limit - seal), "crc=%08x\n",
                       (unsigned)checksum(changed, (size_t)(seal - changed))) == 13);
        struct desktop_seat parsed;
        CHECK(state_decode(changed, strlen(changed), &parsed) == -1 && errno == EUCLEAN);
    }
    observed(
        "independently_resealed_sign_leading_zero_numeric_overflow_and_identity_relation_denials");
}

static void metadata(struct desktop_seat* seat) {
    static const char* names[] = {"server.auth", "client.auth", "server.log",
                                  "clients.log", "Xorg.log",    "Xorg.log.old"};
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++) {
        int user = i == 1;
        mode_t mode = user ? 0400 : 0600;
        uid_t uid = user ? seat->uid : 0;
        gid_t gid = user ? seat->gid : 0;
        state_file(seat);
        write_file(names[i], "artifact", 8, mode | 0020, uid, gid);
        rejected(EACCES);
        write_file(names[i], "artifact", 8, mode, uid + 1, gid);
        rejected(EACCES);
        write_file(names[i], "artifact", 8, mode, uid, gid + 1);
        rejected(EACCES);
        write_file(names[i], "artifact", 8, mode, uid, gid);
        char path[256];
        snprintf(path, sizeof(path), "%s/%s", DESKTOP_DIRECTORY, names[i]);
        CHECK(link(path, "/tmp/axiom64-seat-recovery-link") == 0);
        rejected(EACCES);
        CHECK(unlink("/tmp/axiom64-seat-recovery-link") == 0);
        erase(names[i]);
        CHECK(symlink("/etc/passwd", path) == 0);
        rejected(EACCES);
        erase(names[i]);
        CHECK(mkfifo(path, mode) == 0);
        rejected(EACCES);
        erase(names[i]);
        CHECK(mkdir(path, mode) == 0);
        rejected(EACCES);
        CHECK(rmdir(path) == 0);
    }
    state_file(seat);
    write_file("unknown", "x", 1, 0600, 0, 0);
    rejected(EUCLEAN);
    erase("unknown");
    erase("state");
    write_file("server.auth", "orphan", 6, 0600, 0, 0);
    unsigned before = clear_calls;
    CHECK(desktop_seat_recover() == -1 && errno == EUCLEAN && before == clear_calls);
    CHECK(access(DESKTOP_DIRECTORY "/server.auth", F_OK) == 0);
    erase("server.auth");
    observed("all_artifact_uid_gid_mode_link_symlink_fifo_directory_unknown_and_orphan_denials");
}

static void ownership(struct desktop_seat* seat) {
    state_file(seat);
    rejected(EBUSY);
    struct desktop_seat saved = *seat;
    saved.owner = INT32_MAX;
    saved.owner_start = 0;
    for (int client = 0; client < 2; client++) {
        if (client) {
            saved.clients = seat->owner;
            saved.clients_start = seat->owner_start;
        } else {
            saved.server = seat->owner;
            saved.server_start = seat->owner_start;
        }
        state_file(&saved);
        rejected(EBUSY);
        saved.server = saved.clients = 0;
        saved.server_start = saved.clients_start = 0;
    }
    state_file(seat);
    int lock = open(DESKTOP_DIRECTORY "/lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    CHECK(lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) == 0);
    rejected(EWOULDBLOCK);
    CHECK(close(lock) == 0);
    int display = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(display >= 0 && mkdir("/tmp/.X11-unix", 01777) == 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, "/tmp/.X11-unix/X0");
    CHECK(bind(display, (struct sockaddr*)&address, sizeof(address)) == 0 &&
          listen(display, 1) == 0);
    rejected(EBUSY);
    CHECK(close(display) == 0 && unlink(address.sun_path) == 0 && rmdir("/tmp/.X11-unix") == 0);
    observed("actual_matching_owner_server_client_flock_and_foreign_unix_display_block_recovery");
}

static void simulated_saved_identity(struct desktop_seat* seat) {
    struct desktop_seat saved = *seat;
    saved.owner_start++;
    state_file(&saved);
    write_file("server.auth", "server", 6, 0600, 0, 0);
    write_file("client.auth", "client", 6, 0400, seat->uid, seat->gid);
    write_file("Xorg.log", "log", 3, 0600, 0, 0);
    write_file("t-0123456789abcdef0123456789abcdef", "partial", 7, 0600, 0, 0);
    CHECK(desktop_seat_recover() == 0);
    CHECK(kill(getpid(), 0) == 0);
    CHECK(access(DESKTOP_DIRECTORY "/state", F_OK) == -1 && errno == ENOENT);
    CHECK(access(DESKTOP_DIRECTORY "/client.auth", F_OK) == -1 && errno == ENOENT);
    CHECK(access(DESKTOP_DIRECTORY "/t-0123456789abcdef0123456789abcdef", F_OK) == -1 &&
          errno == ENOENT);
    saved = *seat;
    saved.boot[0] = saved.boot[0] == 'a' ? 'b' : 'a';
    state_file(&saved);
    CHECK(desktop_seat_recover() == 0 && kill(getpid(), 0) == 0);
    write_file("t-0123456789abcdef0123456789abcdef", "partial", 7, 0600, 0, 0);
    CHECK(desktop_seat_recover() == 0);
    observed("simulated_saved_wrong_birth_tick_and_changed_boot_retire_files_without_signals");
}

static void damaged_state(struct desktop_seat* seat) {
    char bytes[state_limit], suffix[2048];
    size_t length;
    CHECK(state_encode(seat, bytes, &length) == 0);
    const char legacy[] = "axiom64-seat=1\nowner=2147483647\nserver=0\nclients=0\nuid=1000\n";
    write_file("state", legacy, sizeof(legacy) - 1, 0600, 0, 0);
    rejected(EUCLEAN);
    memcpy(suffix, bytes, length);
    memset(suffix + length, '\n', sizeof(suffix) - length);
    write_file("state", suffix, sizeof(suffix), 0600, 0, 0);
    rejected(EUCLEAN);
    for (size_t i = 0; i < length; i++) {
        write_file("state", bytes, i, 0600, 0, 0);
        rejected(EUCLEAN);
    }
    state_file(seat);
    CHECK(chmod(DESKTOP_DIRECTORY "/state", 0640) == 0);
    rejected(EACCES);
    CHECK(chmod(DESKTOP_DIRECTORY "/state", 0600) == 0);
    framebuffer_error = 1;
    struct desktop_seat saved = *seat;
    saved.owner_start++;
    state_file(&saved);
    CHECK(desktop_seat_recover() == -1 && errno == EIO);
    CHECK(access(DESKTOP_DIRECTORY "/state", F_OK) == 0);
    framebuffer_error = 0;
    CHECK(desktop_seat_recover() == 0);
    observed(
        "public_recovery_truncation_oversized_suffix_legacy_unsafe_state_and_framebuffer_failure");
}

static void xorg_artifacts(struct desktop_seat* seat) {
    struct desktop_seat saved = *seat;
    saved.owner = INT32_MAX;
    saved.owner_start = 0;
    saved.server = seat->owner;
    saved.server_start = seat->owner_start + 1;
    char pid[13];
    CHECK(snprintf(pid, sizeof(pid), "%10u\n", (unsigned)saved.server) == 11);
    state_file(&saved);
    write_file("/tmp/.X0-lock", pid, 11, 0400, 0, 0);
    rejected(EACCES);
    write_file("/tmp/.X0-lock", pid, 11, 0444, 1000, 0);
    rejected(EACCES);
    write_file("/tmp/.X0-lock", pid, 11, 0444, 0, 1000);
    rejected(EACCES);
    write_file("/tmp/.X0-lock", pid, 11, 0444, 0, 0);
    CHECK(link("/tmp/.X0-lock", "/tmp/axiom64-X0-alias") == 0);
    rejected(EACCES);
    erase("/tmp/axiom64-X0-alias");
    write_file("/tmp/.X0-lock", "0000000000\n", 11, 0444, 0, 0);
    rejected(EUCLEAN);
    pid[11] = '0';
    write_file("/tmp/.X0-lock", pid, 12, 0444, 0, 0);
    rejected(EACCES);
    erase("/tmp/.X0-lock");
    CHECK(symlink("/etc/passwd", "/tmp/.X0-lock") == 0);
    rejected(EACCES);
    erase("/tmp/.X0-lock");
    CHECK(mkfifo("/tmp/.X0-lock", 0444) == 0);
    rejected(EACCES);
    erase("/tmp/.X0-lock");
    write_file("/tmp/.X0-lock", pid, 11, 0444, 0, 0);
    CHECK(mkdir("/tmp/.X11-unix", 01777) == 0 && chmod("/tmp/.X11-unix", 01777) == 0);
    write_file("/tmp/.X11-unix/X0", "x", 1, 0777, 0, 0);
    rejected(EACCES);
    erase("/tmp/.X11-unix/X0");
    int socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(socket_fd >= 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, "/tmp/.X11-unix/X0");
    CHECK(bind(socket_fd, (struct sockaddr*)&address, sizeof(address)) == 0 &&
          close(socket_fd) == 0);
    CHECK(chmod(address.sun_path, 0777) == 0 && chown(address.sun_path, 1000, 0) == 0);
    rejected(EACCES);
    CHECK(chown(address.sun_path, 0, 1000) == 0);
    rejected(EACCES);
    CHECK(chown(address.sun_path, 0, 0) == 0 && chmod(address.sun_path, 0700) == 0);
    rejected(EACCES);
    CHECK(chmod(address.sun_path, 0777) == 0 && chmod("/tmp/.X11-unix", 0777) == 0);
    rejected(EACCES);
    CHECK(chmod("/tmp/.X11-unix", 01777) == 0);
    saved.server_start = seat->owner_start;
    state_file(&saved);
    rejected(EBUSY);
    saved.server_start++;
    state_file(&saved);
    CHECK(link("/tmp/.X0-lock", "/tmp/.tX0-lock") == 0);
    CHECK(desktop_seat_recover() == 0 && kill(getpid(), 0) == 0);
    CHECK(access(address.sun_path, F_OK) == -1 && errno == ENOENT);
    CHECK(access("/tmp/.X0-lock", F_OK) == -1 && errno == ENOENT);
    CHECK(access("/tmp/.tX0-lock", F_OK) == -1 && errno == ENOENT);
    write_file("/tmp/.X0-lock", pid, 11, 0444, 0, 0);
    unsigned before = clear_calls;
    CHECK(desktop_seat_recover() == -1 && errno == EUCLEAN && before == clear_calls);
    CHECK(access("/tmp/.X0-lock", F_OK) == 0);
    erase("/tmp/.X0-lock");
    CHECK(rmdir("/tmp/.X11-unix") == 0);
    observed("actual_stale_xorg_socket_lock_pair_retirement_and_foreign_metadata_pid_eof_denials");
}

static void exited_leader_group(void) {
    int ready[2], lifetime[2];
    CHECK(pipe2(ready, O_CLOEXEC) == 0 && pipe2(lifetime, O_CLOEXEC | O_NONBLOCK) == 0);
    pid_t leader = fork();
    CHECK(leader >= 0);
    if (!leader) {
        close(ready[0]);
        close(lifetime[0]);
        CHECK(setsid() == getpid());
        pid_t descendant = fork();
        CHECK(descendant >= 0);
        if (!descendant) {
            close(ready[1]);
            for (;;)
                pause();
        }
        CHECK(write(ready[1], &descendant, sizeof(descendant)) == (ssize_t)sizeof(descendant));
        close(lifetime[1]);
        _exit(0);
    }
    close(ready[1]);
    close(lifetime[1]);
    pid_t descendant;
    CHECK(read(ready[0], &descendant, sizeof(descendant)) == (ssize_t)sizeof(descendant));
    close(ready[0]);
    pid_t owned = leader;
    for (unsigned attempt = 0;; attempt++) {
        int result = observe_child(&owned);
        if (result < 0) {
            CHECK(errno == ECHILD);
            break;
        }
        CHECK(attempt < 500);
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
    CHECK(owned == leader && kill(descendant, 0) == 0 && getpgid(descendant) == leader);
    siginfo_t information = {0};
    CHECK(waitid(P_PID, leader, &information, WEXITED | WNOHANG | WNOWAIT) == 0 &&
          information.si_pid == leader && information.si_code == CLD_EXITED &&
          information.si_status == 0);
    CHECK(stop_child(owned) == 0);
    CHECK(waitpid(leader, NULL, WNOHANG) == -1 && errno == ECHILD);
    struct pollfd lifetime_poll = {.fd = lifetime[0], .events = POLLIN | POLLHUP};
    CHECK(poll(&lifetime_poll, 1, 5000) == 1 && lifetime_poll.revents & POLLHUP);
    char byte;
    CHECK(read(lifetime[0], &byte, 1) == 0 && close(lifetime[0]) == 0);
    observed("actual_exited_unreaped_leader_keeps_pid_pinned_until_owned_descendant_group_exit");
}

static void gated_publication_crashes(void) {
    CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);
    for (unsigned phase = 0; phase < 3; phase++) {
        int report[2], lifetime[2];
        CHECK(pipe2(report, O_CLOEXEC) == 0 && pipe2(lifetime, O_CLOEXEC) == 0);
        pid_t controller = fork();
        CHECK(controller >= 0);
        if (!controller) {
            close(report[0]);
            close(lifetime[0]);
            struct desktop_seat saved = {.owner = getpid(), .uid = 1000, .gid = 1001};
            saved.directory = account_directory_open(DESKTOP_DIRECTORY, 0755, 0);
            CHECK(saved.directory >= 0);
            saved.lock = account_file_open(saved.directory, "lock", O_RDWR, 0600, 0);
            CHECK(saved.lock >= 0 && flock(saved.lock, LOCK_EX | LOCK_NB) == 0);
            CHECK(boot_identity(saved.boot) == 0 &&
                  process_capture(saved.owner, &saved.owner_start) == 0 && state_save(&saved) == 0);
            int gate[2];
            CHECK(pipe2(gate, O_CLOEXEC) == 0);
            pid_t worker = fork();
            CHECK(worker >= 0);
            if (!worker) {
                close(gate[1]);
                close(report[1]);
                if (child_gate(gate[0], saved.owner) < 0)
                    _exit(126);
                // This side effect stands at the actual post-gate exec point.
                // No framebuffer, Xorg socket or lock can exist before it.
                int marker = open(DESKTOP_DIRECTORY "/released", O_WRONLY | O_CREAT | O_EXCL, 0600);
                CHECK(marker >= 0 && write(marker, "exec", 4) == 4 && close(marker) == 0);
                _exit(0);
            }
            close(gate[0]);
            close(lifetime[1]);
            if (phase) {
                saved.server = worker;
                CHECK(process_capture(worker, &saved.server_start) == 0 && state_save(&saved) == 0);
            }
            CHECK(write(report[1], &worker, sizeof(worker)) == (ssize_t)sizeof(worker));
            close(report[1]);
            if (phase == 2) {
                CHECK(write(gate[1], "G", 1) == 1 && close(gate[1]) == 0);
                int status;
                CHECK(waitpid(worker, &status, 0) == worker && WIFEXITED(status) &&
                      WEXITSTATUS(status) == 0);
                _exit(0);
            }
            for (;;)
                pause();
        }
        close(report[1]);
        close(lifetime[1]);
        pid_t worker;
        CHECK(read(report[0], &worker, sizeof(worker)) == (ssize_t)sizeof(worker));
        close(report[0]);
        if (phase != 2) {
            CHECK(access(DESKTOP_DIRECTORY "/released", F_OK) == -1 && errno == ENOENT);
            CHECK(kill(controller, SIGKILL) == 0);
        }
        int status;
        CHECK(waitpid(controller, &status, 0) == controller);
        CHECK(phase == 2 ? WIFEXITED(status) && WEXITSTATUS(status) == 0
                         : WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        struct pollfd ended = {.fd = lifetime[0], .events = POLLIN | POLLHUP};
        CHECK(poll(&ended, 1, 5000) == 1 && (ended.revents & POLLHUP));
        char byte;
        CHECK(read(lifetime[0], &byte, 1) == 0 && close(lifetime[0]) == 0);
        if (phase != 2) {
            CHECK(waitpid(worker, &status, 0) == worker);
            CHECK(WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) == 126));
            CHECK(access(DESKTOP_DIRECTORY "/released", F_OK) == -1 && errno == ENOENT);
        } else {
            CHECK(access(DESKTOP_DIRECTORY "/released", F_OK) == 0);
            erase("released");
        }
        CHECK(desktop_seat_recover() == 0);
        CHECK(access(DESKTOP_DIRECTORY "/state", F_OK) == -1 && errno == ENOENT);
    }
    CHECK(prctl(PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) == 0);
    observed("actual_supervisor_crashes_before_pid_publication_and_before_gate_release_never_exec");
    observed("actual_durable_pid_publication_then_gate_release_allows_child_side_effect");
}

int main(void) {
    CHECK(getuid() == 0 && geteuid() == 0 && getgid() == 0);
    CHECK(mkdir(DESKTOP_DIRECTORY, 0755) == 0 && chmod(DESKTOP_DIRECTORY, 0755) == 0);
    int framebuffer = open(pixels_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(framebuffer >= 0 && ftruncate(framebuffer, 4096) == 0 && close(framebuffer) == 0);
    struct desktop_seat seat = {.owner = getpid(), .uid = 1000, .gid = 1001};
    CHECK(boot_identity(seat.boot) == 0 && process_start(seat.owner, &seat.owner_start) == 1);
    CHECK(desktop_seat_recover() == 0);
    codec(&seat);
    noncanonical(&seat);
    metadata(&seat);
    ownership(&seat);
    simulated_saved_identity(&seat);
    damaged_state(&seat);
    xorg_artifacts(&seat);
    exited_leader_group();
    gated_publication_crashes();
    erase("lock");
    CHECK(rmdir(DESKTOP_DIRECTORY) == 0 && unlink(pixels_path) == 0);
    dprintf(1, "SEAT_RECOVERY_RESULT observations=%u framebuffer_adapter_calls=%u\n", observations,
            clear_calls);
    return 0;
}
