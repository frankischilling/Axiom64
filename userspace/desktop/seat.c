// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "seat.h"
#include "authority.h"
#include "../accounts/protected.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef DESKTOP_DIRECTORY
#define DESKTOP_DIRECTORY "/run/axiom64-seat"
#endif

struct desktop_seat {
    int directory, lock;
    pid_t server, clients;
    pid_t owner;
    uid_t uid;
    gid_t gid;
    uint64_t owner_start, server_start, clients_start;
    char boot[37];
    uint8_t cookie[16];
    int published;
};

static const char* files[] = {"server.auth", "client.auth",  "server.log", "clients.log",
                              "Xorg.log",    "Xorg.log.old", "state"};

enum { state_limit = 512, inventory_limit = 128 };

struct inventory {
    char names[inventory_limit][35];
    size_t count;
    int state, artifacts;
};

struct xorg_inventory {
    int temporary, sockets;
    int lock, temporary_lock, socket;
};

static int failed(int error) {
    errno = error;
    return -1;
}

static int display_available(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, "/tmp/.X11-unix/X0");
    int result = connect(fd, (struct sockaddr*)&address, sizeof(address));
    int error = errno;
    close(fd);
    if (!result)
        return failed(EBUSY);
    return error == ENOENT || error == ECONNREFUSED ? 0 : failed(error);
}

static int clear_framebuffer(void) {
    int fd = open("/dev/fb0", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    uint8_t fixed[80] = {0};
    uint32_t variable[40] = {0}, length = 0;
    int error = ioctl(fd, 0x4600, variable) < 0 || ioctl(fd, 0x4602, fixed) < 0 ? errno : 0;
    memcpy(&length, fixed + 24, 4);
    if (!error && (!variable[0] || !variable[1] || variable[6] != 32 || !length ||
                   length > 256u * 1024 * 1024))
        error = EINVAL;
    void* pixels = MAP_FAILED;
    if (!error) {
        pixels = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (pixels == MAP_FAILED)
            error = errno;
        else {
            memset(pixels, 0, length);
            if (munmap(pixels, length) < 0)
                error = errno;
        }
    }
    close(fd);
    return error ? failed(error) : 0;
}

static int read_complete(int fd, char* bytes, size_t capacity, size_t* length) {
    size_t used = 0;
    for (;;) {
        char extra;
        ssize_t count = read(fd, used < capacity ? bytes + used : &extra,
                             used < capacity ? capacity - used : 1);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
            return -1;
        if (!count) {
            *length = used;
            return 0;
        }
        if (used == capacity)
            return failed(EUCLEAN);
        used += (size_t)count;
    }
}

static int proc_open(const char* path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct statfs filesystem;
    int error = fstatfs(fd, &filesystem) < 0 ? errno : 0;
    if (!error && filesystem.f_type != 0x9fa0)
        error = ENODEV;
    if (error) {
        close(fd);
        return failed(error);
    }
    return fd;
}

static int boot_valid(const char* value) {
    unsigned present = 0;
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-')
                return 0;
        } else {
            if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')))
                return 0;
            present |= value[i] != '0';
        }
    }
    return present && !value[36];
}

static int boot_identity(char output[37]) {
    int fd = proc_open("/proc/sys/kernel/random/boot_id");
    if (fd < 0)
        return -1;
    char bytes[37];
    size_t length = 0;
    int error = read_complete(fd, bytes, sizeof(bytes), &length) < 0 ? errno : 0;
    if (close(fd) < 0 && !error)
        error = errno;
    if (!error && (length != 37 || bytes[36] != '\n'))
        error = EUCLEAN;
    bytes[36] = 0;
    if (!error && !boot_valid(bytes))
        error = EUCLEAN;
    if (!error)
        memcpy(output, bytes, 37);
    return error ? failed(error) : 0;
}

static int decimal(const char** input, uint64_t maximum, uint64_t* value) {
    const char* cursor = *input;
    if (*cursor < '0' || *cursor > '9' || (*cursor == '0' && cursor[1] >= '0' && cursor[1] <= '9'))
        return failed(EUCLEAN);
    uint64_t result = 0;
    do {
        unsigned digit = (unsigned)(*cursor++ - '0');
        if (result > maximum / 10 || (result == maximum / 10 && digit > maximum % 10))
            return failed(EUCLEAN);
        result = result * 10 + digit;
    } while (*cursor >= '0' && *cursor <= '9');
    *input = cursor;
    *value = result;
    return 0;
}

static int process_start(pid_t pid, uint64_t* start) {
    if (pid <= 0)
        return failed(EINVAL);
    char path[64], bytes[4097];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    int fd = proc_open(path);
    if (fd < 0)
        return errno == ENOENT || errno == ESRCH ? 0 : -1;
    size_t length = 0;
    int error = read_complete(fd, bytes, sizeof(bytes) - 1, &length) < 0 ? errno : 0;
    if (close(fd) < 0 && !error)
        error = errno;
    if (error)
        return error == ENOENT || error == ESRCH ? 0 : failed(error);
    if (!length || memchr(bytes, 0, length) || bytes[length - 1] != '\n')
        return failed(EUCLEAN);
    bytes[length] = 0;
    const char* cursor = bytes;
    uint64_t actual;
    if (decimal(&cursor, INT32_MAX, &actual) < 0 || actual != (unsigned)pid || cursor[0] != ' ' ||
        cursor[1] != '(')
        return failed(EUCLEAN);
    // comm may contain spaces, newlines and parentheses. The numeric tail
    // follows the last closing parenthesis, not the first one.
    cursor = strrchr(cursor + 2, ')');
    if (!cursor || strlen(cursor) < 4 || cursor[1] != ' ' || !strchr("RSDZTtXxKWPI", cursor[2]) ||
        cursor[3] != ' ')
        return failed(EUCLEAN);
    cursor += 4;
    for (unsigned field = 4; field <= 22; field++) {
        int negative = *cursor == '-';
        if (negative)
            cursor++;
        uint64_t value;
        if (decimal(&cursor, field == 22 ? UINT64_MAX : UINT64_C(9223372036854775808), &value) <
                0 ||
            (field == 22 && negative) || *cursor != ' ')
            return failed(EUCLEAN);
        if (field == 22)
            *start = value;
        cursor++;
    }
    return 1;
}

static int process_capture(pid_t pid, uint64_t* start) {
    int result = process_start(pid, start);
    return result == 1 ? 0 : result < 0 ? -1 : failed(ESRCH);
}

static uint32_t checksum(const char* bytes, size_t length) {
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < length; i++) {
        crc ^= (unsigned char)bytes[i];
        for (unsigned bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
    }
    return crc ^ UINT32_MAX;
}

static int state_encode(const struct desktop_seat* seat, char bytes[state_limit], size_t* length) {
    int size =
        snprintf(bytes, state_limit,
                 "axiom64-seat=2\nboot=%s\nowner=%d:%llu\nserver=%d:%llu\nclients=%d:%llu\n"
                 "uid=%u\ngid=%u\n",
                 seat->boot, (int)seat->owner, (unsigned long long)seat->owner_start,
                 (int)seat->server, (unsigned long long)seat->server_start, (int)seat->clients,
                 (unsigned long long)seat->clients_start, (unsigned)seat->uid, (unsigned)seat->gid);
    if (size < 0 || size > state_limit - 14)
        return failed(EOVERFLOW);
    int tail = snprintf(bytes + size, state_limit - (size_t)size, "crc=%08x\n",
                        (unsigned)checksum(bytes, (size_t)size));
    if (tail != 13)
        return failed(EOVERFLOW);
    *length = (size_t)size + 13;
    return 0;
}

static int state_decode(const char* bytes, size_t length, struct desktop_seat* seat) {
    if (!length || length >= state_limit || memchr(bytes, 0, length))
        return failed(EUCLEAN);
    char buffer[state_limit];
    memcpy(buffer, bytes, length);
    buffer[length] = 0;
    const char* cursor = buffer;
    const char prefix[] = "axiom64-seat=2\nboot=";
    if (strncmp(cursor, prefix, sizeof(prefix) - 1))
        return failed(EUCLEAN);
    cursor += sizeof(prefix) - 1;
    if (strlen(cursor) < 37 || cursor[36] != '\n')
        return failed(EUCLEAN);
    memcpy(seat->boot, cursor, 36);
    seat->boot[36] = 0;
    if (!boot_valid(seat->boot))
        return failed(EUCLEAN);
    cursor += 37;
    const char* keys[] = {"owner=", "server=", "clients=", "uid=", "gid="};
    pid_t* pids[] = {&seat->owner, &seat->server, &seat->clients};
    uint64_t* starts[] = {&seat->owner_start, &seat->server_start, &seat->clients_start};
    for (unsigned field = 0; field < 5; field++) {
        size_t size = strlen(keys[field]);
        uint64_t value;
        if (strncmp(cursor, keys[field], size))
            return failed(EUCLEAN);
        cursor += size;
        if (decimal(&cursor, field < 3 ? INT32_MAX : UINT32_MAX - 1u, &value) < 0)
            return -1;
        if (field < 3) {
            *pids[field] = (pid_t)value;
            if (*cursor++ != ':' || decimal(&cursor, UINT64_MAX, starts[field]) < 0 ||
                (!value && *starts[field]))
                return failed(EUCLEAN);
        } else if (field == 3)
            seat->uid = (uid_t)value;
        else
            seat->gid = (gid_t)value;
        if (*cursor++ != '\n')
            return failed(EUCLEAN);
    }
    if (!seat->owner || !seat->uid || (seat->server && seat->owner == seat->server) ||
        (seat->clients && (seat->owner == seat->clients || seat->server == seat->clients)))
        return failed(EUCLEAN);
    size_t sealed = (size_t)(cursor - buffer);
    if (length - sealed != 13 || strncmp(cursor, "crc=", 4))
        return failed(EUCLEAN);
    uint32_t crc = 0;
    for (size_t i = 4; i < 12; i++) {
        unsigned digit = cursor[i] >= '0' && cursor[i] <= '9'   ? (unsigned)(cursor[i] - '0')
                         : cursor[i] >= 'a' && cursor[i] <= 'f' ? (unsigned)(cursor[i] - 'a' + 10)
                                                                : 16;
        if (digit == 16)
            return failed(EUCLEAN);
        crc = crc * 16 + digit;
    }
    return cursor[12] != '\n' || crc != checksum(buffer, sealed) ? failed(EUCLEAN) : 0;
}

static int state_write(int fd, void* opaque) {
    char bytes[state_limit];
    size_t length;
    if (state_encode(opaque, bytes, &length) < 0)
        return -1;
    for (size_t used = 0; used < length;) {
        ssize_t count = write(fd, bytes + used, length - used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return failed(count < 0 ? errno : EIO);
        used += (size_t)count;
    }
    return 0;
}

static int state_save(struct desktop_seat* seat) {
    seat->published = 1; // Publication can be visible even after a late fsync error.
    int result = account_file_publish(seat->directory, "state", 0600, state_write, seat);
    if (!result)
        seat->published = 1;
    return result;
}

static int temporary_name(const char* name) {
    if (strlen(name) != 34 || name[0] != 't' || name[1] != '-')
        return 0;
    for (size_t i = 2; i < 34; i++)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f')))
            return 0;
    return 1;
}

static int inventory_read(const struct desktop_seat* seat, struct inventory* inventory) {
    memset(inventory, 0, sizeof(*inventory));
    int fd = openat(seat->directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    DIR* stream = fdopendir(fd);
    if (!stream) {
        int error = errno;
        close(fd);
        return failed(error);
    }
    int error = 0;
    for (;;) {
        errno = 0;
        struct dirent* entry = readdir(stream);
        if (!entry) {
            error = errno;
            break;
        }
        const char* name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, ".."))
            continue;
        int lock = !strcmp(name, "lock"), state = !strcmp(name, "state");
        int known = lock || temporary_name(name);
        for (size_t i = 0; i < sizeof(files) / sizeof(*files); i++)
            known |= !strcmp(name, files[i]);
        if (!known || inventory->count == inventory_limit) {
            error = known ? E2BIG : EUCLEAN;
            break;
        }
        struct stat value;
        if (fstatat(seat->directory, name, &value, AT_SYMLINK_NOFOLLOW) < 0) {
            error = errno;
            break;
        }
        int user = !strcmp(name, "client.auth");
        if (!S_ISREG(value.st_mode) || value.st_nlink != 1 ||
            value.st_uid != (user ? seat->uid : 0) || value.st_gid != (user ? seat->gid : 0) ||
            (value.st_mode & 07777) != (user ? 0400 : 0600)) {
            error = EACCES;
            break;
        }
        inventory->state |= state;
        inventory->artifacts |= !lock && !state && !temporary_name(name);
        if (!lock && !state)
            strcpy(inventory->names[inventory->count++], name);
    }
    if (closedir(stream) < 0 && !error)
        error = errno;
    return error ? failed(error) : 0;
}

static int inventory_remove(const struct desktop_seat* seat, const struct inventory* inventory) {
    for (size_t i = 0; i < inventory->count; i++)
        if (unlinkat(seat->directory, inventory->names[i], 0) < 0)
            return -1;
    // Keep the complete ownership record until every artifact has retired.
    if (fsync(seat->directory) < 0)
        return -1;
    if (inventory->state && unlinkat(seat->directory, "state", 0) < 0)
        return -1;
    return fsync(seat->directory);
}

static int xorg_directory(int fd) {
    struct stat value;
    if (fstat(fd, &value) < 0)
        return -1;
    return !S_ISDIR(value.st_mode) || value.st_uid || value.st_gid ||
                   (value.st_mode & 07777) != 01777
               ? failed(EACCES)
               : 0;
}

static void xorg_close(struct xorg_inventory* inventory) {
    if (inventory->sockets >= 0)
        close(inventory->sockets);
    if (inventory->temporary >= 0)
        close(inventory->temporary);
}

static int xorg_lock(int directory, const char* name, pid_t server, struct stat* value,
                     int* present) {
    if (fstatat(directory, name, value, AT_SYMLINK_NOFOLLOW) < 0)
        return errno == ENOENT ? 0 : -1;
    *present = 1;
    if (!server)
        return failed(EUCLEAN);
    if (!S_ISREG(value->st_mode) || value->st_uid || value->st_gid ||
        (value->st_mode & 07777) != 0444 || value->st_size != 11)
        return failed(EACCES);
    int fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return -1;
    char bytes[11], expected[12];
    size_t length = 0;
    int error = read_complete(fd, bytes, sizeof(bytes), &length) < 0 ? errno : 0;
    if (close(fd) < 0 && !error)
        error = errno;
    if (!error && (snprintf(expected, sizeof(expected), "%10u\n", (unsigned)server) != 11 ||
                   length != 11 || memcmp(bytes, expected, 11)))
        error = EUCLEAN;
    return error ? failed(error) : 0;
}

static int xorg_read(const struct desktop_seat* seat, int recorded,
                     struct xorg_inventory* inventory) {
    *inventory = (struct xorg_inventory){.temporary = -1, .sockets = -1};
    inventory->temporary = open("/tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int error = inventory->temporary < 0 || xorg_directory(inventory->temporary) < 0 ? errno : 0;
    struct stat locks[2];
    if (!error && (xorg_lock(inventory->temporary, ".X0-lock", recorded ? seat->server : 0,
                             &locks[0], &inventory->lock) < 0 ||
                   xorg_lock(inventory->temporary, ".tX0-lock", recorded ? seat->server : 0,
                             &locks[1], &inventory->temporary_lock) < 0))
        error = errno;
    if (!error) {
        int linked = inventory->lock && inventory->temporary_lock &&
                     locks[0].st_dev == locks[1].st_dev && locks[0].st_ino == locks[1].st_ino;
        if ((inventory->lock && locks[0].st_nlink != (linked ? 2u : 1u)) ||
            (inventory->temporary_lock && locks[1].st_nlink != (linked ? 2u : 1u)))
            error = EACCES;
    }
    if (!error) {
        inventory->sockets = openat(inventory->temporary, ".X11-unix",
                                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (inventory->sockets < 0 && errno != ENOENT)
            error = errno;
        else if (inventory->sockets >= 0 && xorg_directory(inventory->sockets) < 0)
            error = errno;
    }
    struct stat socket;
    if (!error && inventory->sockets >= 0) {
        if (fstatat(inventory->sockets, "X0", &socket, AT_SYMLINK_NOFOLLOW) < 0) {
            if (errno != ENOENT)
                error = errno;
        } else {
            inventory->socket = 1;
            if (!recorded || !seat->server || !inventory->lock)
                error = EUCLEAN;
            else if (!S_ISSOCK(socket.st_mode) || socket.st_uid || socket.st_gid ||
                     socket.st_nlink != 1 || (socket.st_mode & 07777) != 0777)
                error = EACCES;
        }
    }
    if (error)
        xorg_close(inventory);
    return error ? failed(error) : 0;
}

static int xorg_remove(const struct xorg_inventory* inventory) {
    if (inventory->socket &&
        (unlinkat(inventory->sockets, "X0", 0) < 0 || fsync(inventory->sockets) < 0))
        return -1;
    if ((inventory->temporary_lock && unlinkat(inventory->temporary, ".tX0-lock", 0) < 0) ||
        (inventory->lock && unlinkat(inventory->temporary, ".X0-lock", 0) < 0))
        return -1;
    return fsync(inventory->temporary);
}

static int recover(struct desktop_seat* seat) {
    // Never clear another server's framebuffer or remove its authorization.
    if (display_available() < 0)
        return -1;
    int fd = account_file_open(seat->directory, "state", O_RDONLY, 0600, 0);
    int present = fd >= 0;
    if (!present && errno != ENOENT)
        return -1;
    struct desktop_seat saved = {.directory = seat->directory};
    if (present) {
        char bytes[state_limit];
        size_t size = 0;
        int error = read_complete(fd, bytes, sizeof(bytes) - 1, &size) < 0 ? errno : 0;
        if (close(fd) < 0 && !error)
            error = errno;
        if (error || state_decode(bytes, size, &saved) < 0)
            return error ? failed(error) : -1;
    }
    struct inventory inventory;
    if (inventory_read(&saved, &inventory) < 0)
        return -1;
    if (inventory.state != present || (!present && inventory.artifacts))
        return failed(EUCLEAN);
    if (present) {
        char boot[37];
        if (boot_identity(boot) < 0)
            return -1;
        if (!strcmp(boot, saved.boot)) {
            const pid_t pids[] = {saved.owner, saved.server, saved.clients};
            const uint64_t starts[] = {saved.owner_start, saved.server_start, saved.clients_start};
            for (size_t i = 0; i < sizeof(pids) / sizeof(*pids); i++) {
                if (!pids[i])
                    continue;
                uint64_t start;
                int live = process_start(pids[i], &start);
                if (live < 0)
                    return -1;
                if (live && start == starts[i])
                    return failed(EBUSY);
            }
        }
    }
    struct xorg_inventory xorg;
    if (xorg_read(&saved, present, &xorg) < 0)
        return -1;
    int error = clear_framebuffer() < 0 || xorg_remove(&xorg) < 0 ||
                        inventory_remove(&saved, &inventory) < 0
                    ? errno
                    : 0;
    xorg_close(&xorg);
    return error ? failed(error) : 0;
}

int desktop_seat_recover(void) {
    struct desktop_seat seat = {.directory = -1, .lock = -1};
    seat.directory = account_directory_open(DESKTOP_DIRECTORY, 0755, 1);
    if (seat.directory < 0)
        return -1;
    seat.lock = account_file_open(seat.directory, "lock", O_RDWR, 0600, 1);
    int error = seat.lock < 0 || flock(seat.lock, LOCK_EX | LOCK_NB) < 0 ? errno : 0;
    if (!error && recover(&seat) < 0)
        error = errno;
    if (seat.lock >= 0)
        close(seat.lock);
    close(seat.directory);
    return error ? failed(error) : 0;
}

static int private_file(struct desktop_seat* seat, const char* name, int user) {
    int fd =
        openat(seat->directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    int error = fchmod(fd, 0600) < 0 ? errno : 0;
    if (!error && user && (fchown(fd, seat->uid, seat->gid) < 0 || fchmod(fd, 0400) < 0))
        error = errno;
    if (error) {
        close(fd);
        return failed(error);
    }
    return fd;
}

static int close_extra(void) {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3u, UINT32_MAX, 0u) == 0)
        return 0;
    if (errno != ENOSYS && errno != EINVAL)
        return -1;
#endif
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0 || limit.rlim_cur > 1048576)
        return failed(EOVERFLOW);
    for (unsigned fd = 3; fd < limit.rlim_cur; fd++)
        close((int)fd);
    return 0;
}

static int child_gate(int gate, pid_t parent) {
    // The parent cannot publish a birth identity until fork returns. Keep every
    // child before exec until that identity is durably recorded, including a
    // crash before the child has installed its parent-death signal.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0 || getppid() != parent)
        return failed(ECHILD);
    char allowed = 0;
    ssize_t count;
    do {
        count = read(gate, &allowed, 1);
    } while (count < 0 && errno == EINTR);
    int error = count < 0 ? errno : count != 1 || allowed != 'G' ? ECANCELED : 0;
    if (close(gate) < 0 && !error)
        error = errno;
    if (!error && getppid() != parent)
        error = ECHILD;
    return error ? failed(error) : 0;
}

static void child(const struct account_profile* profile, int output, int server, pid_t parent,
                  int gate) {
    if (child_gate(gate, parent) < 0)
        _exit(126);
    int input = open("/dev/null", O_RDONLY);
    if (input < 0 || dup2(input, 0) < 0 || dup2(output, 1) < 0 || dup2(output, 2) < 0 ||
        close_extra() < 0 || setsid() < 0)
        _exit(126);
    for (int number = 1; number < NSIG; number++)
        if (number != SIGKILL && number != SIGSTOP && signal(number, SIG_DFL) == SIG_ERR &&
            errno != EINVAL)
            _exit(126);
    sigset_t mask;
    sigemptyset(&mask);
    if (sigprocmask(SIG_SETMASK, &mask, NULL) < 0)
        _exit(126);
    if (!server && (account_profile_environment(profile, "xterm") < 0 ||
                    account_profile_enter(profile, 0) < 0 || chdir(profile->home) < 0))
        _exit(126);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0 || getppid() != parent)
        _exit(126);
    if (server) {
        // Device access stays in this trusted root server. Every X client must
        // present the private session cookie; TCP listening is disabled.
        // Xorg resets its umask before opening a named log. Keep all diagnostics
        // on the already private stderr descriptor at its normal file verbosity.
        umask(077);
        execl("/usr/libexec/Xorg", "Xorg", ":0", "-config", "/etc/X11/xorg.conf", "-nolisten",
              "tcp", "-noreset", "-auth", DESKTOP_DIRECTORY "/server.auth", "-retro", "-dumbSched",
              "-extension", "GLX", "-logfile", "", "-verbose", "3", (char*)NULL);
    } else {
        umask(077);
        execl("/bin/busybox", "busybox", "sh", "/etc/desktop-client-session.sh", (char*)NULL);
    }
    _exit(127);
}

static int spawn_child(struct desktop_seat* seat, const struct account_profile* profile, int output,
                       int server) {
    int gate[2];
    if (pipe2(gate, O_CLOEXEC) < 0)
        return -1;
    pid_t pid = fork();
    int error = pid < 0 ? errno : 0;
    if (!pid) {
        close(gate[1]);
        child(profile, output, server, seat->owner, gate[0]);
    }
    close(gate[0]);
    if (!error) {
        pid_t* identity = server ? &seat->server : &seat->clients;
        uint64_t* birth = server ? &seat->server_start : &seat->clients_start;
        *identity = pid;
        if (process_capture(pid, birth) < 0 || state_save(seat) < 0)
            error = errno;
        if (!error) {
            ssize_t count;
            do {
                count = write(gate[1], "G", 1);
            } while (count < 0 && errno == EINTR);
            if (count != 1)
                error = count < 0 ? errno : EIO;
        }
    }
    if (close(gate[1]) < 0 && !error)
        error = errno;
    return error ? failed(error) : 0;
}

static int server_ready(const uint8_t cookie[16]) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct timeval timeout = {1, 0};
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, "/tmp/.X11-unix/X0");
    uint8_t request[48] = {'l', 0, 11, 0, 0, 0, 18, 0, 16, 0, 0, 0};
    memcpy(request + 12, "MIT-MAGIC-COOKIE-1", 18);
    memcpy(request + 32, cookie, 16);
    int result = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0 &&
        connect(fd, (struct sockaddr*)&address, sizeof(address)) == 0) {
        size_t sent = 0;
        while (sent < sizeof(request)) {
            ssize_t count = send(fd, request + sent, sizeof(request) - sent, MSG_NOSIGNAL);
            if (count < 0 && errno == EINTR)
                continue;
            if (count <= 0)
                break;
            sent += (size_t)count;
        }
        uint8_t prefix[8];
        size_t used = 0;
        while (sent == sizeof(request) && used < sizeof(prefix)) {
            ssize_t count = read(fd, prefix + used, sizeof(prefix) - used);
            if (count < 0 && errno == EINTR)
                continue;
            if (count <= 0)
                break;
            used += (size_t)count;
        }
        result = used == sizeof(prefix) && prefix[0] == 1 && prefix[2] == 11;
    }
    close(fd);
    explicit_bzero(request, sizeof(request));
    return result;
}

static int observe_child(pid_t* pid) {
    if (*pid <= 0)
        return failed(ECHILD);
    siginfo_t information = {0};
    // Keep an exited leader waitable until its owned group has retired. This
    // pins its numeric PID while cleanup signals that process group.
    int result = waitid(P_PID, (id_t)*pid, &information, WEXITED | WNOHANG | WNOWAIT);
    if (!result && information.si_pid == *pid)
        return failed(ECHILD);
    return result < 0 && errno != EINTR ? -1 : 0;
}

int desktop_seat_observe(struct desktop_seat* seat) {
    if (!seat)
        return failed(EINVAL);
    return observe_child(&seat->server) < 0 || observe_child(&seat->clients) < 0 ? -1 : 0;
}

static int stop_child(pid_t child) {
    if (child <= 0)
        return 0;
    siginfo_t information = {0};
    while (waitid(P_PID, (id_t)child, &information, WEXITED | WNOHANG | WNOWAIT) < 0) {
        if (errno != EINTR)
            return -1;
    }
    int error = kill(-child, SIGKILL) < 0 && errno != ESRCH ? errno : 0;
    if (kill(child, SIGKILL) < 0 && errno != ESRCH)
        return -1;
    pid_t result;
    do {
        result = waitpid(child, NULL, 0);
    } while (result < 0 && errno == EINTR);
    if (result < 0)
        return -1;
    return error ? failed(error) : 0;
}

int desktop_seat_stop(struct desktop_seat* seat) {
    if (!seat)
        return 0;
    int error = stop_child(seat->server) < 0 ? errno : 0;
    if (stop_child(seat->clients) < 0 && !error)
        error = errno;
    struct inventory inventory;
    struct xorg_inventory xorg;
    if (!error && inventory_read(seat, &inventory) < 0)
        error = errno;
    if (!error && xorg_read(seat, seat->published, &xorg) < 0)
        error = errno;
    else if (!error) {
        if (clear_framebuffer() < 0 || xorg_remove(&xorg) < 0 ||
            inventory_remove(seat, &inventory) < 0)
            error = errno;
        xorg_close(&xorg);
    }
    if (seat->lock >= 0)
        close(seat->lock);
    if (seat->directory >= 0)
        close(seat->directory);
    explicit_bzero(seat, sizeof(*seat));
    free(seat);
    return error ? failed(error) : 0;
}

int desktop_seat_start(const struct account_profile* profile, struct desktop_seat** output) {
    if (!profile || !output || profile->uid == 0 || profile->uid == (uid_t)-1 ||
        profile->gid == (gid_t)-1 || geteuid() || getegid())
        return failed(EACCES);
    *output = NULL;
    struct desktop_seat* seat = calloc(1, sizeof(*seat));
    if (!seat)
        return -1;
    seat->directory = account_directory_open(DESKTOP_DIRECTORY, 0755, 1);
    seat->owner = getpid();
    seat->lock = -1;
    int error = seat->directory < 0 ? errno : 0;
    if (!error) {
        seat->lock = account_file_open(seat->directory, "lock", O_RDWR, 0600, 1);
        if (seat->lock < 0 || flock(seat->lock, LOCK_EX | LOCK_NB) < 0)
            error = errno;
    }
    if (!error && recover(seat) < 0)
        error = errno;
    seat->uid = profile->uid;
    seat->gid = profile->gid;
    if (!error && boot_identity(seat->boot) < 0)
        error = errno;
    if (!error && process_capture(seat->owner, &seat->owner_start) < 0)
        error = errno;
    if (!error && (account_nonce(seat->cookie) < 0 || state_save(seat) < 0))
        error = errno;
    for (unsigned user = 0; !error && user < 2; user++) {
        int fd = private_file(seat, user ? "client.auth" : "server.auth", user);
        if (fd < 0)
            error = errno;
        else {
            if (desktop_authority_write(fd, 0, seat->cookie) < 0 || fsync(fd) < 0)
                error = errno;
            close(fd);
        }
    }
    int server_log = -1, client_log = -1;
    if (!error) {
        server_log = private_file(seat, "server.log", 0);
        client_log = private_file(seat, "clients.log", 0);
        if (server_log < 0 || client_log < 0)
            error = errno;
    }
    if (!error) {
        if (spawn_child(seat, profile, server_log, 1) < 0)
            error = errno;
    }
    unsigned attempt = 0;
    for (; !error && attempt < 100; attempt++) {
        if (observe_child(&seat->server) < 0) {
            error = errno;
            break;
        }
        if (server_ready(seat->cookie) == 1)
            break;
        struct timespec delay = {0, 100000000};
        nanosleep(&delay, NULL);
    }
    if (!error && attempt == 100)
        error = ETIMEDOUT;
    if (!error) {
        if (spawn_child(seat, profile, client_log, 0) < 0)
            error = errno;
    }
    if (server_log >= 0)
        close(server_log);
    if (client_log >= 0)
        close(client_log);
    if (error) {
        if (seat->published) {
            int diagnostic = account_file_open(seat->directory, "server.log", O_RDONLY, 0600, 0);
            if (diagnostic >= 0) {
                char bytes[8192];
                ssize_t size = read(diagnostic, bytes, sizeof(bytes));
                if (size > 0) {
                    ssize_t written = write(2, bytes, (size_t)size);
                    (void)written;
                }
                close(diagnostic);
            }
            desktop_seat_stop(seat);
        } else {
            if (seat->lock >= 0)
                close(seat->lock);
            if (seat->directory >= 0)
                close(seat->directory);
            explicit_bzero(seat, sizeof(*seat));
            free(seat);
        }
        return failed(error);
    }
    dprintf(1, "\nACCOUNT_DESKTOP_READY uid=%u server=%d clients=%d\n", (unsigned)profile->uid,
            (int)seat->server, (int)seat->clients);
    *output = seat;
    return 0;
}
