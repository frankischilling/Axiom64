// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../desktop/authority.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "DESKTOP_LOGIN_FAIL line=%d errno=%d expression=%s\n", __LINE__,       \
                    errno, #expression);                                                           \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static int wait_child(pid_t child, int expected) {
    int status;
    CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
          WEXITSTATUS(status) == expected);
    return 0;
}

static int private_file(const char* name) {
    int fd = open(name, O_RDWR | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat info;
    if (fd < 0)
        return -1;
    if (fstat(fd, &info) < 0 || !S_ISREG(info.st_mode) || info.st_nlink != 1 ||
        info.st_uid != getuid() || (info.st_mode & 07777) != 0600) {
        close(fd);
        errno = EACCES;
        return -1;
    }
    return fd;
}

static int probe(const char* authority, int expected) {
    pid_t child = fork();
    if (!child) {
        if (setenv("XAUTHORITY", authority, 1) < 0)
            _exit(126);
        execl("/bin/x11-probe", "x11-probe", "--ready", (char*)NULL);
        _exit(127);
    }
    return wait_child(child, expected);
}

static int authorization(void) {
    CHECK(getuid() == 1000 && geteuid() == 1000 && getgid() == 1000);
    int bash = 0;
    const char* shell;
    setusershell();
    while ((shell = getusershell()))
        bash |= !strcmp(shell, "/bin/bash");
    endusershell();
    CHECK(bash);
    struct stat info;
    CHECK(lstat("/run/axiom64-seat/client.auth", &info) == 0 && S_ISREG(info.st_mode) &&
          info.st_nlink == 1 && info.st_uid == 1000 && info.st_gid == 1000 &&
          (info.st_mode & 07777) == 0400);
    uint8_t cookie[16];
    CHECK(desktop_authority_read("/run/axiom64-seat/client.auth", 0, cookie) == 0);
    CHECK(probe("/run/axiom64-seat/client.auth", 0) == 0 && probe("", 1) == 0);
    uint8_t wrong[16];
    for (unsigned i = 0; i < sizeof(wrong); i++)
        wrong[i] = cookie[i] ^ 0xff;
    int fd = private_file("wrong.auth");
    CHECK(fd >= 0 && desktop_authority_write(fd, 0, wrong) == 0 && fsync(fd) == 0);
    close(fd);
    explicit_bzero(wrong, sizeof(wrong));
    CHECK(probe("/home/admin/wrong.auth", 1) == 0);
    int rotated = 0;
    if (lstat("stale.auth", &info) == 0) {
        CHECK(probe("/home/admin/stale.auth", 1) == 0);
        rotated = 1;
    } else
        CHECK(errno == ENOENT);
    fd = private_file("stale.auth");
    CHECK(fd >= 0 && desktop_authority_write(fd, 0, cookie) == 0 && fsync(fd) == 0);
    close(fd);
    explicit_bzero(cookie, sizeof(cookie));
    puts(rotated ? "DESKTOP_AUTH_PASS valid=1 absent_denied=1 wrong_denied=1 rotated=1"
                 : "DESKTOP_AUTH_PASS valid=1 absent_denied=1 wrong_denied=1 rotated=0");
    return 0;
}

static int graphical(void) {
    CHECK(getuid() == 1000 && geteuid() == 1000 && getgid() == 1000 && isatty(0));
    CHECK(getenv("DISPLAY") && !strcmp(getenv("DISPLAY"), ":0"));
    CHECK(getenv("XAUTHORITY") && !strcmp(getenv("XAUTHORITY"), "/run/axiom64-seat/client.auth"));
    CHECK(getenv("TERM") && !strcmp(getenv("TERM"), "xterm"));
    int fd = private_file("graphical-proof");
    CHECK(fd >= 0);
    CHECK(dprintf(fd, "DESKTOP_PROFILE_SHELL %.128s\n",
                  getenv("SHELL") ? getenv("SHELL") : "absent") > 0);
    pid_t child = fork();
    if (!child) {
        if (dup2(fd, 1) < 0 || dup2(fd, 2) < 0)
            _exit(126);
        execl("/usr/bin/account-normal-observe", "account-normal-observe", "identity", (char*)NULL);
        _exit(127);
    }
    int result = wait_child(child, 0);
    CHECK(fsync(fd) == 0);
    close(fd);
    fd = open("graphical-done", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    CHECK(fd >= 0 && write(fd, "done\n", 5) == 5 && fsync(fd) == 0);
    close(fd);
    return result;
}

static int graphical_result(void) {
    CHECK(getuid() == 1000 && geteuid() == 1000);
    int fd = open("graphical-proof", O_RDONLY | O_NOFOLLOW);
    struct stat info;
    CHECK(fd >= 0 && fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1 &&
          info.st_uid == 1000 && info.st_gid == 1000 && (info.st_mode & 07777) == 0600);
    char text[1024] = {0};
    ssize_t size = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (size > 0 && strstr(text, "FAIL")) {
        ssize_t written = write(2, text, (size_t)size);
        (void)written;
    }
    CHECK(size > 0 && strstr(text, "ACCOUNT_NORMAL_IDENTITY_PASS uid=1000 gid=1000 groups=2 ") &&
          !strstr(text, "FAIL"));
    CHECK(unlink("graphical-proof") == 0 && unlink("graphical-done") == 0);
    puts("DESKTOP_KEYBOARD_IDENTITY_PASS uid=1000 gid=1000 groups=2 caps=0 tty=private "
         "home=private shadow_denied=1");
    return 0;
}

static int foreign(uid_t uid, pid_t server, pid_t clients) {
    CHECK(setgroups(0, NULL) == 0 && setresgid(uid, uid, uid) == 0 &&
          setresuid(uid, uid, uid) == 0);
    CHECK(open("/run/axiom64-seat/client.auth", O_RDONLY) == -1 && errno == EACCES);
    CHECK(open("/run/axiom64-seat/server.auth", O_RDONLY) == -1 && errno == EACCES);
    const char* devices[] = {"/dev/console", "/dev/ttyS0",        "/dev/tty0",        "/dev/tty1",
                             "/dev/fb0",     "/dev/input/event0", "/dev/input/event1"};
    for (unsigned i = 0; i < sizeof(devices) / sizeof(*devices); i++)
        CHECK(open(devices[i], O_RDWR) == -1 && errno == EACCES);
    CHECK(kill(server, 0) == -1 && errno == EPERM);
    CHECK(kill(clients, 0) == -1 && errno == EPERM);
    return 0;
}

struct seat_record {
    uint64_t pid[3], birth[3], uid, gid;
    char boot[37];
};

static int read_record(const char* path, char* bytes, size_t capacity, size_t* length, int proc) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0);
    if (proc) {
        struct statfs filesystem;
        CHECK(fstatfs(fd, &filesystem) == 0 && filesystem.f_type == 0x9fa0);
    }
    *length = 0;
    for (;;) {
        char extra;
        ssize_t count = read(fd, *length < capacity - 1 ? bytes + *length : &extra,
                             *length < capacity - 1 ? capacity - 1 - *length : 1);
        if (count < 0 && errno == EINTR)
            continue;
        CHECK(count >= 0);
        if (!count)
            break;
        CHECK(*length < capacity - 1);
        *length += (size_t)count;
    }
    CHECK(close(fd) == 0 && !memchr(bytes, 0, *length));
    bytes[*length] = 0;
    return 0;
}

static int key(const char** cursor, const char* expected) {
    size_t length = strlen(expected);
    CHECK(!strncmp(*cursor, expected, length));
    *cursor += length;
    return 0;
}

static int number(const char** cursor, uint64_t maximum, uint64_t* output) {
    const char* text = *cursor;
    CHECK(*text >= '0' && *text <= '9');
    CHECK(*text != '0' || text[1] < '0' || text[1] > '9');
    uint64_t result = 0;
    do {
        unsigned digit = (unsigned)(*text++ - '0');
        CHECK(result < maximum / 10 || (result == maximum / 10 && digit <= maximum % 10));
        result = result * 10 + digit;
    } while (*text >= '0' && *text <= '9');
    *cursor = text;
    *output = result;
    return 0;
}

static int seat_record(const char* bytes, size_t length, struct seat_record* record) {
    const char* cursor = bytes;
    CHECK(key(&cursor, "axiom64-seat=2\nboot=") == 0 && strlen(cursor) >= 37);
    memcpy(record->boot, cursor, 36);
    record->boot[36] = 0;
    for (size_t i = 0; i < 36; i++)
        if (i == 8 || i == 13 || i == 18 || i == 23)
            CHECK(record->boot[i] == '-');
        else
            CHECK((record->boot[i] >= '0' && record->boot[i] <= '9') ||
                  (record->boot[i] >= 'a' && record->boot[i] <= 'f'));
    cursor += 36;
    CHECK(key(&cursor, "\n") == 0);
    const char* keys[] = {"owner=", "server=", "clients="};
    for (size_t i = 0; i < 3; i++) {
        CHECK(key(&cursor, keys[i]) == 0 && number(&cursor, INT32_MAX, &record->pid[i]) == 0 &&
              key(&cursor, ":") == 0 && number(&cursor, UINT64_MAX, &record->birth[i]) == 0 &&
              key(&cursor, "\n") == 0 && record->pid[i] > 1);
    }
    CHECK(record->pid[0] != record->pid[1] && record->pid[0] != record->pid[2] &&
          record->pid[1] != record->pid[2]);
    CHECK(key(&cursor, "uid=") == 0 && number(&cursor, UINT32_MAX - 1u, &record->uid) == 0 &&
          key(&cursor, "\ngid=") == 0 && number(&cursor, UINT32_MAX - 1u, &record->gid) == 0 &&
          key(&cursor, "\n") == 0);
    uint32_t crc = UINT32_MAX;
    for (const char* byte = bytes; byte < cursor; byte++) {
        crc ^= (unsigned char)*byte;
        for (unsigned bit = 0; bit < 8; bit++)
            crc = crc & 1 ? crc >> 1 ^ UINT32_C(0xedb88320) : crc >> 1;
    }
    CHECK(key(&cursor, "crc=") == 0 && length - (size_t)(cursor - bytes) == 9);
    char expected[10];
    CHECK(snprintf(expected, sizeof(expected), "%08x\n", crc ^ UINT32_MAX) == 9);
    CHECK(!strcmp(cursor, expected));
    return 0;
}

static int process_birth(uint64_t pid, uint64_t* output) {
    char path[64], bytes[4096];
    size_t length;
    snprintf(path, sizeof(path), "/proc/%u/stat", (unsigned)pid);
    CHECK(read_record(path, bytes, sizeof(bytes), &length, 1) == 0 && length > 4);
    const char* cursor = bytes;
    uint64_t identity;
    CHECK(number(&cursor, INT32_MAX, &identity) == 0 && identity == pid && cursor[0] == ' ' &&
          cursor[1] == '(');
    cursor = strrchr(cursor, ')');
    CHECK(cursor && strlen(cursor) > 4 && cursor[1] == ' ' && cursor[3] == ' ');
    cursor += 4;
    for (unsigned field = 4; field < 22; field++) {
        const char* end = strchr(cursor, ' ');
        CHECK(end && end != cursor);
        cursor = end + 1;
    }
    CHECK(number(&cursor, UINT64_MAX, output) == 0 && *cursor == ' ');
    return 0;
}

static int xorg_metadata(pid_t server) {
    const char* logs[] = {"server.log", "clients.log"};
    struct stat value;
    for (size_t i = 0; i < sizeof(logs) / sizeof(*logs); i++) {
        char path[128];
        snprintf(path, sizeof(path), "/run/axiom64-seat/%s", logs[i]);
        CHECK(lstat(path, &value) == 0 && S_ISREG(value.st_mode) && value.st_nlink == 1 &&
              !value.st_uid && !value.st_gid && (value.st_mode & 07777) == 0600);
    }
    CHECK(lstat("/run/axiom64-seat/Xorg.log", &value) == -1 && errno == ENOENT);
    CHECK(lstat("/run/axiom64-seat/Xorg.log.old", &value) == -1 && errno == ENOENT);
    int log = open("/run/axiom64-seat/server.log", O_RDONLY | O_NOFOLLOW);
    CHECK(log >= 0);
    char diagnostic[4096] = {0};
    ssize_t logged = read(log, diagnostic, sizeof(diagnostic) - 1);
    CHECK(logged > 0 && close(log) == 0 && strstr(diagnostic, "X.Org X Server"));
    CHECK(lstat("/tmp/.X11-unix", &value) == 0 && S_ISDIR(value.st_mode) && !value.st_uid &&
          !value.st_gid && (value.st_mode & 07777) == 01777);
    CHECK(lstat("/tmp/.X11-unix/X0", &value) == 0 && S_ISSOCK(value.st_mode) &&
          value.st_nlink == 1 && !value.st_uid && !value.st_gid && (value.st_mode & 07777) == 0777);
    CHECK(lstat("/tmp/.X0-lock", &value) == 0 && S_ISREG(value.st_mode) && value.st_nlink == 1 &&
          !value.st_uid && !value.st_gid && (value.st_mode & 07777) == 0444 && value.st_size == 11);
    char lock[12], expected[12];
    size_t length;
    CHECK(read_record("/tmp/.X0-lock", lock, sizeof(lock), &length, 0) == 0 && length == 11);
    CHECK(snprintf(expected, sizeof(expected), "%10u\n", (unsigned)server) == 11 &&
          !strcmp(lock, expected));
    return 0;
}

static int privileged(void) {
    CHECK(!getuid() && !geteuid() && !getgid() && !getegid());
    pid_t normal = fork();
    if (!normal) {
        execl("/usr/bin/account-normal-observe", "account-normal-observe", "protected",
              (char*)NULL);
        _exit(127);
    }
    CHECK(wait_child(normal, 0) == 0);
    int fd = open("/run/axiom64-seat/state", O_RDONLY | O_NOFOLLOW);
    struct stat info;
    CHECK(fd >= 0 && fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1 &&
          !info.st_uid && !info.st_gid && (info.st_mode & 07777) == 0600);
    CHECK(close(fd) == 0);
    char state[512], boot[38];
    size_t size;
    struct seat_record record;
    CHECK(read_record("/run/axiom64-seat/state", state, sizeof(state), &size, 0) == 0 &&
          seat_record(state, size, &record) == 0 && record.uid == 1000 && record.gid == 1000);
    CHECK(read_record("/proc/sys/kernel/random/boot_id", boot, sizeof(boot), &size, 1) == 0 &&
          size == 37 && boot[36] == '\n' && !memcmp(boot, record.boot, 36));
    for (size_t i = 0; i < 3; i++) {
        uint64_t birth;
        CHECK(process_birth(record.pid[i], &birth) == 0 && birth == record.birth[i]);
    }
    int owner = (int)record.pid[0], server = (int)record.pid[1], clients = (int)record.pid[2];
    CHECK(xorg_metadata(server) == 0);
    printf("DESKTOP_SEAT_IDENTITY_PASS version=2 boot=%s owner=%d:%llu server=%d:%llu "
           "clients=%d:%llu logs_mode=0600 xorg_lock_mode=0444 xorg_socket_mode=0777\n",
           record.boot, owner, (unsigned long long)record.birth[0], server,
           (unsigned long long)record.birth[1], clients, (unsigned long long)record.birth[2]);
    CHECK(kill(owner, 0) == 0 && kill(server, 0) == 0 && kill(clients, 0) == 0);
    CHECK(lstat("/run/axiom64-seat/server.auth", &info) == 0 && S_ISREG(info.st_mode) &&
          info.st_nlink == 1 && !info.st_uid && !info.st_gid && (info.st_mode & 07777) == 0600);
    pid_t child = fork();
    if (!child)
        _exit(foreign(1001, server, clients));
    CHECK(wait_child(child, 0) == 0);
    // The logged-in owner also cannot access trusted raw devices or signal Xorg.
    child = fork();
    if (!child) {
        if (setgroups(0, NULL) < 0 || setresgid(1000, 1000, 1000) < 0 ||
            setresuid(1000, 1000, 1000) < 0)
            _exit(126);
        int denied = open("/run/axiom64-seat/server.auth", O_RDONLY) == -1 && errno == EACCES &&
                     open("/dev/fb0", O_RDWR) == -1 && errno == EACCES && kill(server, 0) == -1 &&
                     errno == EPERM && kill(clients, 0) == 0;
        _exit(denied ? 0 : 1);
    }
    CHECK(wait_child(child, 0) == 0);
    printf("DESKTOP_PROTECTED_PASS foreign_uid=1001 cookie_denied=1 devices_denied=7 "
           "process_denied=2 owner_server_denied=1 owner=%d server=%d clients=%d\n",
           owner, server, clients);
    return 0;
}

static int retired(int argc, char** argv) {
    CHECK(!getuid() && !geteuid() && argc > 2 && argc <= 32);
    for (int i = 2; i < argc; i++) {
        char* end;
        long pid = strtol(argv[i], &end, 10);
        CHECK(!*end && pid > 1 && pid <= INT32_MAX);
        CHECK(kill((pid_t)pid, 0) == -1 && errno == ESRCH);
    }
    printf("DESKTOP_RETIRED_PASS processes=%d\n", argc - 2);
    return 0;
}

int main(int argc, char** argv) {
    if (argc >= 3 && !strcmp(argv[1], "retired"))
        return retired(argc, argv);
    if (argc >= 2 && !strcmp(argv[1], "protected")) {
        if (argc > 2 && retired(argc, argv))
            return 1;
        return privileged();
    }
    CHECK(argc == 2);
    if (!strcmp(argv[1], "authorization"))
        return authorization();
    if (!strcmp(argv[1], "graphical"))
        return graphical();
    if (!strcmp(argv[1], "result"))
        return graphical_result();
    return 1;
}
