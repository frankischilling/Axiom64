// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <sys/mount.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifndef FILECAP_LINKAGE
#define FILECAP_LINKAGE "static"
#endif

static unsigned observations, checks;
#define CHECK(expression)                                                                          \
    do {                                                                                           \
        checks++;                                                                                  \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "FILECAP_TEST_FAIL line=%d expression=%s errno=%d\n", __LINE__,        \
                    #expression, errno);                                                           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void observe(const char* name, long result, long expected, int error) {
    int actual_error = result < 0 ? errno : 0;
    int passed = result == expected && actual_error == error;
    printf("FILECAP_OBSERVATION pid=%d id=%u name=%s result=%ld errno=%d expected=%ld "
           "expected_errno=%d passed=%d\n",
           getpid(), ++observations, name, result, actual_error, expected, error, passed);
    fflush(stdout);
    CHECK(passed);
}

#define RESULT(name, expression, expected) observe(name, (expression), expected, 0)
#define ERROR(name, expression, error) observe(name, (expression), -1, error)

static void wait_child(pid_t child) {
    int status;
    CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
          WEXITSTATUS(status) == 0);
}

static void drop(uid_t uid) {
    CHECK(setgroups(0, NULL) == 0);
    CHECK(setresgid(uid, uid, uid) == 0);
    CHECK(setresuid(uid, uid, uid) == 0);
}

static void make_file(const char* name, mode_t mode) {
    int fd = open(name, O_CREAT | O_TRUNC | O_RDWR, mode);
    CHECK(fd >= 0 && write(fd, "original", 8) == 8 && close(fd) == 0);
    CHECK(chmod(name, mode) == 0);
}

static void expect_value(const char* path, const char* name, const void* value, size_t size) {
    unsigned char actual[256];
    memset(actual, 0xa5, sizeof(actual));
    CHECK(size <= sizeof(actual));
    RESULT("read-value", getxattr(path, name, actual, sizeof(actual)), (long)size);
    CHECK(!memcmp(value, actual, size) && actual[size] == 0xa5);
}

static void xattr_contract(void) {
    unsigned before = observations;
    make_file("regular", 0666);
    CHECK(symlink("regular", "symlink") == 0);
    const unsigned char value[] = {0, 255, 1, 2, 0};
    char actual[128];
    int fd = open("regular", O_RDONLY);
    CHECK(fd >= 0);
    RESULT("setxattr", setxattr("regular", "user.path", value, sizeof(value), 0), 0);
    RESULT("lsetxattr-regular", lsetxattr("regular", "user.nofollow", "L", 1, 0), 0);
    RESULT("fsetxattr-readonly-fd", fsetxattr(fd, "user.fd", "F", 1, 0), 0);
    RESULT("getxattr", getxattr("regular", "user.path", actual, sizeof(actual)), sizeof(value));
    CHECK(!memcmp(actual, value, sizeof(value)));
    RESULT("lgetxattr-regular", lgetxattr("regular", "user.nofollow", actual, sizeof(actual)), 1);
    CHECK(actual[0] == 'L');
    RESULT("fgetxattr", fgetxattr(fd, "user.fd", actual, sizeof(actual)), 1);
    CHECK(actual[0] == 'F');
    RESULT("listxattr", listxattr("regular", actual, sizeof(actual)), 32);
    RESULT("llistxattr-regular", llistxattr("regular", actual, sizeof(actual)), 32);
    RESULT("flistxattr", flistxattr(fd, actual, sizeof(actual)), 32);
    RESULT("removexattr", removexattr("regular", "user.path"), 0);
    RESULT("lremovexattr-regular", lremovexattr("regular", "user.nofollow"), 0);
    RESULT("fremovexattr", fremovexattr(fd, "user.fd"), 0);
    RESULT("empty-list-query", listxattr("regular", NULL, 0), 0);
    ERROR("missing-get", getxattr("regular", "user.absent", actual, sizeof(actual)), ENODATA);
    ERROR("missing-remove", removexattr("regular", "user.absent"), ENODATA);
    ERROR("replace-absent", setxattr("regular", "user.flags", "v", 1, XATTR_REPLACE), ENODATA);
    ERROR("create-replace-absent", setxattr("regular", "user.flags", "v", 1, 3), ENODATA);
    RESULT("create", setxattr("regular", "user.flags", value, sizeof(value), XATTR_CREATE), 0);
    ERROR("create-present", setxattr("regular", "user.flags", "v", 1, XATTR_CREATE), EEXIST);
    ERROR("create-replace-present", setxattr("regular", "user.flags", "v", 1, 3), EEXIST);
    ERROR("invalid-flags", setxattr("regular", "user.flags", "v", 1, 4), EINVAL);
    expect_value("regular", "user.flags", value, sizeof(value));
    RESULT("replace", setxattr("regular", "user.flags", "replacement", 11, XATTR_REPLACE), 0);
    RESULT("length-query", getxattr("regular", "user.flags", (void*)1, 0), 11);
    memset(actual, 0xa5, sizeof(actual));
    ERROR("short-value", getxattr("regular", "user.flags", actual, 10), ERANGE);
    CHECK((unsigned char)actual[0] == 0xa5 && (unsigned char)actual[10] == 0xa5);
    RESULT("set-empty", setxattr("regular", "user.empty", NULL, 0, 0), 0);
    RESULT("get-empty", getxattr("regular", "user.empty", actual, 1), 0);
    ERROR("empty-name", getxattr("regular", "", actual, sizeof(actual)), ERANGE);
    ERROR("empty-suffix", setxattr("regular", "user.", "v", 1, 0), EINVAL);
    ERROR("unknown-namespace", setxattr("regular", "unknown.value", "v", 1, 0), EOPNOTSUPP);
    char long_name[257];
    memcpy(long_name, "user.", 5);
    memset(long_name + 5, 'a', 250);
    long_name[255] = 0;
    RESULT("max-name", setxattr("regular", long_name, "v", 1, 0), 0);
    RESULT("max-name-remove", removexattr("regular", long_name), 0);
    long_name[255] = 'a';
    long_name[256] = 0;
    ERROR("long-name", setxattr("regular", long_name, "v", 1, 0), ERANGE);
    ERROR("large-value", syscall(SYS_setxattr, "regular", "user.big", 1, 65537, 0), E2BIG);
    ERROR("fault-name", syscall(SYS_getxattr, "regular", 1, actual, sizeof(actual)), EFAULT);
    ERROR("fault-path", syscall(SYS_getxattr, 1, "user.flags", actual, sizeof(actual)), EFAULT);
    ERROR("fault-input", syscall(SYS_setxattr, "regular", "user.flags", 1, 11, 0), EFAULT);
    expect_value("regular", "user.flags", "replacement", 11);
    ERROR("fault-output", syscall(SYS_getxattr, "regular", "user.flags", 1, 11), EFAULT);
    RESULT("list-query", listxattr("regular", (void*)1, 0), 22);
    memset(actual, 0xa5, sizeof(actual));
    ERROR("short-list", listxattr("regular", actual, 21), ERANGE);
    CHECK((unsigned char)actual[0] == 0xa5 && (unsigned char)actual[21] == 0xa5);
    ERROR("fault-list", syscall(SYS_listxattr, "regular", 1, 22), EFAULT);
    ERROR("bad-fd", fgetxattr(-1, "user.flags", actual, sizeof(actual)), EBADF);
    int pathfd = open("regular", O_PATH);
    CHECK(pathfd >= 0);
    ERROR("opath-get", fgetxattr(pathfd, "user.flags", actual, sizeof(actual)), EBADF);
    ERROR("opath-list", flistxattr(pathfd, actual, sizeof(actual)), EBADF);
    ERROR("opath-set", fsetxattr(pathfd, "user.opath", "v", 1, 0), EBADF);
    ERROR("opath-remove", fremovexattr(pathfd, "user.flags"), EBADF);
    CHECK(close(pathfd) == 0);
    expect_value("symlink", "user.flags", "replacement", 11);
    RESULT("follow-set", setxattr("symlink", "user.follow", "yes", 3, 0), 0);
    ERROR("nofollow-user-set", lsetxattr("symlink", "user.link", "no", 2, 0), EPERM);
    ERROR("nofollow-user-get", lgetxattr("symlink", "user.flags", actual, sizeof(actual)), ENODATA);
    RESULT("nofollow-empty-list", llistxattr("symlink", actual, sizeof(actual)), 0);
    RESULT("nofollow-security-set", lsetxattr("symlink", "security.custom", "metadata", 8, 0), 0);
    RESULT("nofollow-security-get", lgetxattr("symlink", "security.custom", actual, sizeof(actual)),
           8);
    CHECK(!memcmp(actual, "metadata", 8));
    RESULT("nofollow-security-list", llistxattr("symlink", actual, sizeof(actual)), 16);
    CHECK(!strcmp(actual, "security.custom"));
    RESULT("symlink-content-preserved", readlink("symlink", actual, sizeof(actual)), 7);
    CHECK(!memcmp(actual, "regular", 7));
    CHECK(link("regular", "alias") == 0 && rename("regular", "renamed") == 0);
    expect_value("alias", "user.flags", "replacement", 11);
    CHECK(unlink("renamed") == 0 && unlink("alias") == 0);
    ERROR("unlinked-path", getxattr("renamed", "user.flags", actual, sizeof(actual)), ENOENT);
    RESULT("unlinked-fd-get", fgetxattr(fd, "user.flags", actual, sizeof(actual)), 11);
    CHECK(!memcmp(actual, "replacement", 11));
    RESULT("unlinked-fd-set", fsetxattr(fd, "user.fd-lifetime", "live", 4, 0), 0);
    RESULT("unlinked-fd-remove", fremovexattr(fd, "user.flags"), 0);
    if (getenv("FILECAP_SHARED_MAPPING")) {
        unsigned char* maximum = malloc(65536);
        unsigned char* output = malloc(65537);
        CHECK(maximum && output);
        for (unsigned i = 0; i < 65536; i++) {
            maximum[i] = (unsigned char)(i * 31 + i / 256);
        }
        RESULT("max-value-set", fsetxattr(fd, "user.maximum", maximum, 65536, 0), 0);
        RESULT("max-value-query", fgetxattr(fd, "user.maximum", (void*)1, 0), 65536);
        memset(output, 0xa5, 65537);
        ERROR("max-value-short", fgetxattr(fd, "user.maximum", output, 65535), ERANGE);
        for (unsigned i = 0; i < 65537; i++) {
            CHECK(output[i] == 0xa5);
        }
        ERROR("max-value-overflow", syscall(SYS_fsetxattr, fd, "user.maximum", 1, 65537, 0), E2BIG);
        RESULT("max-value-clamped-get", fgetxattr(fd, "user.maximum", output, 65537), 65536);
        CHECK(!memcmp(maximum, output, 65536) && output[65536] == 0xa5);
        RESULT("max-value-remove", fremovexattr(fd, "user.maximum"), 0);
        printf("FILECAP_RAM_BOUNDARY_PASS size=65536 bytes_equal=1 tail=%u\n", output[65536]);
        free(output);
        free(maximum);
    }
    CHECK(close(fd) == 0 && unlink("symlink") == 0);
    make_file("permission", 0600);
    RESULT("trusted-root-set", setxattr("permission", "trusted.private", "secret", 6, 0), 0);
    RESULT("security-root-set", setxattr("permission", "security.custom", "metadata", 8, 0), 0);
    RESULT("user-root-set", setxattr("permission", "user.private", "owned", 5, 0), 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        ERROR("user-read-dac", getxattr("permission", "user.private", actual, sizeof(actual)),
              EACCES);
        ERROR("user-write-dac", setxattr("permission", "user.private", "v", 1, 0), EACCES);
        ERROR("trusted-read-hidden",
              getxattr("permission", "trusted.private", actual, sizeof(actual)), ENODATA);
        ERROR("trusted-write-admin", setxattr("permission", "trusted.private", "v", 1, 0), EPERM);
        ERROR("security-write-admin", setxattr("permission", "security.custom", "v", 1, 0), EPERM);
        RESULT("security-read-no-dac",
               getxattr("permission", "security.custom", actual, sizeof(actual)), 8);
        RESULT("list-no-dac-filtered", listxattr("permission", actual, sizeof(actual)), 29);
        unsigned at = 0, user = 0, security = 0;
        while (at < 29) {
            CHECK(strlen((char*)actual + at) < 29 - at);
            user += !strcmp((char*)actual + at, "user.private");
            security += !strcmp((char*)actual + at, "security.custom");
            at += strlen((char*)actual + at) + 1;
        }
        CHECK(user == 1 && security == 1 && at == 29);
        _exit(0);
    }
    wait_child(child);
    CHECK(unlink("permission") == 0);
    CHECK(mkdir("sticky", 01777) == 0 && chmod("sticky", 01777) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        ERROR("sticky-directory-owner", setxattr("sticky", "user.denied", "v", 1, 0), EPERM);
        _exit(0);
    }
    wait_child(child);
    CHECK(rmdir("sticky") == 0);
    printf("FILECAP_XATTR_PASS observations=%u checks=%u all_twelve_syscalls ownership namespaces "
           "bounds lifetime\n",
           observations - before, checks);
    fflush(stdout);
}

struct capability_header {
    uint32_t version;
    int32_t pid;
};

struct capability_data {
    uint32_t effective, permitted, inheritable;
};

struct capabilities {
    uint64_t permitted, effective, inheritable;
};

static struct capabilities capability_get(void) {
    struct capability_header header = {0x20080522, 0};
    struct capability_data data[2] = {{0}};
    CHECK(syscall(SYS_capget, &header, data) == 0);
    return (struct capabilities){data[0].permitted | ((uint64_t)data[1].permitted << 32),
                                 data[0].effective | ((uint64_t)data[1].effective << 32),
                                 data[0].inheritable | ((uint64_t)data[1].inheritable << 32)};
}

static void capability_set(uint64_t permitted, uint64_t effective, uint64_t inheritable) {
    struct capability_header header = {0x20080522, 0};
    struct capability_data data[2] = {
        {(uint32_t)effective, (uint32_t)permitted, (uint32_t)inheritable},
        {(uint32_t)(effective >> 32), (uint32_t)(permitted >> 32), (uint32_t)(inheritable >> 32)}};
    CHECK(syscall(SYS_capset, &header, data) == 0);
}

static void marking(const char* name, uint64_t permitted, uint64_t inheritable, int effective,
                    uint32_t root_id) {
    uint32_t value[6] = {((root_id ? 3u : 2u) << 24) | (effective != 0),
                         (uint32_t)permitted,
                         (uint32_t)inheritable,
                         (uint32_t)(permitted >> 32),
                         (uint32_t)(inheritable >> 32),
                         root_id};
    RESULT("set-file-capability",
           setxattr(name, "security.capability", value, root_id ? 24 : 20, 0), 0);
}

static void filecap_formats(void) {
    make_file("formats", 0600);
    uint32_t value[9] = {0x02000001, 2, 0, 1u << 8, 0};
    RESULT("revision2-set", setxattr("formats", "security.capability", value, 20, 0), 0);
    expect_value("formats", "security.capability", value, 20);
    RESULT("empty-capability-set", setxattr("formats", "security.capability", NULL, 0, 0), 0);
    ERROR("empty-capability-get", getxattr("formats", "security.capability", value, sizeof(value)),
          EINVAL);
    RESULT("empty-capability-listed", listxattr("formats", NULL, 0), 20);
    RESULT("restore-revision2", setxattr("formats", "security.capability", value, 20, 0), 0);
    for (unsigned length = 1; length <= 32; length++) {
        if (length == 20)
            continue;
        ERROR("invalid-capability-length",
              setxattr("formats", "security.capability", value, length, 0), EINVAL);
    }
    expect_value("formats", "security.capability", value, 20);
    value[0] = 0x01000001;
    ERROR("revision1-write-denied", setxattr("formats", "security.capability", value, 12, 0),
          EINVAL);
    value[0] = 0x04000001;
    ERROR("unknown-revision", setxattr("formats", "security.capability", value, 20, 0), EINVAL);
    value[0] = 0x02000003;
    ERROR("unknown-capability-flags", setxattr("formats", "security.capability", value, 20, 0),
          EINVAL);
    value[0] = 0x03000001;
    value[5] = UINT32_MAX;
    ERROR("invalid-namespace-root", setxattr("formats", "security.capability", value, 24, 0),
          EINVAL);
    value[5] = 0;
    RESULT("revision3-root-zero", setxattr("formats", "security.capability", value, 24, 0), 0);
    value[0] = 0x02000001;
    expect_value("formats", "security.capability", value, 20);
    value[0] = 0x03000001;
    value[5] = 1000;
    RESULT("revision3-other-root", setxattr("formats", "security.capability", value, 24, 0), 0);
    expect_value("formats", "security.capability", value, 24);
    RESULT("capability-remove", removexattr("formats", "security.capability"), 0);
    CHECK(unlink("formats") == 0);
    puts("FILECAP_FORMAT_PASS wire_revisions root_identity rejected_values preserve_metadata");
    fflush(stdout);
}

static void filecap_content(void) {
    for (unsigned action = 0; action < 8; action++) {
        make_file("marked", 0666);
        int fd = open("marked", O_RDWR);
        CHECK(fd >= 0);
        marking("marked", 2, 0, 1, 0);
        uint32_t actual[6];
        RESULT("open-keeps-capability",
               fgetxattr(fd, "security.capability", actual, sizeof(actual)), 20);
        switch (action) {
        case 0:
            RESULT("zero-write", write(fd, "", 0), 0);
            break;
        case 1:
            RESULT("ordinary-write", write(fd, "B", 1), 1);
            break;
        case 2:
            RESULT("pwrite", pwrite(fd, "B", 1, 1), 1);
            break;
        case 3:
            RESULT("truncate-same-size", ftruncate(fd, 8), 0);
            break;
        case 4:
            RESULT("truncate-short", ftruncate(fd, 4), 0);
            break;
        case 5:
            RESULT("chown-same", fchown(fd, 0, 0), 0);
            break;
        case 6:
            RESULT("chown-ignore", fchown(fd, -1, -1), 0);
            break;
        case 7:
            RESULT("chmod-preserves", fchmod(fd, 0755), 0);
            break;
        }
        if (action == 0 || action == 7)
            RESULT("content-unchanged-marking",
                   fgetxattr(fd, "security.capability", actual, sizeof(actual)), 20);
        else
            ERROR("content-clears-marking",
                  fgetxattr(fd, "security.capability", actual, sizeof(actual)), ENODATA);
        CHECK(close(fd) == 0 && unlink("marked") == 0);
    }
    if (getenv("FILECAP_SHARED_MAPPING")) {
        make_file("mapped", 0666);
        int fd = open("mapped", O_RDWR);
        CHECK(fd >= 0 && ftruncate(fd, 4096) == 0);
        marking("mapped", 2, 0, 1, 0);
        char* shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(shared != MAP_FAILED);
        shared[1] = 'M';
        uint32_t actual[6];
        RESULT("shared-store-keeps-marking",
               fgetxattr(fd, "security.capability", actual, sizeof(actual)), 20);
        CHECK(close(fd) == 0 && munmap(shared, 4096) == 0 && unlink("mapped") == 0);
        puts("FILECAP_SHARED_MAPPING_PASS actual_shared_store marking_preserved");
    }
    puts("FILECAP_CONTENT_PASS open zero_write write pwrite truncate ownership chmod");
    fflush(stdout);
}

static void filecap_admin(void) {
    make_file("admin", 0000);
    marking("admin", 2, 0, 1, 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0);
        drop(1001);
        capability_set(1ull << 31, 1ull << 31, 0);
        struct capabilities admin = capability_get();
        CHECK(admin.permitted == (1ull << 31) && admin.effective == (1ull << 31));
        marking("admin", 2, 0, 1, 0);
        RESULT("setfcap-remove", removexattr("admin", "security.capability"), 0);
        marking("admin", 2, 0, 1, 0);
        ERROR("setfcap-not-security-admin", setxattr("admin", "security.custom", "v", 1, 0), EPERM);
        ERROR("setfcap-not-trusted-admin", setxattr("admin", "trusted.custom", "v", 1, 0), EPERM);
        capability_set(0, 0, 0);
        uint32_t value[5] = {0x02000001, 2, 0, 0, 0};
        ERROR("unprivileged-setfcap", setxattr("admin", "security.capability", value, 20, 0),
              EPERM);
        ERROR("unprivileged-removefcap", removexattr("admin", "security.capability"), EPERM);
        uint32_t root_value[6] = {0x03000001, 2, 0, 0, 0, UINT32_MAX};
        ERROR("unprivileged-invalid-root",
              setxattr("admin", "security.capability", root_value, 24, 0), EPERM);
        root_value[0] = 0x03000003;
        ERROR("unprivileged-invalid-flags",
              setxattr("admin", "security.capability", root_value, 24, 0), EINVAL);
        RESULT("unprivileged-readfcap",
               getxattr("admin", "security.capability", value, sizeof(value)), 20);
        _exit(0);
    }
    wait_child(child);
    uint32_t expected[5] = {0x02000001, 2, 0, 0, 0};
    expect_value("admin", "security.capability", expected, 20);
    CHECK(unlink("admin") == 0);
    puts("FILECAP_ADMIN_PASS dedicated_setfcap_capability actual_nonowner_set_remove "
         "denial_preserves_value");
    fflush(stdout);
}

static uint64_t ambient_get(void) {
    uint64_t result = 0;
    for (unsigned bit = 0; bit <= 40; bit++) {
        long value = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, bit, 0, 0);
        CHECK(value == 0 || value == 1);
        if (value)
            result |= 1ull << bit;
    }
    return result;
}

static uint64_t bounding_get(void) {
    uint64_t result = 0;
    for (unsigned bit = 0; bit <= 40; bit++) {
        long value = prctl(PR_CAPBSET_READ, bit, 0, 0, 0);
        CHECK(value == 0 || value == 1);
        if (value)
            result |= 1ull << bit;
    }
    return result;
}

static void failed_credentials(const char* name, const char* stage) {
    struct capabilities caps = capability_get();
    uid_t r, e, s;
    gid_t gr, ge, gs;
    CHECK(getresuid(&r, &e, &s) == 0 && getresgid(&gr, &ge, &gs) == 0);
    printf(
        "FILECAP_FAILED_CREDENTIAL_RECEIPT name=%s stage=%s pid=%d permitted=%llx effective=%llx "
        "inheritable=%llx ambient=%llx bounding=%llx ruid=%u euid=%u suid=%u fsuid=%u rgid=%u "
        "egid=%u sgid=%u fsgid=%u securebits=%d dumpable=%d no_new_privileges=%d\n",
        name, stage, getpid(), (unsigned long long)caps.permitted,
        (unsigned long long)caps.effective, (unsigned long long)caps.inheritable,
        (unsigned long long)ambient_get(), (unsigned long long)bounding_get(), r, e, s,
        (uid_t)setfsuid((uid_t)-1), gr, ge, gs, (gid_t)setfsgid((gid_t)-1),
        prctl(PR_GET_SECUREBITS, 0, 0, 0, 0), prctl(PR_GET_DUMPABLE, 0, 0, 0, 0),
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
    fflush(stdout);
}

static void copy_self(const char* program, const char* name) {
    int input = open(program, O_RDONLY), output = open(name, O_CREAT | O_EXCL | O_WRONLY, 0700);
    CHECK(input >= 0 && output >= 0);
    char buffer[16384];
    ssize_t length;
    while ((length = read(input, buffer, sizeof(buffer))) > 0)
        CHECK(write(output, buffer, length) == length);
    CHECK(length == 0 && close(input) == 0 && fchmod(output, 0755) == 0 && close(output) == 0);
}

static void exec_service(int argc, char** argv) {
    CHECK(argc == 13);
    struct capabilities caps = capability_get();
    uint64_t permitted = strtoull(argv[3], NULL, 16), effective = strtoull(argv[4], NULL, 16);
    uint64_t inheritable = strtoull(argv[5], NULL, 16), ambient = strtoull(argv[6], NULL, 16);
    uid_t real = strtoul(argv[7], NULL, 10), expected_uid = strtoul(argv[8], NULL, 10);
    gid_t expected_gid = strtoul(argv[9], NULL, 10);
    int secure = atoi(argv[10]), no_new = atoi(argv[12]);
    uid_t r, e, s;
    gid_t gr, ge, gs;
    CHECK(getresuid(&r, &e, &s) == 0 && getresgid(&gr, &ge, &gs) == 0);
    unsigned long actual_secure = getauxval(AT_SECURE);
    int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    int keepcaps = prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
    int actual_no_new = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    uint64_t actual_ambient = ambient_get(), bounding = bounding_get();
    printf("FILECAP_EXEC_RECEIPT name=%s pid=%d permitted=%llx effective=%llx inheritable=%llx "
           "ambient=%llx bounding=%llx ruid=%u euid=%u suid=%u rgid=%u egid=%u sgid=%u secure=%lu "
           "dumpable=%d keepcaps=%d no_new_privileges=%d expected_dumpable=%s\n",
           argv[2], getpid(), (unsigned long long)caps.permitted,
           (unsigned long long)caps.effective, (unsigned long long)caps.inheritable,
           (unsigned long long)actual_ambient, (unsigned long long)bounding, r, e, s, gr, ge, gs,
           actual_secure, dumpable, keepcaps, actual_no_new, argv[11]);
    fflush(stdout);
    CHECK(caps.permitted == permitted && caps.effective == effective &&
          caps.inheritable == inheritable);
    CHECK(actual_ambient == ambient && r == real && e == expected_uid && s == expected_uid);
    CHECK(gr == real && ge == expected_gid && gs == expected_gid);
    CHECK(getauxval(AT_UID) == real && getauxval(AT_EUID) == expected_uid);
    CHECK(getauxval(AT_GID) == real && getauxval(AT_EGID) == expected_gid);
    CHECK(actual_secure == (unsigned)secure && keepcaps == 0 && actual_no_new == no_new);
    CHECK(dumpable >= 0 && dumpable <= 2);
    CHECK(!strcmp(argv[11], "normal") || !strcmp(argv[11], "restricted"));
    CHECK((dumpable == 1) == !strcmp(argv[11], "normal"));
    int fd = open("protected", O_RDONLY);
    if (effective & 2) {
        char data[8];
        CHECK(fd >= 0 && read(fd, data, sizeof(data)) == 8 && !memcmp(data, "original", 8));
        CHECK(close(fd) == 0);
    } else {
        CHECK(fd == -1 && errno == EACCES);
        if (permitted & 2) {
            capability_set(permitted, permitted, inheritable);
            fd = open("protected", O_RDONLY);
            CHECK(fd >= 0 && close(fd) == 0);
        }
    }
    if (real == 1001) {
        CHECK(setresuid(1001, 1001, 1001) == 0);
        capability_set(0, 0, 0);
        ERROR("exec-irreversible-uid-drop", setresuid(0, 0, 0), EPERM);
        struct capability_header header = {0x20080522, 0};
        struct capability_data restore[2] = {{2, 2, 0}, {0}};
        ERROR("exec-irreversible-cap-drop", syscall(SYS_capset, &header, restore), EPERM);
    }
    printf("FILECAP_EXEC_SERVICE_PASS name=%s actual_dac auxiliary_ids capability_sets "
           "irreversible_drop\n",
           argv[2]);
    fflush(stdout);
}

enum exec_flags {
    exec_inheritable = 1,
    exec_ambient = 2,
    exec_bound_high = 4,
    exec_bound_low = 8,
    exec_noroot = 16,
    exec_root = 32,
    exec_no_new = 64,
    exec_denied = 128,
    exec_setuid = 256,
    exec_setgid = 512
};

struct exec_case {
    const char* name;
    uint64_t file_permitted, file_inheritable;
    unsigned flags;
    uint32_t root_id;
    int has_file, file_effective;
    uint64_t permitted, effective, ambient;
    int secure;
    const char* dumpable;
};

static void exec_setup(unsigned flags) {
    if (flags & exec_noroot)
        CHECK(prctl(PR_SET_SECUREBITS, 1, 0, 0, 0) == 0);
    if (flags & exec_inheritable) {
        struct capabilities caps = capability_get();
        capability_set(caps.permitted, caps.effective, 2);
    }
    if (flags & exec_bound_high)
        CHECK(prctl(PR_CAPBSET_DROP, 40, 0, 0, 0) == 0);
    if (flags & exec_bound_low)
        CHECK(prctl(PR_CAPBSET_DROP, 1, 0, 0, 0) == 0);
    if (!(flags & exec_root)) {
        if (flags & exec_inheritable)
            CHECK(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0);
        drop(1001);
        if (flags & exec_inheritable)
            capability_set(2, 0, 2);
    }
    if (flags & exec_ambient)
        CHECK(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 1, 0, 0) == 0);
    if (flags & exec_no_new)
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
}

static void exec_contract(const char* program) {
    const uint64_t file_bits = 2 | (1ull << 40);
    uint64_t root_bits = bounding_get();
    CHECK((root_bits & file_bits) == file_bits);
    struct exec_case cases[] = {
        {"plain", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "normal"},
        {"effective", file_bits, 0, 0, 0, 1, 1, file_bits, file_bits, 0, 1, "restricted"},
        {"permitted", file_bits, 0, 0, 0, 1, 0, file_bits, 0, 0, 1, "restricted"},
        {"inheritable", 0, 2, exec_inheritable, 0, 1, 1, 2, 2, 0, 1, "normal"},
        {"inheritable-bounded", 0, 2, exec_inheritable | exec_bound_low, 0, 1, 1, 2, 2, 0, 1,
         "normal"},
        {"ambient-plain", 0, 0, exec_inheritable | exec_ambient, 0, 0, 0, 2, 2, 2, 0, "normal"},
        {"ambient-empty", 0, 0, exec_inheritable | exec_ambient, 0, 1, 0, 0, 0, 0, 0, "normal"},
        {"empty-effective", 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, "normal"},
        {"foreign-root", file_bits, 0, exec_inheritable | exec_ambient, 1000, 1, 1, 2, 2, 2, 0,
         "normal"},
        {"no-new-privileges", file_bits, 0, exec_no_new, 0, 1, 1, 0, 0, 0, 1, "normal"},
        {"no-new-ambient", file_bits, 0, exec_no_new | exec_inheritable | exec_ambient, 0, 1, 1, 2,
         2, 0, 1, "normal"},
        {"bounded-permitted", file_bits, 0, exec_bound_high, 0, 1, 0, 2, 0, 0, 1, "restricted"},
        {"bounded-denied", file_bits, 0, exec_bound_high | exec_denied, 0, 1, 1, 0, 0, 0, 0,
         "normal"},
        {"noroot-root", 2, 0, exec_noroot | exec_root, 0, 1, 1, 2, 2, 0, 0, "normal"},
        {"setuid-file", 2, 0, exec_setuid, 0, 1, 1, 2, 2, 0, 1, "restricted"},
        {"setgid-file", 2, 0, exec_setgid, 0, 1, 1, 2, 2, 0, 1, "restricted"},
        {"setids-file", 2, 0, exec_setuid | exec_setgid, 0, 1, 1, 2, 2, 0, 1, "restricted"},
        {"no-new-setuid", file_bits, 0, exec_setuid | exec_no_new, 0, 1, 1, 0, 0, 0, 1, "normal"},
        {"no-new-setgid", file_bits, 0, exec_setgid | exec_no_new, 0, 1, 1, 0, 0, 0, 1, "normal"},
        {"no-new-setids", file_bits, 0, exec_setuid | exec_setgid | exec_no_new, 0, 1, 1, 0, 0, 0,
         1, "normal"},
        {"root-compatibility", 2, 0, exec_root, 0, 1, 0, root_bits, root_bits, 0, 0, "normal"},
        {"unknown-capability-bit", 1ull << 41, 0, 0, 0, 1, 1, 0, 0, 0, 1, "normal"}};
    make_file("protected", 0000);
    copy_self(program, "exec-service");
    for (unsigned at = 0; at < sizeof(cases) / sizeof(cases[0]); at++) {
        const struct exec_case* test = &cases[at];
        int removed = removexattr("exec-service", "security.capability");
        CHECK(removed == 0 || errno == ENODATA);
        CHECK(chmod("exec-service", 0755 | ((test->flags & exec_setuid) ? 04000 : 0) |
                                        ((test->flags & exec_setgid) ? 02000 : 0)) == 0);
        if (test->has_file)
            marking("exec-service", test->file_permitted, test->file_inheritable,
                    test->file_effective, test->root_id);
        char permitted[32], effective[32], inheritable[32], ambient[32];
        snprintf(permitted, sizeof(permitted), "%llx", (unsigned long long)test->permitted);
        snprintf(effective, sizeof(effective), "%llx", (unsigned long long)test->effective);
        snprintf(inheritable, sizeof(inheritable), "%x", (test->flags & exec_inheritable) ? 2 : 0);
        snprintf(ambient, sizeof(ambient), "%llx", (unsigned long long)test->ambient);
        char secure[8];
        snprintf(secure, sizeof(secure), "%d", test->secure);
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            exec_setup(test->flags);
            if (test->flags & exec_denied) {
                struct capabilities before = capability_get();
                failed_credentials(test->name, "before");
                ERROR("bounded-effective-exec", execl("./exec-service", "./exec-service", NULL),
                      EPERM);
                failed_credentials(test->name, "after");
                struct capabilities after = capability_get();
                CHECK(!memcmp(&before, &after, sizeof(before)) && getuid() == 1001 &&
                      geteuid() == 1001);
                printf("FILECAP_FAILED_EXEC_PASS name=%s errno=%d credentials_unchanged\n",
                       test->name, EPERM);
                fflush(stdout);
                _exit(0);
            }
            const char* real = (test->flags & exec_root) ? "0" : "1001";
            const char* uid = (test->flags & exec_root) ||
                                      ((test->flags & exec_setuid) && !(test->flags & exec_no_new))
                                  ? "0"
                                  : "1001";
            const char* gid = (test->flags & exec_root) ||
                                      ((test->flags & exec_setgid) && !(test->flags & exec_no_new))
                                  ? "0"
                                  : "1001";
            execl("./exec-service", "./exec-service", "--exec-service", test->name, permitted,
                  effective, inheritable, ambient, real, uid, gid, secure, test->dumpable,
                  (test->flags & exec_no_new) ? "1" : "0", NULL);
            CHECK(0);
        }
        wait_child(child);
    }
    make_file("invalid-executable", 0755);
    marking("invalid-executable", file_bits, 0, 1, 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        exec_setup(exec_inheritable | exec_ambient);
        struct capabilities before = capability_get();
        uint64_t ambient = ambient_get(), bounding = bounding_get();
        long bits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
        char* args[] = {"./invalid-executable", NULL};
        failed_credentials("invalid-elf", "before");
        ERROR("failed-elf-exec", execve(args[0], args, environ), ENOEXEC);
        failed_credentials("invalid-elf", "after");
        struct capabilities after = capability_get();
        CHECK(!memcmp(&before, &after, sizeof(before)) && ambient_get() == ambient);
        CHECK(bounding_get() == bounding && prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) == bits);
        CHECK(getuid() == 1001 && geteuid() == 1001);
        puts("FILECAP_FAILED_EXEC_PASS name=invalid-elf errno=8 credentials_unchanged "
             "ambient_preserved");
        fflush(stdout);
        _exit(0);
    }
    wait_child(child);
    CHECK(unlink("invalid-executable") == 0 && unlink("exec-service") == 0 &&
          unlink("protected") == 0);
    printf("FILECAP_EXEC_PASS cases=%zu actual_privilege_changes failed_exec_transaction\n",
           sizeof(cases) / sizeof(cases[0]));
    fflush(stdout);
}

static void tool_run(const char* name, const char* const* arguments, int expected_status,
                     char* output, size_t capacity) {
    const char* directory = getenv("FILECAP_TOOLS");
    CHECK(directory != NULL);
    char path[1024];
    CHECK(snprintf(path, sizeof(path), "%s/%s", directory, name) < (int)sizeof(path));
    char* argv[8] = {path};
    unsigned count = 0;
    while (arguments[count]) {
        CHECK(count < 6);
        argv[count + 1] = (char*)arguments[count];
        count++;
    }
    int pipes[2];
    CHECK(pipe2(pipes, O_CLOEXEC) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(pipes[0]) == 0 && dup2(pipes[1], 1) == 1 && dup2(pipes[1], 2) == 2);
        CHECK(close(pipes[1]) == 0);
        execv(path, argv);
        CHECK(0);
    }
    CHECK(close(pipes[1]) == 0);
    size_t used = 0;
    ssize_t length;
    while ((length = read(pipes[0], output + used, capacity - used - 1)) > 0) {
        used += length;
        CHECK(used < capacity - 1);
    }
    CHECK(length == 0 && close(pipes[0]) == 0);
    output[used] = 0;
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status));
    printf("FILECAP_TOOL_RECEIPT name=%s status=%d expected=%d bytes=%zu hex=", name,
           WEXITSTATUS(status), expected_status, used);
    for (size_t i = 0; i < used; i++)
        printf("%02x", (unsigned char)output[i]);
    puts("");
    fflush(stdout);
    CHECK(WEXITSTATUS(status) == expected_status);
}

static void tools_contract(const char* program) {
    copy_self(program, "tool-service");
    make_file("protected", 0000);
    for (unsigned dynamic = 0; dynamic < 2; dynamic++) {
        const char* setcap = dynamic ? "setcap-dynamic" : "setcap-static";
        const char* getcap = dynamic ? "getcap-dynamic" : "getcap-static";
        const char* capability = "cap_dac_override,cap_checkpoint_restore=ep";
        const char* set[] = {capability, "./tool-service", NULL};
        const char* get[] = {"./tool-service", NULL};
        const char* remove[] = {"-r", "./tool-service", NULL};
        char output[2048];
        tool_run(setcap, set, 0, output, sizeof(output));
        CHECK(!output[0]);
        tool_run(getcap, get, 0, output, sizeof(output));
        CHECK(!strcmp(output, "./tool-service cap_dac_override,cap_checkpoint_restore=ep\n"));
        uint32_t expected[5] = {0x02000001, 2, 0, 1u << 8, 0};
        expect_value("tool-service", "security.capability", expected, 20);
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            drop(1001);
            execl("./tool-service", "./tool-service", "--exec-service",
                  dynamic ? "tool-dynamic" : "tool-static", "10000000002", "10000000002", "0", "0",
                  "1001", "1001", "1001", "1", "restricted", "0", NULL);
            CHECK(0);
        }
        wait_child(child);
        child = fork();
        CHECK(child >= 0);
        if (!child) {
            drop(1001);
            tool_run(setcap, set, 1, output, sizeof(output));
            CHECK(strstr(output, "Operation not permitted") != NULL);
            tool_run(setcap, remove, 1, output, sizeof(output));
            CHECK(strstr(output, "Operation not permitted") != NULL);
            _exit(0);
        }
        wait_child(child);
        expect_value("tool-service", "security.capability", expected, 20);
        const char* foreign[] = {"-n", "1000", capability, "./tool-service", NULL};
        tool_run(setcap, foreign, 0, output, sizeof(output));
        uint32_t namespaced[6] = {0x03000001, 2, 0, 1u << 8, 0, 1000};
        expect_value("tool-service", "security.capability", namespaced, 24);
        const char* get_foreign[] = {"-n", "./tool-service", NULL};
        tool_run(getcap, get_foreign, 0, output, sizeof(output));
        CHECK(!strcmp(output,
                      "./tool-service cap_dac_override,cap_checkpoint_restore=ep [rootid=1000]\n"));
        tool_run(setcap, remove, 0, output, sizeof(output));
        tool_run(getcap, get, 0, output, sizeof(output));
        CHECK(!output[0]);
    }
    CHECK(unlink("tool-service") == 0 && unlink("protected") == 0);
    puts("FILECAP_TOOLS_PASS upstream_getcap_setcap static dynamic allowed denied root_identity "
         "actual_exec");
    fflush(stdout);
}

static void mount_contract(const char* program) {
    const char* target = getenv("FILECAP_MOUNT_TARGET");
    CHECK(target != NULL);
    copy_self(program, "policy-service");
    make_file("protected", 0000);
    marking("policy-service", 2 | (1ull << 40), 0, 1, 0);
    sync();
    RESULT("remount-nosuid", mount(NULL, target, NULL, MS_REMOUNT | MS_NOSUID, NULL), 0);
    for (unsigned empty = 0; empty < 2; empty++) {
        if (empty)
            RESULT("nosuid-empty-marking",
                   setxattr("policy-service", "security.capability", NULL, 0, 0), 0);
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            drop(1001);
            ERROR("unprivileged-remount", mount(NULL, target, NULL, MS_REMOUNT, NULL), EPERM);
            execl("./policy-service", "./policy-service", "--exec-service",
                  empty ? "nosuid-empty" : "nosuid", "0", "0", "0", "0", "1001", "1001", "1001",
                  "0", "normal", "0", NULL);
            CHECK(0);
        }
        wait_child(child);
    }
    marking("policy-service", 2, 0, 1, 0);
    RESULT("remount-readonly", mount(NULL, target, NULL, MS_REMOUNT | MS_RDONLY, NULL), 0);
    int fd = open("policy-service", O_RDONLY);
    CHECK(fd >= 0);
    uint32_t value[5] = {0x02000001, 2, 0, 0, 0};
    expect_value("policy-service", "security.capability", value, sizeof(value));
    ERROR("readonly-path-set", setxattr("policy-service", "user.denied", "v", 1, 0), EROFS);
    ERROR("readonly-nofollow-set", lsetxattr("policy-service", "user.denied", "v", 1, 0), EROFS);
    ERROR("readonly-fd-set", fsetxattr(fd, "user.denied", "v", 1, 0), EROFS);
    ERROR("readonly-capability-set", fsetxattr(fd, "security.capability", value, 20, 0), EROFS);
    ERROR("readonly-invalid-capability",
          setxattr("policy-service", "security.capability", value, 12, 0), EROFS);
    ERROR("readonly-unknown-namespace", setxattr("policy-service", "unknown.value", "v", 1, 0),
          EROFS);
    ERROR("readonly-path-remove", removexattr("policy-service", "security.capability"), EROFS);
    ERROR("readonly-nofollow-remove", lremovexattr("policy-service", "security.capability"), EROFS);
    ERROR("readonly-fd-remove", fremovexattr(fd, "security.capability"), EROFS);
    CHECK(close(fd) == 0);
    RESULT("remount-writable", mount(NULL, target, NULL, MS_REMOUNT, NULL), 0);
    CHECK(unlink("policy-service") == 0 && unlink("protected") == 0);
    puts("FILECAP_MOUNT_PASS nosuid suppresses_valid_and_invalid_file_caps "
         "readonly_path_nofollow_fd precedence");
    fflush(stdout);
}

static void metadata_bounds(void) {
    const char* block = getenv("FILECAP_EXT2_BLOCK_SIZE");
    if (!block)
        return;
    size_t size = strtoul(block, NULL, 10);
    CHECK(size == 1024 || size == 2048 || size == 4096);
    make_file("bounds", 0600);
    RESULT("bounded-original", setxattr("bounds", "user.original", "preserved", 9, 0), 0);
    char* value = malloc(size + 1);
    CHECK(value != NULL);
    memset(value, 'B', size + 1);
    ERROR("ext2-value-too-large", setxattr("bounds", "user.original", value, size + 1, 0), ERANGE);
    ERROR("ext2-block-full", setxattr("bounds", "user.original", value, size, 0), ENOSPC);
    expect_value("bounds", "user.original", "preserved", 9);
    for (unsigned round = 0; round < 512; round++) {
        uint32_t number = round;
        CHECK(setxattr("bounds", "user.cycle", &number, sizeof(number), 0) == 0);
        uint32_t actual = UINT32_MAX;
        CHECK(getxattr("bounds", "user.cycle", &actual, sizeof(actual)) == sizeof(actual));
        CHECK(actual == number && removexattr("bounds", "user.cycle") == 0);
    }
    expect_value("bounds", "user.original", "preserved", 9);
    free(value);
    CHECK(unlink("bounds") == 0);
    puts("FILECAP_EXT2_BOUNDS_PASS size_limits failed_replacement_preserves_data cycles=512");
    fflush(stdout);
}

static void persist_verify(const char* directory) {
    CHECK(chdir(directory) == 0);
    struct stat file, alias;
    CHECK(stat("renamed", &file) == 0 && stat("alias", &alias) == 0);
    CHECK(file.st_ino == alias.st_ino && file.st_dev == alias.st_dev && file.st_nlink == 2);
    CHECK(file.st_uid == 65537 && file.st_gid == 131073 && (file.st_mode & 07777) == 0755);
    const unsigned char bytes[] = {0, 255, 17, 0, 127};
    expect_value("renamed", "user.binary", bytes, sizeof(bytes));
    expect_value("alias", "user.empty", "", 0);
    expect_value("renamed", "trusted.private", "secret", 6);
    expect_value("alias", "security.custom", "metadata", 8);
    uint32_t caps[5] = {0x02000001, 2, 0, 1u << 8, 0};
    expect_value("renamed", "security.capability", caps, sizeof(caps));
    int fd = open("renamed", O_RDONLY);
    CHECK(fd >= 0);
    uint32_t actual[5];
    RESULT("persisted-fd-capability", fgetxattr(fd, "security.capability", actual, sizeof(actual)),
           20);
    CHECK(!memcmp(caps, actual, sizeof(caps)) && close(fd) == 0);
    if (getenv("FILECAP_TOOLS")) {
        const char* get[] = {"./renamed", NULL};
        char output[2048];
        tool_run("getcap-dynamic", get, 0, output, sizeof(output));
        CHECK(!strcmp(output, "./renamed cap_dac_override,cap_checkpoint_restore=ep\n"));
    }
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        execl("./renamed", "./renamed", "--exec-service", "persisted", "10000000002", "10000000002",
              "0", "0", "1001", "1001", "1001", "1", "restricted", "0", NULL);
        CHECK(0);
    }
    wait_child(child);
    puts("FILECAP_PERSIST_VERIFY_PASS full_width_owner binary_empty_values hardlink_rename "
         "actual_capability_exec");
    fflush(stdout);
}

static void persist_create(const char* program, const char* directory) {
    CHECK(mkdir(directory, 0755) == 0 && chdir(directory) == 0);
    copy_self(program, "helper");
    make_file("protected", 0000);
    CHECK(chown("helper", 65537, 131073) == 0 && chmod("helper", 0755) == 0);
    const unsigned char bytes[] = {0, 255, 17, 0, 127};
    RESULT("persist-binary", setxattr("helper", "user.binary", bytes, sizeof(bytes), XATTR_CREATE),
           0);
    RESULT("persist-empty", setxattr("helper", "user.empty", NULL, 0, XATTR_CREATE), 0);
    RESULT("persist-trusted", setxattr("helper", "trusted.private", "secret", 6, XATTR_CREATE), 0);
    RESULT("persist-security", setxattr("helper", "security.custom", "metadata", 8, XATTR_CREATE),
           0);
    marking("helper", 2 | (1ull << 40), 0, 1, 0);
    CHECK(link("helper", "alias") == 0 && rename("helper", "renamed") == 0);
    puts("FILECAP_PERSIST_CREATE_PASS attribute_inode_owner hardlink rename");
    persist_verify(directory);
}

static void shared_contract(void) {
    CHECK(chdir("/tmp") == 0);
    expect_value("alpha", "user.shared", "original", 8);
    expect_value("beta", "user.shared", "original", 8);
    expect_value("alpha", "user.\xc3\xa9", "utf8", 4);
    int fd = open("beta", O_RDONLY);
    CHECK(fd >= 0);
    RESULT("shared-cow-replace", fsetxattr(fd, "user.shared", "changed", 7, XATTR_REPLACE), 0);
    expect_value("beta", "user.shared", "changed", 7);
    expect_value("alpha", "user.shared", "original", 8);
    expect_value("beta", "user.\xc3\xa9", "utf8", 4);
    uint32_t caps[5] = {0x02000001, 2, 0, 0, 0};
    expect_value("alpha", "security.capability", caps, 20);
    expect_value("beta", "security.capability", caps, 20);
    CHECK(chown("beta", 0, 0) == 0);
    ERROR("cow-owner-strips-mark", fgetxattr(fd, "security.capability", caps, 20), ENODATA);
    expect_value("alpha", "security.capability", caps, 20);
    CHECK(close(fd) == 0);
    CHECK(link("alpha", "alias") == 0 && rename("alpha", "renamed") == 0);
    fd = open("renamed", O_RDONLY);
    CHECK(fd >= 0);
    int alias = dup(fd);
    CHECK(alias >= 0 && unlink("renamed") == 0 && unlink("alias") == 0);
    RESULT("shared-unlinked-read", fgetxattr(fd, "user.shared", caps, sizeof(caps)), 8);
    CHECK(!memcmp(caps, "original", 8));
    RESULT("shared-unlinked-replace", fsetxattr(alias, "user.shared", "retained", 8, 0), 0);
    CHECK(close(fd) == 0);
    RESULT("shared-last-description", fgetxattr(alias, "user.shared", caps, sizeof(caps)), 8);
    CHECK(!memcmp(caps, "retained", 8) && close(alias) == 0);
    expect_value("beta", "user.shared", "changed", 7);
    sync();
    puts("FILECAP_SHARED_PASS shared_block_cow nonascii opaque_preserved hardlink_rename "
         "unlinked_description last_close");
}

static void disk_wire(int argc, char** argv) {
    CHECK(argc == 10 && chdir("/tmp") == 0);
    const char* path = argv[2];
    int length = atoi(argv[3]), get_error = atoi(argv[4]), exec_error = atoi(argv[5]);
    unsigned char buffer[24];
    if (get_error)
        ERROR("disk-wire-public-get", getxattr(path, "security.capability", buffer, sizeof(buffer)),
              get_error);
    else
        RESULT("disk-wire-public-get",
               getxattr(path, "security.capability", buffer, sizeof(buffer)), length);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        if (exec_error) {
            struct capabilities before = capability_get();
            uint64_t ambient = ambient_get(), bounding = bounding_get();
            int securebits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
            failed_credentials(path, "before");
            ERROR("disk-wire-invalid-exec", execl(path, path, NULL), exec_error);
            failed_credentials(path, "after");
            struct capabilities after = capability_get();
            CHECK(!memcmp(&before, &after, sizeof(before)) && ambient_get() == ambient &&
                  bounding_get() == bounding &&
                  prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) == securebits && getuid() == 1001 &&
                  geteuid() == 1001);
            printf("FILECAP_FAILED_EXEC_PASS name=%s errno=%d credentials_unchanged\n", path,
                   exec_error);
            fflush(stdout);
            _exit(0);
        }
        execl(path, path, "--exec-service", path, argv[6], argv[7], "0", "0", "1001", "1001",
              "1001", argv[8], argv[9], "0", NULL);
        CHECK(0);
    }
    wait_child(child);
    printf("FILECAP_DISK_WIRE_PASS name=%s public_errno=%d exec_errno=%d\n", path, get_error,
           exec_error);
    fflush(stdout);
}

static void fault_contract(void) {
    CHECK(chdir("/tmp") == 0);
    expect_value("fault", "user.value", "original", 8);
    expect_value("fault", "user.unrelated", "preserved", 9);
    uint32_t caps[5] = {0x02000001, 2, 0, 0, 0};
    expect_value("fault", "security.capability", caps, 20);
    int fd = open("fault", O_RDONLY);
    CHECK(fd >= 0);
    ERROR("injected-xattr-io", fsetxattr(fd, "user.value", "recovered", 9, 0), EIO);
    expect_value("fault", "user.value", "recovered", 9);
    expect_value("fault", "user.unrelated", "preserved", 9);
    expect_value("fault", "security.capability", caps, 20);
    RESULT("explicit-overlay-fsync", fsync(fd), 0);
    CHECK(close(fd) == 0);
    puts("FILECAP_IO_RECOVERY_PASS original_error_retained complete_overlay explicit_fsync "
         "unrelated_data");
}

static void full_contract(void) {
    CHECK(chdir("/tmp") == 0);
    make_file("new-attribute", 0600);
    int fd = open("fill", O_CREAT | O_WRONLY, 0600);
    CHECK(fd >= 0);
    char data[32768];
    memset(data, 'F', sizeof(data));
    unsigned long filled = 0;
    for (;;) {
        ssize_t written = write(fd, data, sizeof(data));
        if (written < 0) {
            CHECK(errno == ENOSPC);
            break;
        }
        CHECK(written > 0);
        filled += written;
        CHECK(filled <= 16 * 1024 * 1024);
    }
    CHECK(close(fd) == 0 && filled > 0);
    fd = open("fill", O_WRONLY | O_APPEND);
    CHECK(fd >= 0);
    while (write(fd, data, 1024) > 0)
        filled += 1024;
    CHECK(errno == ENOSPC && close(fd) == 0);
    struct statfs space;
    CHECK(statfs(".", &space) == 0);
    if (space.f_bfree) {
        // An indirect-pointer allocation can need two blocks while an EA
        // needs one. Consume any remainder using existing direct pointers.
        fd = open("new-attribute", O_WRONLY);
        CHECK(fd >= 0);
        for (unsigned block = 1; space.f_bfree && block < 12; block++) {
            CHECK(pwrite(fd, data, 1024, block * 1024) == 1024);
            CHECK(statfs(".", &space) == 0);
        }
        CHECK(close(fd) == 0);
    }
    CHECK(space.f_bfree == 0);
    uint32_t caps[5] = {0x02000001, 2, 0, 0, 0};
    ERROR("full-volume-file-capability",
          setxattr("new-attribute", "security.capability", caps, 20, 0), ENOSPC);
    ERROR("full-volume-no-file-capability",
          getxattr("new-attribute", "security.capability", data, sizeof(data)), ENODATA);
    ERROR("full-volume-attribute", setxattr("new-attribute", "user.value", "v", 1, 0), ENOSPC);
    ERROR("full-volume-unset", getxattr("new-attribute", "user.value", data, sizeof(data)),
          ENODATA);
    expect_value("fault", "user.value", "original", 8);
    expect_value("fault", "user.unrelated", "preserved", 9);
    expect_value("fault", "security.capability", caps, 20);
    CHECK(unlink("fill") == 0);
    sync();
    RESULT("released-space-attribute", setxattr("new-attribute", "user.value", "v", 1, 0), 0);
    expect_value("new-attribute", "user.value", "v", 1);
    CHECK(unlink("new-attribute") == 0);
    printf("FILECAP_FULL_PASS filled=%lu old_attributes_preserved allocation_reclaimed\n", filled);
    fflush(stdout);
}

static void installed_contract(const char* program) {
    CHECK(setenv("FILECAP_TOOLS", "/usr/sbin", 1) == 0);
    CHECK(mkdir("/tmp/filecap-installed", 0755) == 0 && chdir("/tmp/filecap-installed") == 0);
    copy_self(program, "service");
    make_file("protected", 0000);
    const char* set[] = {"cap_dac_override,cap_checkpoint_restore=ep", "./service", NULL};
    const char* get[] = {"./service", NULL};
    const char* remove[] = {"-r", "./service", NULL};
    char output[2048];
    tool_run("setcap", set, 0, output, sizeof(output));
    tool_run("getcap", get, 0, output, sizeof(output));
    CHECK(!strcmp(output, "./service cap_dac_override,cap_checkpoint_restore=ep\n"));
    uint32_t caps[5] = {0x02000001, 2, 0, 1u << 8, 0};
    expect_value("service", "security.capability", caps, 20);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        tool_run("setcap", remove, 1, output, sizeof(output));
        CHECK(strstr(output, "Operation not permitted") != NULL);
        execl("./service", "./service", "--exec-service", "installed-runtime", "10000000002",
              "10000000002", "0", "0", "1001", "1001", "1001", "1", "restricted", "0", NULL);
        CHECK(0);
    }
    wait_child(child);
    expect_value("service", "security.capability", caps, 20);
    tool_run("setcap", remove, 0, output, sizeof(output));
    tool_run("getcap", get, 0, output, sizeof(output));
    CHECK(!output[0]);
    CHECK(unlink("service") == 0 && unlink("protected") == 0 && chdir("/") == 0 &&
          rmdir("/tmp/filecap-installed") == 0);
    puts("FILECAP_INSTALLED_TOOLS_PASS ordinary_image actual_runtime_tools marking denied_removal "
         "privileged_exec");
    fflush(stdout);
}

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "--exec-service")) {
        exec_service(argc, argv);
        return 0;
    }
    CHECK(getuid() == 0 && geteuid() == 0);
    if (argc == 2 && !strcmp(argv[1], "--installed-tools")) {
        installed_contract(argv[0]);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "--reject-mount")) {
        ERROR("damaged-mount", mount(argv[2], "/tmp", "ext2", 0, NULL), atoi(argv[3]));
        printf("FILECAP_REJECT_PASS device=%s errno=%d\n", argv[2], atoi(argv[3]));
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--shared-contract")) {
        shared_contract();
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--disk-wire")) {
        disk_wire(argc, argv);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--fault-contract")) {
        fault_contract();
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--full-contract")) {
        full_contract();
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--verify-persist")) {
        persist_verify(argv[2]);
        printf("FILECAP_PERSIST_REBOOT_PASS linkage=%s\n", FILECAP_LINKAGE);
        return 0;
    }
    const char* directory = argc > 1 ? argv[1] : "/tmp/file-capabilities";
    CHECK(mkdir(directory, 0777) == 0 && chmod(directory, 0777) == 0 && chdir(directory) == 0);
    xattr_contract();
    filecap_formats();
    filecap_content();
    filecap_admin();
    exec_contract(argv[0]);
    tools_contract(argv[0]);
    mount_contract(argv[0]);
    metadata_bounds();
    CHECK(chdir("/") == 0 && rmdir(directory) == 0);
    if (getenv("FILECAP_PERSIST_DIR"))
        persist_create(argv[0], getenv("FILECAP_PERSIST_DIR"));
    printf("FILECAP_TEST_PASS linkage=%s parent_observations=%u parent_checks=%u\n",
           FILECAP_LINKAGE, observations, checks);
    return 0;
}
