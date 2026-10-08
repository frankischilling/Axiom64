// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef ABI_LINKAGE
#define ABI_LINKAGE "static"
#endif
#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "ABI_FAIL line=%d: %s errno=%d (%s)\n", __LINE__, #expr, errno,        \
                    strerror(errno));                                                              \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void child_status(pid_t child, int expected) {
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == expected);
}

static void relative_modes(void) {
    CHECK(mkdir("/tmp/abi-chmod", 0700) == 0);
    int parent = open("/tmp/abi-chmod", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(parent >= 0);
    int file = openat(parent, "file", O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(file >= 0);
    CHECK(fchmodat(parent, "file", 0640, 0) == 0);
    struct stat information;
    CHECK(fstat(file, &information) == 0 && S_ISREG(information.st_mode) &&
          (information.st_mode & 07777) == 0640);
    CHECK(symlinkat("file", parent, "alias") == 0);
    CHECK(fchmodat(parent, "alias", 0610, 0) == 0);
    CHECK(fstat(file, &information) == 0 && (information.st_mode & 07777) == 0610);
    CHECK(fstatat(parent, "alias", &information, AT_SYMLINK_NOFOLLOW) == 0 &&
          S_ISLNK(information.st_mode));
    CHECK(fchmodat(999, "/tmp/abi-chmod/file", 0660, 0) == 0);
    CHECK(fstat(file, &information) == 0 && (information.st_mode & 07777) == 0660);
    CHECK(fchmodat(999, "file", 0600, 0) == -1 && errno == EBADF);
    CHECK(fchmodat(file, "file", 0600, 0) == -1 && errno == ENOTDIR);
    CHECK(fchmodat(parent, "file/child", 0600, 0) == -1 && errno == ENOTDIR);
    CHECK(fchmodat(parent, "missing", 0600, 0) == -1 && errno == ENOENT);
    CHECK(symlinkat("loop", parent, "loop") == 0);
    CHECK(fchmodat(parent, "loop", 0600, 0) == -1 && errno == ELOOP);
    CHECK(unlinkat(parent, "loop", 0) == 0);
    CHECK(syscall(SYS_fchmodat, parent, (void*)(uintptr_t)0xffff800000000000, 0600) == -1 &&
          errno == EFAULT);
    CHECK(fchmodat(AT_FDCWD, "/tmp/abi-chmod", 0750, 0) == 0);
    CHECK(fstat(parent, &information) == 0 && S_ISDIR(information.st_mode) &&
          (information.st_mode & 07777) == 0750);
    CHECK(unlinkat(parent, "alias", 0) == 0 && unlinkat(parent, "file", 0) == 0);
    CHECK(close(file) == 0 && close(parent) == 0 && rmdir("/tmp/abi-chmod") == 0);
    puts("ABI_RELATIVE_MODES_PASS linkage=" ABI_LINKAGE);
}

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "child"))
        return 17;
    struct utsname name;
    CHECK(uname(&name) == 0);
    CHECK(!strcmp(name.sysname, "Axiom64"));
    CHECK(getpid() > 0);
    CHECK(getuid() == 0);
    CHECK(syscall(SYS_gettid) == getpid());
    errno = 0;
    CHECK(syscall(999) == -1 && errno == ENOSYS);
    CHECK(syscall(SYS_write, 1, (void*)(uintptr_t)0xffff800000000000, 4) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_read, 999, (void*)0, 1) == -1 && errno == EBADF);
    CHECK(syscall(SYS_write, 1, (void*)(uintptr_t)0x7ffffffffffe, 8) == -1 && errno == EFAULT);
    relative_modes();

    char* memory = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(memory != MAP_FAILED);
    strcpy(memory, "private memory");
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(!strcmp(memory, "private memory"));
        memory[0] = 'x';
        _exit(42);
    }
    child_status(child, 42);
    CHECK(memory[0] == 'p');
    CHECK(mprotect(memory, 8192, PROT_READ) == 0);
    CHECK(syscall(SYS_read, 0, memory, 1) == -1 && errno == EFAULT);
    CHECK(munmap(memory, 8192) == 0);
    CHECK(syscall(SYS_write, 1, memory, 1) == -1 && errno == EFAULT);

    int fd = open("/tmp/abi-file", O_CREAT | O_TRUNC | O_RDWR, 0644);
    CHECK(fd >= 0);
    CHECK(write(fd, "abcdefgh", 8) == 8);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    char buffer[32] = {0};
    CHECK(read(fd, buffer, 8) == 8);
    CHECK(!memcmp(buffer, "abcdefgh", 8));
    CHECK(pwrite(fd, "XY", 2, 3) == 2);
    CHECK(pread(fd, buffer, 8, 0) == 8);
    CHECK(!memcmp(buffer, "abcXYfgh", 8));
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_size == 8 && S_ISREG(st.st_mode));
    struct timespec file_times[2] = {{123, 456}, {124, 789}};
    CHECK(futimens(fd, file_times) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_atim.tv_sec == 123 && st.st_atim.tv_nsec == 456 &&
          st.st_mtim.tv_sec == 124 && st.st_mtim.tv_nsec == 789);
    file_times[0].tv_nsec = UTIME_OMIT;
    file_times[1] = (struct timespec){125, 999};
    CHECK(utimensat(AT_FDCWD, "/tmp/abi-file", file_times, 0) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_atim.tv_sec == 123 && st.st_mtim.tv_sec == 125 &&
          st.st_mtim.tv_nsec == 999);
    CHECK(ftruncate(fd, 3) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_size == 3);
    CHECK(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
    CHECK(fcntl(fd, F_GETFD) == FD_CLOEXEC);
    int second = dup(fd);
    CHECK(second >= 0);
    CHECK(fcntl(second, F_GETFD) == 0);
    CHECK(close(second) == 0);
    CHECK(close(fd) == 0);
    CHECK(stat("/tmp/abi-file", &st) == 0);
    CHECK(unlink("/tmp/abi-file") == 0);

    fd = open("/tmp/link-original", O_CREAT | O_TRUNC | O_RDWR, 0600);
    CHECK(fd >= 0);
    CHECK(write(fd, "linked", 6) == 6);
    CHECK(link("/tmp/link-original", "/tmp/link-alias") == 0);
    struct stat alias;
    CHECK(stat("/tmp/link-original", &st) == 0 && st.st_nlink == 2);
    CHECK(stat("/tmp/link-alias", &alias) == 0 && alias.st_ino == st.st_ino);
    CHECK(unlink("/tmp/link-original") == 0);
    CHECK(stat("/tmp/link-alias", &st) == 0 && st.st_nlink == 1);
    second = open("/tmp/link-alias", O_RDWR);
    CHECK(second >= 0);
    CHECK(pwrite(second, "L", 1, 0) == 1);
    CHECK(pread(fd, buffer, 6, 0) == 6 && !memcmp(buffer, "Linked", 6));
    CHECK(unlink("/tmp/link-alias") == 0);
    CHECK(pread(fd, buffer, 6, 0) == 6);
    close(second);
    close(fd);

    int pipefd[2];
    CHECK(pipe(pipefd) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(pipefd[0]);
        CHECK(write(pipefd[1], "pipe-data", 9) == 9);
        close(pipefd[1]);
        _exit(0);
    }
    close(pipefd[1]);
    memset(buffer, 0, sizeof(buffer));
    CHECK(read(pipefd[0], buffer, 9) == 9);
    CHECK(!strcmp(buffer, "pipe-data"));
    CHECK(read(pipefd[0], buffer, 1) == 0);
    close(pipefd[0]);
    child_status(child, 0);

    child = fork();
    CHECK(child >= 0);
    if (!child) {
        execl(argv[0], argv[0], "child", (char*)0);
        _exit(99);
    }
    child_status(child, 17);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        char* args[] = {"missing", 0};
        CHECK(execv("/does-not-exist", args) == -1 && errno == ENOENT);
        _exit(23);
    }
    child_status(child, 23);

    DIR* dir = opendir("/bin");
    CHECK(dir != 0);
    int entries = 0;
    while (readdir(dir))
        entries++;
    CHECK(entries > 4);
    CHECK(closedir(dir) == 0);
    CHECK(mkdir("/tmp/abi-dir", 0755) == 0);
    CHECK(chdir("/tmp/abi-dir") == 0);
    CHECK(getcwd(buffer, sizeof(buffer)) == buffer && !strcmp(buffer, "/tmp/abi-dir"));
    CHECK(chdir("/") == 0);
    CHECK(rmdir("/tmp/abi-dir") == 0);

    struct timespec before, after, delay = {0, 20000000};
    CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    CHECK(nanosleep(&delay, 0) == 0);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    CHECK(after.tv_sec > before.tv_sec || after.tv_nsec >= before.tv_nsec + 20000000);
    puts("ABI_TESTS_PASS linkage=" ABI_LINKAGE);
    return 0;
}
