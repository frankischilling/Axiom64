// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/manager/ownership.hpp"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using ax::net::Ownership;

static void check(bool condition, const char* reason) {
    if (!condition) {
        fprintf(stderr, "OWNERSHIP_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static bool busy(int error) {
    return error == EWOULDBLOCK || error == EAGAIN;
}

static void transfer(int fd, void* data, size_t size, bool output) {
    auto* bytes = static_cast<char*>(data);
    while (size) {
        ssize_t count = output ? write(fd, bytes, size) : read(fd, bytes, size);
        if (count < 0 && errno == EINTR)
            continue;
        check(count > 0, "process handshake");
        bytes += count;
        size -= size_t(count);
    }
}

static void wait_ok(pid_t child) {
    int status = 0;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "child result");
}

static struct stat metadata(const char* path) {
    struct stat value;
    check(lstat(path, &value) == 0, "metadata");
    return value;
}

static void file(const char* path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    check(fd >= 0 && write(fd, "keep", 4) == 4 && close(fd) == 0, "fixture file");
}

static const char* replaced_lock;
static const char* replacement_backup;
static bool replace_after_lock;
extern "C" int __real_flock(int, int);

extern "C" int __wrap_flock(int descriptor, int operation) {
    int result = __real_flock(descriptor, operation);
    if (!result && replace_after_lock) {
        replace_after_lock = false;
        check(rename(replaced_lock, replacement_backup) == 0,
              "inode substitution preserves the held inode elsewhere");
        file(replaced_lock);
    }
    return result;
}

int main(int argc, char** argv) {
    alarm(30);
    if (argc == 5 && !strcmp(argv[1], "--handoff")) {
        int input = atoi(argv[3]), output = atoi(argv[4]);
        char ready = 'r';
        transfer(output, &ready, 1, true);
        transfer(input, &ready, 1, false);
        Ownership owner;
        check(owner.open(argv[2]) == 0 && owner.close() == 0,
              "exec discards the inherited close-on-exec lock");
        return 0;
    }
    check(argc == 2 || argc == 3, "fixture root argument");
    const char* root = argv[1];
    char runtime[256], lock[300], alias[300];
    check(snprintf(runtime, sizeof(runtime), "%s/private/manager", root) > 0, "runtime spelling");
    check(snprintf(lock, sizeof(lock), "%s/manager.lock", runtime) > 0, "lock spelling");
    Ownership owner, contender;
    check(owner.open(nullptr) == EINVAL, "null runtime rejected");
    check(owner.open("/") == EINVAL && owner.open("relative") == EINVAL,
          "unsafe runtime spelling rejected");
    mode_t old = umask(0777);
    check(owner.open(runtime) == 0,
          "first owner creates a private runtime under restrictive umask");
    umask(old);
    struct stat original = metadata(lock), directory = metadata(runtime);
    check(S_ISREG(original.st_mode) && (original.st_mode & 07777) == 0600 &&
              original.st_uid == geteuid() && original.st_nlink == 1 &&
              S_ISDIR(directory.st_mode) && (directory.st_mode & 07777) == 0700 &&
              directory.st_uid == geteuid(),
          "exact private modes and owner");
    check(owner.open(runtime) == EALREADY && busy(contender.open(runtime)),
          "same object and competing descriptions rejected");
    check(metadata(lock).st_ino == original.st_ino, "failed contender preserves lock inode");
    check(owner.close() == 0 && owner.close() == 0 && contender.open(runtime) == 0 &&
              contender.close() == 0,
          "final close allows restart without unlink");
    int fd = open(lock, O_WRONLY);
    check(fd >= 0 && write(fd, "keep", 4) == 4 && close(fd) == 0, "opaque contents");
    check(owner.open(runtime) == 0 && owner.close() == 0, "existing lock acquired");
    char content[4];
    fd = open(lock, O_RDONLY);
    check(fd >= 0 && read(fd, content, 4) == 4 && !memcmp(content, "keep", 4) && close(fd) == 0,
          "acquisition never truncates contents");

    check(owner.open(runtime) == 0, "parent exec owner");
    int ready[2], release[2];
    check(pipe(ready) == 0 && pipe(release) == 0, "exec pipes");
    pid_t child = fork();
    check(child >= 0, "exec fork");
    if (!child) {
        char input[16], output[16];
        snprintf(input, sizeof(input), "%d", release[0]);
        snprintf(output, sizeof(output), "%d", ready[1]);
        execl(argv[0], argv[0], "--handoff", runtime, input, output, static_cast<char*>(nullptr));
        _exit(2);
    }
    char message = 'r';
    transfer(ready[0], &message, 1, false);
    check(owner.close() == 0, "parent releases after exec");
    transfer(release[1], &message, 1, true);
    wait_ok(child);
    const int exec_pipes[]{ready[0], ready[1], release[0], release[1]};
    for (int pipefd : exec_pipes)
        check(close(pipefd) == 0, "exec pipes closed");

    int gate[2], results[2];
    char race_runtime[256], race_lock[300];
    snprintf(race_runtime, sizeof(race_runtime), "%s/creation-race", root);
    snprintf(race_lock, sizeof(race_lock), "%s/manager.lock", race_runtime);
    check(mkdir(race_runtime, 0700) == 0, "fresh first-creation race directory");
    check(pipe(gate) == 0 && pipe(results) == 0 && pipe(release) == 0, "race pipes");
    pid_t children[8];
    for (unsigned i = 0; i < 8; i++) {
        children[i] = fork();
        check(children[i] >= 0, "race fork");
        if (!children[i]) {
            transfer(gate[0], &message, 1, false);
            Ownership candidate;
            int error = candidate.open(race_runtime);
            check(!error || busy(error), "racing contender result");
            transfer(results[1], &error, sizeof(error), true);
            if (!error)
                transfer(release[0], &message, 1, false);
            check(candidate.close() == 0, "race close");
            _exit(0);
        }
    }
    char tickets[8]{};
    transfer(gate[1], tickets, sizeof(tickets), true);
    unsigned winners = 0;
    for (unsigned i = 0; i < 8; i++) {
        int error;
        transfer(results[0], &error, sizeof(error), false);
        winners += error == 0;
    }
    struct stat race_inode = metadata(race_lock);
    check(winners == 1 && busy(owner.open(race_runtime)), "exactly one simultaneous owner");
    transfer(release[1], &message, 1, true);
    for (pid_t process : children)
        wait_ok(process);
    const int race_pipes[]{gate[0], gate[1], results[0], results[1], release[0], release[1]};
    for (int pipefd : race_pipes)
        check(close(pipefd) == 0, "race pipes closed");
    check(owner.open(race_runtime) == 0 && owner.close() == 0 &&
              metadata(race_lock).st_ino == race_inode.st_ino,
          "races preserve one permanent inode");

    check(pipe(ready) == 0, "exit pipe");
    child = fork();
    check(child >= 0, "exit fork");
    if (!child) {
        Ownership candidate;
        check(candidate.open(runtime) == 0, "child owns before kill");
        transfer(ready[1], &message, 1, true);
        for (;;)
            pause();
    }
    transfer(ready[0], &message, 1, false);
    check(busy(owner.open(runtime)) && kill(child, SIGKILL) == 0, "kill live owner");
    int status;
    check(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
              WTERMSIG(status) == SIGKILL && owner.open(runtime) == 0 && owner.close() == 0,
          "process death releases ownership");
    check(close(ready[0]) == 0 && close(ready[1]) == 0, "exit pipes closed");

    char replaced[300];
    snprintf(replaced, sizeof(replaced), "%s/replaced-lock", runtime);
    replaced_lock = lock;
    replacement_backup = replaced;
    replace_after_lock = true;
    check(owner.open(runtime) == ESTALE && !replace_after_lock,
          "inode substitution after acquiring the real flock is rejected");
    check(unlink(lock) == 0 && rename(replaced, lock) == 0 && owner.open(runtime) == 0 &&
              owner.close() == 0 && metadata(lock).st_ino == original.st_ino,
          "rejected substitution releases the original lock without unlinking it");

    snprintf(alias, sizeof(alias), "%s/alias", runtime);
    check(link(lock, alias) == 0 && owner.open(runtime) == EACCES && unlink(alias) == 0,
          "hard-linked lock rejected");
    const mode_t modes[]{0000, 0400, 0644, 0666, 0700};
    for (mode_t mode : modes) {
        check(chmod(lock, mode) == 0 && owner.open(runtime) == EACCES,
              "unsafe lock permissions rejected");
    }
    check(chmod(lock, 0600) == 0 && chmod(runtime, 0755) == 0 && owner.open(runtime) == EACCES &&
              chmod(runtime, 0700) == 0,
          "unsafe runtime permissions rejected");
    check(rename(lock, alias) == 0 && symlink(alias, lock) == 0 && owner.open(runtime) == ELOOP &&
              unlink(lock) == 0 && rename(alias, lock) == 0,
          "symlink lock rejected");
    check(rename(lock, alias) == 0 && mkdir(lock, 0700) == 0 && owner.open(runtime) == EINVAL &&
              rmdir(lock) == 0,
          "nonregular lock rejected");
    if (argc == 3 && !strcmp(argv[2], "--native")) {
        check(mkfifo(lock, 0600) == 0, "writerless FIFO fixture");
        for (unsigned i = 0; i < 300; i++)
            check(owner.open(runtime) == EINVAL, "writerless FIFO never blocks or leaks");
        check(unlink(lock) == 0, "FIFO cleanup");
        if (!geteuid()) {
            file(lock);
            check(chown(lock, 65534, 65534) == 0 && owner.open(runtime) == EACCES &&
                      unlink(lock) == 0,
                  "real foreign-owned lock rejected under root");
        }
    }
    check(rename(alias, lock) == 0 && owner.open(runtime) == 0 && owner.close() == 0 &&
              metadata(lock).st_ino == original.st_ino,
          "rejected paths leave original inode intact");
    if (argc == 3 && !geteuid())
        check(chown(runtime, 65534, 65534) == 0 && owner.open(runtime) == EACCES &&
                  chown(runtime, 0, 0) == 0,
              "real foreign-owned runtime rejected under root");
    puts("OWNERSHIP_PASS modes=private race_owners=1 fork_exec=pass killed_restart=pass");
    return 0;
}
