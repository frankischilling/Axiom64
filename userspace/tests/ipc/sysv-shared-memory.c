// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { page = 4096 };

static void check(int success, const char* operation) {
    if (!success) {
        fprintf(stderr, "SYSV_SHM_FAIL %s errno=%d\n", operation, errno);
        _exit(1);
    }
}

#define fails(call, error) check((call) == -1 && errno == (error), #call)
#define attach_fails(call, error) check((call) == (void*)-1 && errno == (error), #call)

static void ordinary(void) {
    check(!setgroups(0, NULL) && !setgid(65534) && !setuid(65534), "ordinary credentials");
}

static struct shmid_ds status_of(int id) {
    struct shmid_ds info;
    check(!shmctl(id, IPC_STAT, &info), "IPC_STAT");
    return info;
}

static key_t status_key(struct shmid_ds info) {
    key_t key;
    // x86-64 ipc_perm starts with the key. Libc uses different private member names.
    memcpy(&key, &info.shm_perm, sizeof(key));
    return key;
}

static int segment(size_t size, int mode) {
    int id = shmget(IPC_PRIVATE, size, mode);
    check(id >= 0, "private segment");
    return id;
}

static char* attach(int id, void* base, int flags) {
    void* ptr = shmat(id, base, flags);
    check(ptr != (void*)-1, "attach segment");
    return ptr;
}

static void wait_ok(pid_t child) {
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child completion");
}

static void recent(time_t timestamp) {
    time_t actual = time(NULL);
    check(timestamp <= actual && timestamp >= actual - 5, "wall clock timestamp");
}

static char* anonymous(void* base, size_t length, int fixed) {
    char* ptr = mmap(base, length, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | (fixed ? MAP_FIXED : 0), -1, 0);
    check(ptr != MAP_FAILED && (!fixed || ptr == base), "anonymous mapping");
    return ptr;
}

static int write_from_pipe(void* address) {
    int fds[2];
    check(!pipe(fds) && write(fds[1], "p", 1) == 1, "mapping probe pipe");
    int result = read(fds[0], address, 1);
    int error = errno;
    check(!close(fds[0]) && !close(fds[1]), "close mapping probe");
    errno = error;
    return result;
}

static void metadata(void) {
    key_t key = 0x6d000000 | getpid();
    fails(shmget(key, 0, 0600), ENOENT);
    int id = shmget(key, page + 1, IPC_CREAT | IPC_EXCL | 0600);
    check(id >= 0, "create named segment");
    check(shmget(key, 0, 0400) == id, "keyed lookup");
    fails(shmget(key, page + 2, 0400), EINVAL);
    fails(shmget(key, page + 1, IPC_CREAT | IPC_EXCL | 0600), EEXIST);
    struct shmid_ds info = status_of(id);
    check(status_key(info) == key && info.shm_segsz == page + 1 && info.shm_perm.uid == getuid() &&
              info.shm_perm.cuid == getuid() && info.shm_perm.gid == getgid() &&
              info.shm_perm.cgid == getgid() && (info.shm_perm.mode & 0777) == 0600 &&
              info.shm_cpid == getpid() && !info.shm_lpid && !info.shm_nattch && !info.shm_atime &&
              !info.shm_dtime,
          "new segment ABI metadata");
    recent(info.shm_ctime);
    struct shminfo limits;
    struct shm_info usage;
    int slot = shmctl(0, SHM_INFO, (struct shmid_ds*)&usage);
    check(slot >= 0 && usage.used_ids == 1 && usage.shm_tot == 2, "live segment page accounting");
    check(shmctl(0, IPC_INFO, (struct shmid_ds*)&limits) == slot && limits.shmmin == 1 &&
              limits.shmmax >= page + 1 && limits.shmmni >= 64 && limits.shmseg >= 64,
          "IPC limits");
    check(shmctl(slot, SHM_STAT, &info) == id && shmctl(slot, SHM_STAT_ANY, &info) == id,
          "indexed lookup returns live identifier");

    char* first = attach(id, NULL, 0);
    check(first[page] == 0, "rounded last page initially zero");
    first[page] = 's';
    info = status_of(id);
    check(info.shm_nattch == 1 && info.shm_lpid == getpid(), "attach stats");
    recent(info.shm_atime);
    check(!shmctl(id, IPC_RMID, NULL), "mark attached segment for removal");
    info = status_of(id);
    check(status_key(info) == IPC_PRIVATE && (info.shm_perm.mode & SHM_DEST) &&
              info.shm_nattch == 1,
          "removed segment retains only its numeric lookup");
    fails(shmget(key, 0, 0), ENOENT);
    int replacement = shmget(key, page, IPC_CREAT | IPC_EXCL | 0600);
    check(replacement >= 0 && replacement != id, "key reuse while old region remains attached");
    char* second = attach(id, NULL, SHM_RDONLY);
    check(second[page] == 's', "still-live marked segment accepts a new attachment by identifier");
    check(!shmdt(second), "detach read-only attachment");
    recent(status_of(id).shm_dtime);
    check(!munmap(first, 2 * page), "last ordinary unmap releases removed segment");
    fails(shmctl(id, IPC_STAT, &info), EINVAL);
    check(!shmctl(replacement, IPC_RMID, NULL), "remove replacement");
}

static void fragments(void) {
    int id = segment(4 * page, 0600);
    char* base = attach(id, NULL, 0);
    char* read_only = attach(id, NULL, SHM_RDONLY);
    base[page] = 'c';
    check(read_only[page] == 'c' && !mprotect(read_only, page, PROT_NONE) &&
              !mprotect(read_only, page, PROT_READ),
          "permission splits preserve shared pages");
    fails(mprotect(read_only, page, PROT_READ | PROT_WRITE), EACCES);
    check(!shmdt(read_only) && status_of(id).shm_nattch == 1, "detach protected alias fragments");
    check(!mprotect(base + page, page, PROT_READ) && status_of(id).shm_nattch == 3,
          "middle protection change creates three VMAs");
    check(!mprotect(base + page, page, PROT_READ | PROT_WRITE) && status_of(id).shm_nattch == 3 &&
              base[page] == 'c',
          "restoring protection preserves fragment identity");
    check(!munmap(base, page) && status_of(id).shm_nattch == 2, "base page unmap");
    anonymous(base, page, 1);
    char filename[] = "/tmp/shm-replacement-XXXXXX";
    int fd = mkstemp(filename);
    check(fd >= 0 && !unlink(filename) && !ftruncate(fd, page), "prepare backing file");
    check(mmap(base + 2 * page, page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, fd, 0) ==
              base + 2 * page,
          "install file mapping in a shared fragment");
    check(status_of(id).shm_nattch == 2, "fixed replacement trims its shared fragment");
    fails(shmdt(base + page), EINVAL);
    check(!shmdt(base) && !status_of(id).shm_nattch, "detach by original base across holes");
    check(write_from_pipe(base) == 1 && write_from_pipe(base + 2 * page) == 1,
          "detaching leaves unrelated replacements mapped");
    char value;
    check(pread(fd, &value, 1, 0) == 1 && value == 'p' && !close(fd),
          "surviving file replacement still shares its backing");
    fails(write_from_pipe(base + page), EFAULT);
    fails(write_from_pipe(base + 3 * page), EFAULT);
    fails(shmdt(base), EINVAL);
    check(!munmap(base, 4 * page) && !shmctl(id, IPC_RMID, NULL), "fragment cleanup");

    id = segment(3 * page, 0600);
    base = attach(id, NULL, 0);
    check(!munmap(base + page, page) && status_of(id).shm_nattch == 2, "middle unmap splits VMA");
    check(!shmdt(base) && !status_of(id).shm_nattch && !shmctl(id, IPC_RMID, NULL),
          "detaching across an unmapped middle releases both ends");
}

static void remapping(void) {
    int long_id = segment(3 * page, 0600);
    int short_id = segment(page, 0600);
    char* address = anonymous(NULL, 3 * page, 0);
    check(!munmap(address, 3 * page), "reserve an explicit range");
    attach_fails(shmat(long_id, address + 1, 0), EINVAL);
    attach_fails(shmat(long_id, NULL, SHM_REMAP), EINVAL);
    check(attach(long_id, address + 1, SHM_RND) == address, "rounded explicit attach");
    address[2 * page] = 't';
    attach_fails(shmat(short_id, address, 0), EINVAL);
    check(attach(short_id, address, SHM_REMAP) == address && address[2 * page] == 't',
          "remap replaces only the new segment's extent");
    check(status_of(short_id).shm_nattch == 1 && status_of(long_id).shm_nattch == 1,
          "both mapping identities remain");
    check(!shmdt(address) && !status_of(short_id).shm_nattch &&
              status_of(long_id).shm_nattch == 1 && address[2 * page] == 't',
          "detach selects new mapping before displaced remainder");
    check(!shmctl(long_id, IPC_RMID, NULL) && attach(long_id, address, SHM_REMAP) == address &&
              address[2 * page] == 't' && status_of(long_id).shm_nattch == 1,
          "remapping the final removed attachment keeps its backing alive");
    check(!shmdt(address) && !shmctl(short_id, IPC_RMID, NULL), "detach remapped regions");
    struct shmid_ds info;
    fails(shmctl(long_id, IPC_STAT, &info), EINVAL);
}

struct shared_vm {
    int id;
    char* base;
};

static int detach_shared(void* argument) {
    struct shared_vm* shared = argument;
    check(status_of(shared->id).shm_nattch == 2 && shared->base[0] == 'x',
          "CLONE_VM shares the same fragments");
    check(!shmdt(shared->base), "shared address space detach");
    return 0;
}

static void process_lifecycle(const char* executable) {
    int id = segment(2 * page, 0600);
    char* base = attach(id, NULL, 0);
    base[0] = 'x';
    check(!mprotect(base + page, page, PROT_READ), "split attachment before fork");
    pid_t child = fork();
    check(child >= 0, "fork with attachment");
    if (!child) {
        check(status_of(id).shm_nattch == 4 && base[0] == 'x', "fork retains both fragments");
        base[0] = 'y';
        char number[16];
        check(snprintf(number, sizeof(number), "%d", id) > 0, "exec segment identifier");
        execl(executable, executable, "--inspect-exec", number, (char*)NULL);
        check(0, "exec same probe");
    }
    wait_ok(child);
    struct shmid_ds info = status_of(id);
    check(info.shm_nattch == 2 && info.shm_lpid == child && base[0] == 'y',
          "exec closed only the child's fragments");
    recent(info.shm_dtime);

    base[0] = 'x';
    struct shared_vm shared = {id, base};
    void* stack = malloc(65536);
    check(stack != NULL, "clone stack");
    child = clone(detach_shared, (char*)stack + 65536, CLONE_VM | SIGCHLD, &shared);
    check(child >= 0, "shared VM child");
    wait_ok(child);
    free(stack);
    check(!status_of(id).shm_nattch, "shared detach visible to parent");
    fails(shmdt(base), EINVAL);
    check(!shmctl(id, IPC_RMID, NULL), "process test segment cleanup");

    int channel[2];
    check(!pipe(channel), "exit synchronization");
    id = segment(page, 0600);
    child = fork();
    check(child >= 0, "fork final mapping owner");
    if (!child) {
        check(!close(channel[1]), "close child writer");
        attach(id, NULL, 0);
        check(!shmctl(id, IPC_RMID, NULL), "remove last-child segment");
        char token;
        check(read(channel[0], &token, 1) == 1, "release exiting child");
        _exit(0);
    }
    check(!close(channel[0]) && write(channel[1], "x", 1) == 1 && !close(channel[1]),
          "allow child to exit");
    wait_ok(child);
    fails(shmctl(id, IPC_STAT, &info), EINVAL);
}

static void locking(void) {
    if (!getuid())
        return;
    struct rlimit limit = {page, page};
    check(!setrlimit(RLIMIT_MEMLOCK, &limit), "memlock test budget");
    int first = segment(page, 0600), second = segment(page, 0600);
    check(!shmctl(first, SHM_LOCK, NULL) && (status_of(first).shm_perm.mode & SHM_LOCKED),
          "ordinary owner locks one segment");
    check(!shmctl(first, SHM_LOCK, NULL), "repeat lock does not charge twice");
    fails(shmctl(second, SHM_LOCK, NULL), ENOMEM);
    check(!(status_of(second).shm_perm.mode & SHM_LOCKED), "failed lock leaves metadata unchanged");
    check(!shmctl(first, SHM_UNLOCK, NULL) && !(status_of(first).shm_perm.mode & SHM_LOCKED) &&
              !shmctl(second, SHM_LOCK, NULL),
          "unlock releases the user's budget");
    check(!shmctl(first, IPC_RMID, NULL) && !shmctl(second, IPC_RMID, NULL),
          "destroy locked and unlocked segments");
}

static void permissions(void) {
    if (getuid())
        return;
    int id = segment(page, 0600);
    struct shmid_ds info = status_of(id);
    int slot = shmctl(0, SHM_INFO, (struct shmid_ds*)&(struct shm_info){0});
    check(slot >= 0, "indexed status slot");
    pid_t child = fork();
    check(child >= 0, "fork nonowner");
    if (!child) {
        ordinary();
        fails(shmctl(id, IPC_STAT, &info), EACCES);
        fails(shmctl(slot, SHM_STAT, &info), EACCES);
        check(shmctl(slot, SHM_STAT_ANY, &info) == id && info.shm_perm.cuid == 0,
              "unprivileged indexed enumeration");
        fails(shmctl(id, IPC_RMID, NULL), EPERM);
        fails(shmctl(id, SHM_LOCK, NULL), EPERM);
        attach_fails(shmat(id, NULL, SHM_RDONLY), EACCES);
        _exit(0);
    }
    wait_ok(child);

    char* writable = attach(id, NULL, 0);
    const unsigned char code[] = {0xb8, 37, 0, 0, 0, 0xc3}; // return 37
    memcpy(writable, code, sizeof(code));
    info.shm_perm.gid = 65534;
    info.shm_perm.mode = 0650;
    check(!shmctl(id, IPC_SET, &info), "grant read and execute access to segment group");
    child = fork();
    check(child >= 0, "fork group member");
    if (!child) {
        ordinary();
        attach_fails(shmat(id, NULL, 0), EACCES);
        char* executable = attach(id, NULL, SHM_RDONLY | SHM_EXEC);
        check(((int (*)(void))executable)() == 37, "SHM_EXEC installs executable shared pages");
        fails(mprotect(executable, page, PROT_READ | PROT_WRITE), EACCES);
        check(!shmdt(executable), "detach group mapping");
        _exit(0);
    }
    wait_ok(child);
    check(!shmdt(writable) && !shmctl(id, IPC_RMID, NULL), "permission test cleanup");
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(20);
    if (argc == 3 && !strcmp(argv[1], "--inspect-exec")) {
        check(status_of(atoi(argv[2])).shm_nattch == 2, "exec detached inherited fragments");
        return 0;
    }
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")), "arguments");
    if (argc == 2)
        ordinary();
    metadata();
    puts("SYSV_SHM_CASE metadata");
    fragments();
    puts("SYSV_SHM_CASE fragments");
    remapping();
    puts("SYSV_SHM_CASE remapping");
    process_lifecycle(argv[0]);
    puts("SYSV_SHM_CASE process-lifecycle");
    locking();
    puts("SYSV_SHM_CASE locking");
    permissions();
    puts("SYSV_SHM_CASE permissions");
    printf("SYSV_SHM_PASS uid=%u\n", (unsigned)getuid());
    return 0;
}
