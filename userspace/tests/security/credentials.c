// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef CREDENTIAL_LINKAGE
#define CREDENTIAL_LINKAGE "static"
#endif
#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "CREDENTIAL_TEST_FAIL line=%d condition=%s errno=%d\n", __LINE__,      \
                    #condition, errno);                                                            \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
#define ERROR(expression, code)                                                                    \
    do {                                                                                           \
        errno = 0;                                                                                 \
        CHECK((expression) == -1 && errno == (code));                                              \
    } while (0)

static void wait_child(pid_t child) {
    int status;
    CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
          !WEXITSTATUS(status));
}

static void drop(uid_t user) {
    gid_t group = user;
    CHECK(setgroups(1, &group) == 0);
    CHECK(setresgid(user, user, user) == 0);
    CHECK(setresuid(user, user, user) == 0);
}

static void check_ids(uid_t real, uid_t effective, uid_t saved) {
    uid_t r = -1, e = -1, s = -1;
    CHECK(getresuid(&r, &e, &s) == 0 && r == real && e == effective && s == saved);
    CHECK(getuid() == real && geteuid() == effective);
    CHECK((uid_t)syscall(SYS_setfsuid, -1) == effective);
}

static void identity_tests(void) {
    gid_t groups[] = {1003, 1001, 1003};
    CHECK(setgroups(3, groups) == 0 && getgroups(0, NULL) == 3);
    gid_t actual[3];
    CHECK(getgroups(3, actual) == 3 && actual[0] == 1001 && actual[1] == 1003 && actual[2] == 1003);
    ERROR(syscall(SYS_getgroups, 2, actual), EINVAL);
    ERROR(syscall(SYS_getgroups, -1, actual), EINVAL);
    ERROR(syscall(SYS_getgroups, 3, 1), EFAULT);
    ERROR(syscall(SYS_setgroups, 3, 1), EFAULT);
    gid_t invalid = -1;
    ERROR(syscall(SYS_setgroups, 1, &invalid), EINVAL);
    ERROR(syscall(SYS_setgroups, 65537, groups), EINVAL);
    CHECK(getgroups(0, NULL) == 3);
    ERROR(syscall(SYS_setuid, -1), EINVAL);
    ERROR(syscall(SYS_setgid, -1), EINVAL);
    uid_t r = 42, s = 43;
    ERROR(syscall(SYS_getresuid, &r, 1, &s), EFAULT);
    CHECK(r == 0 && s == 43);
    CHECK((uid_t)syscall(SYS_setfsuid, 1001) == 0);
    CHECK((uid_t)syscall(SYS_setfsuid, -1) == 1001);
    CHECK((uid_t)syscall(SYS_setfsuid, 0) == 1001);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setresgid(1001, 1002, 1003) == 0);
        CHECK(setresuid(1001, 0, 0) == 0);
        CHECK(seteuid(1002) == 0);
        check_ids(1001, 1002, 0);
        ERROR(setuid(1002), EPERM);
        CHECK(setuid(0) == 0);
        check_ids(1001, 0, 0);
        CHECK(setuid(1001) == 0);
        check_ids(1001, 1001, 1001);
        ERROR(setuid(0), EPERM);
        ERROR(setgroups(0, NULL), EPERM);
        CHECK((uid_t)syscall(SYS_setfsuid, 0) == 1001);
        CHECK(getgroups(3, actual) == 3 && actual[0] == 1001);
        _exit(0);
    }
    wait_child(child);
    check_ids(0, 0, 0);
    CHECK(getgroups(0, NULL) == 3 && setgroups(0, NULL) == 0);
    puts("CREDENTIAL_IDS_PASS faults saved_ids filesystem_ids fork groups");
}

static atomic_int ready, release_worker;
static int raw_thread;

static void* worker(void* unused) {
    (void)unused;
    if (raw_thread)
        CHECK(syscall(SYS_setresuid, 1001, 1001, 1001) == 0);
    atomic_store(&ready, 1);
    while (!atomic_load(&release_worker))
        sched_yield();
    check_ids(1001, 1001, 1001);
    if (!raw_thread) {
        gid_t groups[2];
        CHECK(getgid() == 1001 && getegid() == 1001 && getgroups(2, groups) == 2);
        CHECK(groups[0] == 1001 && groups[1] == 1003);
    }
    return NULL;
}

static void thread_tests(void) {
    for (raw_thread = 0; raw_thread < 2; raw_thread++) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            pthread_t thread;
            atomic_store(&ready, 0);
            atomic_store(&release_worker, 0);
            CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
            while (!atomic_load(&ready))
                sched_yield();
            if (raw_thread)
                check_ids(0, 0, 0);
            else {
                gid_t groups[] = {1003, 1001};
                CHECK(setgroups(2, groups) == 0 && setgid(1001) == 0 && setuid(1001) == 0);
                check_ids(1001, 1001, 1001);
            }
            atomic_store(&release_worker, 1);
            CHECK(pthread_join(thread, NULL) == 0);
            _exit(0);
        }
        wait_child(child);
    }
    puts("CREDENTIAL_THREADS_PASS wrappers all_threads raw_syscall task_local");
}

struct capability_header {
    unsigned version;
    int pid;
};

struct capability_data {
    unsigned effective, permitted, inheritable;
};

static void capability_tests(void) {
    struct capability_header header = {0, 0};
    CHECK(syscall(SYS_capget, &header, NULL) == 0 && header.version == 0x20080522);
    struct capability_data data[2];
    CHECK(syscall(SYS_capget, &header, data) == 0 && (data[0].effective & (1u << 7)));
    ERROR(syscall(SYS_capget, 1, data), EFAULT);
    ERROR(syscall(SYS_capset, &header, 1), EFAULT);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct capability_data reduced[2];
        memcpy(reduced, data, sizeof(data));
        reduced[0].effective &= ~(1u << 7);
        reduced[0].permitted &= ~(1u << 7);
        CHECK(syscall(SYS_capset, &header, reduced) == 0);
        ERROR(syscall(SYS_capset, &header, data), EPERM);
        ERROR(setuid(1001), EPERM);
        _exit(0);
    }
    wait_child(child);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0);
        drop(1001);
        CHECK(syscall(SYS_capget, &header, data) == 0 && !data[0].effective && !data[1].effective);
        CHECK(data[0].permitted & (1u << 7));
        data[0].effective = 1u << 7;
        CHECK(syscall(SYS_capset, &header, data) == 0 && setuid(1002) == 0);
        data[0].effective = data[0].permitted = data[0].inheritable = 0;
        data[1].effective = data[1].permitted = data[1].inheritable = 0;
        CHECK(syscall(SYS_capset, &header, data) == 0);
        ERROR(setuid(0), EPERM);
        CHECK(prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0 && prctl(PR_GET_DUMPABLE) == 1);
        CHECK(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 && prctl(PR_GET_DUMPABLE) == 0);
        _exit(0);
    }
    wait_child(child);
    puts("CREDENTIAL_CAPS_PASS capget capset irreversible_mask keepcaps dumpable");
}

static void file(const char* name, uid_t owner, gid_t group, mode_t mode) {
    int fd = open(name, O_CREAT | O_TRUNC | O_RDWR, 0600);
    CHECK(fd >= 0 && write(fd, "original", 8) == 8);
    CHECK(fchown(fd, owner, group) == 0 && fchmod(fd, mode) == 0 && close(fd) == 0);
}

static void permission_tests(void) {
    CHECK(mkdir("hidden", 0700) == 0 && mkdir("sticky", 01777) == 0 && chmod("sticky", 01777) == 0);
    CHECK(mkdir("inherited", 02777) == 0 && chown("inherited", 0, 1002) == 0 &&
          chmod("inherited", 02777) == 0);
    file("owner1", 1001, 1001, 0600);
    file("owner2", 1002, 1002, 0600);
    file("group", 1002, 1001, 0640);
    file("hidden/secret", 0, 0, 0644);
    file("sticky/own", 1001, 1001, 0666);
    file("sticky/other", 1002, 1002, 0666);
    file("retained", 0, 0, 0600);
    CHECK(symlink("owner2", "link2") == 0);
    int retained = open("retained", O_RDWR);
    CHECK(retained >= 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        struct stat state;
        int fd = open("owner1", O_RDWR);
        CHECK(fd >= 0 && close(fd) == 0);
        fd = open("group", O_RDONLY);
        CHECK(fd >= 0 && close(fd) == 0);
        ERROR(open("group", O_WRONLY), EACCES);
        ERROR(open("owner2", O_RDONLY), EACCES);
        ERROR(open("link2", O_RDWR), EACCES);
        ERROR(open("hidden/secret", O_RDONLY), EACCES);
        ERROR(stat("hidden/secret", &state), EACCES);
        ERROR(chdir("hidden"), EACCES);
        ERROR(chmod("owner2", 0777), EPERM);
        ERROR(chown("owner1", 1002, -1), EPERM);
        CHECK(chown("owner1", -1, 1001) == 0);
        ERROR(chown("owner1", -1, 1002), EPERM);
        CHECK(unlink("sticky/own") == 0);
        ERROR(unlink("sticky/other"), EPERM);
        ERROR(rename("sticky/other", "sticky/moved"), EPERM);
        CHECK(write(retained, "changed!", 8) == 8);
        fd = open("zero", O_CREAT | O_EXCL | O_RDWR, 0000);
        CHECK(fd >= 0 && write(fd, "zero", 4) == 4 && close(fd) == 0);
        ERROR(open("zero", O_RDONLY), EACCES);
        CHECK(mkdir("inherited/child", 0755) == 0);
        CHECK(stat("inherited/child", &state) == 0 && state.st_uid == 1001 &&
              state.st_gid == 1002 && (state.st_mode & S_ISGID));
        ERROR(syscall(SYS_chroot, "."), EPERM);
        ERROR(socket(AF_PACKET, SOCK_RAW, 0), EPERM);
        ERROR(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), EPERM);
        CHECK(kill(getpid(), 0) == 0);
        ERROR(kill(getppid(), 0), EPERM);
        ERROR(syscall(SYS_ptrace, 16, getppid(), 0, 0), EPERM);
        ERROR(setpgid(getppid(), 0), ESRCH);
        ERROR(link("helper", "helper-alias"), EPERM);
        _exit(0);
    }
    wait_child(child);
    CHECK(close(retained) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setresuid(1001, 0, 0) == 0);
        ERROR(access("owner2", R_OK), EACCES);
        CHECK(faccessat(AT_FDCWD, "owner2", R_OK, AT_EACCESS) == 0);
        _exit(0);
    }
    wait_child(child);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1002);
        int fd = open("owner2", O_RDWR);
        CHECK(fd >= 0 && close(fd) == 0);
        ERROR(open("owner1", O_RDONLY), EACCES);
        fd = open("group", O_RDONLY);
        CHECK(fd >= 0 && close(fd) == 0);
        CHECK(kill(getpid(), 0) == 0);
        ERROR(kill(getppid(), 0), EPERM);
        _exit(0);
    }
    wait_child(child);
    puts("CREDENTIAL_DAC_PASS two_users groups traversal sticky inherited_owner retained_fd");
}

static void path_tests(void) {
    CHECK(mkdir("jail", 0755) == 0 && mkdir("jail/sub", 0755) == 0);
    file("jail/inside", 0, 0, 0644);
    CHECK(symlink("/inside", "jail/absolute") == 0);
    CHECK(symlink("../../inside", "jail/sub/relative") == 0);
    CHECK(symlink("../owner1", "jail/escape") == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        int directory = open(".", O_RDONLY | O_DIRECTORY);
        int retained = open("retained", O_RDONLY);
        CHECK(directory >= 0 && retained >= 0);
        CHECK(chroot("jail") == 0 && chdir("/") == 0);
        drop(1001);
        const char* allowed[] = {"/inside", "/absolute", "/sub/relative", "/../../inside"};
        for (unsigned at = 0; at < sizeof(allowed) / sizeof(allowed[0]); at++) {
            int fd = open(allowed[at], O_RDONLY);
            char bytes[8];
            CHECK(fd >= 0 && read(fd, bytes, sizeof(bytes)) == 8 && !memcmp(bytes, "original", 8));
            CHECK(close(fd) == 0);
        }
        struct stat root, parent;
        CHECK(stat("/", &root) == 0 && stat("/..", &parent) == 0);
        CHECK(root.st_dev == parent.st_dev && root.st_ino == parent.st_ino);
        ERROR(open("/owner1", O_RDONLY), ENOENT);
        ERROR(open("/escape", O_RDONLY), ENOENT);
        char bytes[8];
        CHECK(read(retained, bytes, sizeof(bytes)) == 8 && !memcmp(bytes, "changed!", 8));
        int fd = openat(directory, "owner1", O_RDONLY);
        CHECK(fd >= 0 && close(fd) == 0);
        ERROR(openat(directory, "owner2", O_RDONLY), EACCES);
        CHECK(close(directory) == 0 && close(retained) == 0);
        _exit(0);
    }
    wait_child(child);
    CHECK(unlink("jail/inside") == 0 && unlink("jail/absolute") == 0);
    CHECK(unlink("jail/sub/relative") == 0 && unlink("jail/escape") == 0);
    CHECK(rmdir("jail/sub") == 0 && rmdir("jail") == 0);
    puts("CREDENTIAL_PATH_PASS chroot absolute_relative_symlinks dotdot retained_directory_fd");
}

static volatile sig_atomic_t signal_uid, signal_pid, received;

static void identity_signal(int number, siginfo_t* info, void* context) {
    (void)number;
    (void)context;
    signal_uid = info->si_uid;
    signal_pid = info->si_pid;
    received = 1;
}

static void signal_tests(void) {
    int ready_pipe[2];
    CHECK(pipe(ready_pipe) == 0);
    pid_t receiver = fork();
    CHECK(receiver >= 0);
    if (!receiver) {
        struct sigaction action = {.sa_sigaction = identity_signal, .sa_flags = SA_SIGINFO};
        CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, NULL) == 0);
        drop(1001);
        CHECK(kill(getpid(), SIGUSR1) == 0);
        CHECK(received && signal_uid == 1001 && signal_pid == getpid());
        received = 0;
        CHECK(write(ready_pipe[1], "r", 1) == 1);
        while (!received)
            sched_yield();
        CHECK(signal_uid == 1001 && signal_pid > 0 && signal_pid != getpid());
        _exit(0);
    }
    char marker;
    CHECK(read(ready_pipe[0], &marker, 1) == 1 && marker == 'r');
    CHECK(kill(receiver, 0) == 0);
    pid_t other = fork();
    CHECK(other >= 0);
    if (!other) {
        drop(1002);
        ERROR(kill(receiver, 0), EPERM);
        ERROR(syscall(SYS_ptrace, 16, receiver, 0, 0), EPERM);
        _exit(0);
    }
    wait_child(other);
    pid_t sender = fork();
    CHECK(sender >= 0);
    if (!sender) {
        drop(1001);
        CHECK(kill(receiver, SIGUSR1) == 0);
        _exit(0);
    }
    wait_child(sender);
    wait_child(receiver);
    CHECK(close(ready_pipe[0]) == 0 && close(ready_pipe[1]) == 0);
    puts("CREDENTIAL_SIGNAL_PASS cross_user_denied same_user_allowed siginfo_real_uid");
}

static void network_permission_tests(void) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(fd >= 0);
        struct sockaddr_in address = {
            .sin_family = AF_INET, .sin_port = htons(1), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        ERROR(bind(fd, (struct sockaddr*)&address, sizeof(address)), EACCES);
        struct ifreq request = {0};
        strcpy(request.ifr_name, "lo");
        CHECK(ioctl(fd, SIOCGIFFLAGS, &request) == 0);
        ERROR(ioctl(fd, SIOCSIFFLAGS, &request), EPERM);
        CHECK(close(fd) == 0);
        fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        struct sockaddr_nl local = {.nl_family = AF_NETLINK};
        struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
        CHECK(fd >= 0 && bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0);
        const unsigned types[] = {RTM_NEWADDR, RTM_DELADDR, RTM_NEWROUTE, RTM_DELROUTE};
        for (unsigned at = 0; at < sizeof(types) / sizeof(types[0]); at++) {
            struct {
                struct nlmsghdr header;
                struct rtmsg route;
            } message = {.header = {.nlmsg_len = sizeof(message),
                                    .nlmsg_type = types[at],
                                    .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
                                    .nlmsg_seq = at + 100},
                         .route = {.rtm_family = AF_INET, .rtm_table = RT_TABLE_MAIN}};

            CHECK(sendto(fd, &message, sizeof(message), 0, (struct sockaddr*)&kernel,
                         sizeof(kernel)) == sizeof(message));
            char response[256];
            ssize_t count = recv(fd, response, sizeof(response), 0);
            CHECK(count >= (ssize_t)(sizeof(struct nlmsghdr) + sizeof(int)));
            struct nlmsghdr header;
            int error;
            memcpy(&header, response, sizeof(header));
            memcpy(&error, response + sizeof(header), sizeof(error));
            CHECK(header.nlmsg_type == NLMSG_ERROR && header.nlmsg_seq == at + 100 &&
                  error == -EPERM);
        }
        CHECK(close(fd) == 0);
        ERROR(syscall(SYS_reboot, 0, 0, 0, 0), EPERM);
        _exit(0);
    }
    wait_child(child);
    puts("CREDENTIAL_NETWORK_PASS reserved_ports ioctl netlink_mutations reboot denied");
}

static void ipc_tests(void) {
    int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    CHECK(id >= 0);
    struct shmid_ds info;
    CHECK(shmctl(id, IPC_STAT, &info) == 0 && info.shm_perm.uid == 0 && info.shm_perm.cuid == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        errno = 0;
        CHECK(shmat(id, NULL, SHM_RDONLY) == (void*)-1 && errno == EACCES);
        ERROR(shmctl(id, IPC_STAT, &info), EACCES);
        ERROR(shmctl(id, IPC_RMID, NULL), EPERM);
        _exit(0);
    }
    wait_child(child);
    info.shm_perm.uid = info.shm_perm.gid = 1001;
    CHECK(shmctl(id, IPC_SET, &info) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        CHECK(shmctl(id, IPC_STAT, &info) == 0 && info.shm_perm.uid == 1001 &&
              info.shm_perm.cuid == 0);
        char* bytes = shmat(id, NULL, 0);
        CHECK(bytes != (void*)-1);
        memcpy(bytes, "owned", 6);
        CHECK(shmdt(bytes) == 0);
        info.shm_perm.gid = 1002;
        CHECK(shmctl(id, IPC_SET, &info) == 0);
        CHECK(shmctl(id, IPC_STAT, &info) == 0 && info.shm_perm.gid == 1002);
        _exit(0);
    }
    wait_child(child);
    char* bytes = shmat(id, NULL, SHM_RDONLY);
    CHECK(bytes != (void*)-1 && !memcmp(bytes, "owned", 6) && shmdt(bytes) == 0);
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    puts("CREDENTIAL_SHM_PASS owner creator denied_attach denied_control allowed_payload");
}

static int unix_listener(const char* name, mode_t mode) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    CHECK(fd >= 0 && strlen(name) < sizeof(address.sun_path));
    strcpy(address.sun_path, name);
    CHECK(bind(fd, (struct sockaddr*)&address, sizeof(address)) == 0 && listen(fd, 4) == 0);
    CHECK(chmod(name, mode) == 0);
    return fd;
}

static void peer_credentials(int fd, pid_t pid, uid_t uid, gid_t gid) {
    struct ucred credentials;
    socklen_t size = sizeof(credentials);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) == 0 &&
          size == sizeof(credentials));
    CHECK(credentials.pid == pid && credentials.uid == uid && credentials.gid == gid);
}

static void unix_tests(void) {
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    int restricted = unix_listener("restricted.sock", 0600);
    int public = unix_listener("public.sock", 0666);
    pid_t parent = getpid(), child = fork();
    CHECK(child >= 0);
    if (!child) {
        gid_t group = 1001;
        CHECK(setgroups(1, &group) == 0 && setresgid(1001, 1001, 1001) == 0);
        CHECK(setresuid(1001, 1001, 0) == 0);
        peer_credentials(pair[0], parent, 0, 0);
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        strcpy(address.sun_path, "restricted.sock");
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        CHECK(fd >= 0);
        ERROR(connect(fd, (struct sockaddr*)&address, sizeof(address)), EACCES);
        strcpy(address.sun_path, "public.sock");
        CHECK(connect(fd, (struct sockaddr*)&address, sizeof(address)) == 0);
        peer_credentials(fd, parent, 0, 0);
        CHECK(seteuid(0) == 0 && setuid(1002) == 0 && write(fd, "x", 1) == 1);
        CHECK(close(fd) == 0);
        _exit(0);
    }
    int accepted = accept(public, NULL, NULL);
    char marker;
    CHECK(accepted >= 0 && read(accepted, &marker, 1) == 1 && marker == 'x');
    peer_credentials(accepted, child, 1001, 1001);
    wait_child(child);
    CHECK(close(accepted) == 0 && close(restricted) == 0 && close(public) == 0);
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
    CHECK(unlink("restricted.sock") == 0 && unlink("public.sock") == 0);
    puts("CREDENTIAL_UNIX_PASS pathname_dac captured_peer_identity inherited_connection");
}

static void service(uid_t expected, int secure) {
    check_ids(1001, expected, expected);
    CHECK(getgid() == 1001 && getegid() == 1001);
    CHECK(getauxval(AT_UID) == 1001 && getauxval(AT_EUID) == expected);
    CHECK(getauxval(AT_GID) == 1001 && getauxval(AT_EGID) == 1001);
    CHECK(getauxval(AT_SECURE) == (unsigned)secure);
    if (!expected)
        CHECK(setuid(1001) == 0);
    ERROR(setuid(0), EPERM);
    puts("CREDENTIAL_SERVICE_PASS actual_exec irreversible_drop");
}

static void copy_binary(int input, const char* destination) {
    int output = open(destination, O_CREAT | O_EXCL | O_WRONLY, 0700);
    CHECK(output >= 0);
    char buffer[16384];
    ssize_t count;
    while ((count = read(input, buffer, sizeof(buffer))) > 0)
        CHECK(write(output, buffer, count) == count);
    CHECK(count == 0 && close(input) == 0 && fchmod(output, 04755) == 0 && close(output) == 0);
}

static void mount_policy(const char* target, const char* executable, const char* payload) {
    CHECK(mount(NULL, target, NULL, MS_REMOUNT | MS_NOSUID, NULL) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        ERROR(mount(NULL, target, NULL, MS_REMOUNT, NULL), EPERM);
        ERROR(umount(target), EPERM);
        execl(executable, executable, "--service", "1001", "0", NULL);
        CHECK(0);
    }
    wait_child(child);
    CHECK(mount(NULL, target, NULL, MS_REMOUNT | MS_NOEXEC, NULL) == 0);
    int mapping_fd = open(payload, O_RDONLY);
    CHECK(mapping_fd >= 0);
    errno = 0;
    CHECK(mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, mapping_fd, 0) == MAP_FAILED &&
          errno == EPERM);
    void* mapped = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, mapping_fd, 0);
    CHECK(mapped != MAP_FAILED);
    ERROR(mprotect(mapped, 4096, PROT_READ | PROT_EXEC), EACCES);
    pid_t mapping_child = fork();
    CHECK(mapping_child >= 0);
    if (!mapping_child) {
        ERROR(mprotect(mapped, 4096, PROT_READ | PROT_EXEC), EACCES);
        CHECK(munmap(mapped, 4096) == 0);
        _exit(0);
    }
    wait_child(mapping_child);
    CHECK(munmap(mapped, 4096) == 0 && close(mapping_fd) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        ERROR(execl(executable, executable, NULL), EACCES);
        check_ids(1001, 1001, 1001);
        _exit(0);
    }
    wait_child(child);
    CHECK(mount(NULL, target, NULL, MS_REMOUNT | MS_RDONLY, NULL) == 0);
    int fd = open(payload, O_RDONLY);
    CHECK(fd >= 0 && close(fd) == 0);
    ERROR(open(payload, O_WRONLY), EROFS);
    ERROR(chmod(payload, 0777), EROFS);
    ERROR(chown(payload, 1002, 1002), EROFS);
    ERROR(unlink(payload), EROFS);
    CHECK(mount(NULL, target, NULL, MS_REMOUNT, NULL) == 0);
}

static void mount_tests(void) {
    // Native execution uses a private mount namespace created by the harness.
    CHECK(mkdir("mount", 0755) == 0 && mount("none", "mount", "ramfs", 0, NULL) == 0);
    int input = open("helper", O_RDONLY);
    CHECK(input >= 0);
    copy_binary(input, "mount/helper");
    file("mount/payload", 0, 0, 0644);
    mount_policy("mount", "mount/helper", "mount/payload");
    CHECK(umount("mount") == 0 && rmdir("mount") == 0);
    const char* existing = getenv("CREDENTIAL_POLICY_MOUNT");
    if (existing)
        mount_policy(existing, "./helper", "owner1");
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct stat root, devices;
        CHECK(stat("/", &root) == 0 && stat("/dev", &devices) == 0);
        const char* target = root.st_dev == devices.st_dev ? "/" : "/dev";
        CHECK(mount(NULL, target, NULL, MS_REMOUNT | MS_NODEV, NULL) == 0);
        ERROR(open("/dev/null", O_RDWR), EACCES);
        CHECK(mount(NULL, target, NULL, MS_REMOUNT, NULL) == 0);
        int fd = open("/dev/null", O_RDWR);
        CHECK(fd >= 0 && close(fd) == 0);
        _exit(0);
    }
    wait_child(child);
    puts("CREDENTIAL_MOUNT_PASS nosuid noexec nodev readonly denied_unprivileged_changes");
}

static void exec_tests(void) {
    for (unsigned no_new = 0; no_new < 2; no_new++) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            drop(1001);
            if (no_new)
                CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
            execl("./helper", "./helper", "--service", no_new ? "1001" : "0", no_new ? "0" : "1",
                  NULL);
            CHECK(0);
        }
        wait_child(child);
    }
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        ERROR(execl("./missing", "missing", NULL), ENOENT);
        check_ids(1001, 1001, 1001);
        _exit(0);
    }
    wait_child(child);
    puts("CREDENTIAL_EXEC_PASS setuid no_new_privileges auxiliary_ids failed_exec");
}

static void capability_service(const char* mode) {
    struct capability_header header = {0x20080522, 0};
    struct capability_data data[2];
    CHECK(syscall(SYS_capget, &header, data) == 0);
    unsigned raw = 1u << 13;
    if (!strcmp(mode, "ambient")) {
        check_ids(1001, 1001, 1001);
        CHECK(data[0].effective == raw && data[0].permitted == raw && data[0].inheritable == raw);
        CHECK(!data[1].effective && !data[1].permitted && !data[1].inheritable);
        CHECK(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, 13, 0, 0) == 1);
        ERROR(setuid(0), EPERM);
    } else {
        CHECK(!strcmp(mode, "bounded"));
        check_ids(0, 0, 0);
        CHECK(!(data[0].effective & raw) && !(data[0].permitted & raw));
        CHECK(prctl(PR_CAPBSET_READ, 13, 0, 0, 0) == 0);
        drop(1001);
        ERROR(setuid(0), EPERM);
    }
    CHECK(getauxval(AT_SECURE) == 0);
    printf("CREDENTIAL_CAP_SERVICE_PASS mode=%s\n", mode);
}

static void group_service(gid_t expected, unsigned secure) {
    check_ids(1001, 1001, 1001);
    gid_t real, effective, saved;
    CHECK(getresgid(&real, &effective, &saved) == 0 && real == 1001 && effective == expected &&
          saved == expected);
    CHECK((gid_t)syscall(SYS_setfsgid, -1) == expected);
    CHECK(getauxval(AT_GID) == 1001 && getauxval(AT_EGID) == expected &&
          getauxval(AT_SECURE) == secure);
    CHECK(setresgid(1001, 1001, 1001) == 0);
    ERROR(setgid(1002), EPERM);
    puts("CREDENTIAL_GROUP_SERVICE_PASS setgid_saved_ids irreversible_drop");
}

static void privilege_exec_tests(void) {
    int input = open("helper", O_RDONLY);
    CHECK(input >= 0);
    copy_binary(input, "plain-helper");
    CHECK(chmod("plain-helper", 0755) == 0);
    input = open("helper", O_RDONLY);
    CHECK(input >= 0);
    copy_binary(input, "group-helper");
    CHECK(chown("group-helper", 0, 1002) == 0 && chmod("group-helper", 02755) == 0);
    for (unsigned no_new = 0; no_new < 2; no_new++) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            CHECK(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0);
            drop(1001);
            struct capability_header header = {0x20080522, 0};
            struct capability_data data[2] = {{0, 1u << 13, 1u << 13}, {0, 0, 0}};
            CHECK(syscall(SYS_capset, &header, data) == 0);
            CHECK(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 13, 0, 0) == 0);
            if (no_new)
                CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
            execl("./plain-helper", "./plain-helper", "--cap-service", "ambient", NULL);
            CHECK(0);
        }
        wait_child(child);
        child = fork();
        CHECK(child >= 0);
        if (!child) {
            drop(1001);
            if (no_new)
                CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
            execl("./group-helper", "./group-helper", "--group-service", no_new ? "1001" : "1002",
                  no_new ? "0" : "1", NULL);
            CHECK(0);
        }
        wait_child(child);
    }
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(prctl(PR_CAPBSET_DROP, 13, 0, 0, 0) == 0);
        execl("./plain-helper", "./plain-helper", "--cap-service", "bounded", NULL);
        CHECK(0);
    }
    wait_child(child);
    CHECK(unlink("plain-helper") == 0 && unlink("group-helper") == 0);
    puts("CREDENTIAL_CAP_EXEC_PASS ambient no_new_privileges bounding setgid");
}

static void interpreter_tests(void) {
    int input = open("helper", O_RDONLY);
    CHECK(input >= 0);
    Elf64_Ehdr header;
    CHECK(pread(input, &header, sizeof(header), 0) == sizeof(header));
    Elf64_Phdr interpreter = {0};
    for (unsigned at = 0; at < header.e_phnum; at++) {
        Elf64_Phdr program;
        CHECK(pread(input, &program, sizeof(program), header.e_phoff + at * header.e_phentsize) ==
              sizeof(program));
        if (program.p_type == PT_INTERP)
            interpreter = program;
    }
    if (!interpreter.p_type) {
        CHECK(close(input) == 0);
        puts("CREDENTIAL_INTERPRETER_PASS static_without_interpreter");
        return;
    }
    char path[1024], replacement[1024] = "./deny-loader";
    CHECK(interpreter.p_filesz >= sizeof("./deny-loader") && interpreter.p_filesz <= sizeof(path));
    CHECK(pread(input, path, interpreter.p_filesz, interpreter.p_offset) ==
          (ssize_t)interpreter.p_filesz);
    CHECK(path[interpreter.p_filesz - 1] == 0);
    int loader = open(path, O_RDONLY);
    CHECK(loader >= 0);
    copy_binary(loader, "deny-loader");
    CHECK(chmod("deny-loader", 0644) == 0);
    copy_binary(input, "interpreter-helper");
    CHECK(chmod("interpreter-helper", 0755) == 0);
    int output = open("interpreter-helper", O_WRONLY);
    CHECK(output >= 0 && pwrite(output, replacement, interpreter.p_filesz, interpreter.p_offset) ==
                             (ssize_t)interpreter.p_filesz);
    CHECK(close(output) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        ERROR(execl("./interpreter-helper", "./interpreter-helper", NULL), EACCES);
        ERROR(execl(".", ".", NULL), EACCES);
        check_ids(1001, 1001, 1001);
        _exit(0);
    }
    wait_child(child);
    CHECK(chmod("deny-loader", 0111) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        execl("./interpreter-helper", "./interpreter-helper", "--service", "1001", "0", NULL);
        CHECK(0);
    }
    wait_child(child);
    CHECK(unlink("interpreter-helper") == 0 && unlink("deny-loader") == 0);
    puts("CREDENTIAL_INTERPRETER_PASS denied_execute permitted_execute_only failed_exec_atomic");
}

static void verify_remounted_owner(void) {
    struct stat state;
    CHECK(stat("/tmp/persisted-owner", &state) == 0);
    CHECK(state.st_uid == 65537 && state.st_gid == 131073 && (state.st_mode & 07777) == 0640);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(65537);
        int fd = open("/tmp/persisted-owner", O_RDONLY);
        char bytes[8];
        CHECK(fd >= 0 && read(fd, bytes, sizeof(bytes)) == 8 && !memcmp(bytes, "original", 8));
        CHECK(close(fd) == 0);
        _exit(0);
    }
    wait_child(child);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        drop(1001);
        ERROR(open("/tmp/persisted-owner", O_RDONLY), EACCES);
        _exit(0);
    }
    wait_child(child);
    puts("CREDENTIAL_REMOUNT_PASS decoded_full_width_owner permission_checks");
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "--verify-owner")) {
        CHECK(geteuid() == 0);
        verify_remounted_owner();
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "--service")) {
        service(strtoul(argv[2], NULL, 10), atoi(argv[3]));
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--cap-service")) {
        capability_service(argv[2]);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "--group-service")) {
        group_service(strtoul(argv[2], NULL, 10), strtoul(argv[3], NULL, 10));
        return 0;
    }
    int keep_owner = argc == 2 && !strcmp(argv[1], "--keep-owner");
    CHECK((argc == 1 || keep_owner) && getuid() == 0 && geteuid() == 0);
    int self = open(argv[0], O_RDONLY);
    CHECK(self >= 0);
    identity_tests();
    thread_tests();
    capability_tests();
    ipc_tests();
    signal_tests();
    network_permission_tests();
    char temporary[] = "/tmp/axiom64-credentials-XXXXXX";
    CHECK(mkdtemp(temporary) && chmod(temporary, 01777) == 0 && chdir(temporary) == 0);
    copy_binary(self, "helper");
    permission_tests();
    path_tests();
    unix_tests();
    exec_tests();
    privilege_exec_tests();
    interpreter_tests();
    mount_tests();
    const char* paths[] = {"helper",   "owner1", "owner2",        "group",       "link2",
                           "retained", "zero",   "hidden/secret", "sticky/other"};
    for (unsigned at = 0; at < sizeof(paths) / sizeof(paths[0]); at++)
        CHECK(unlink(paths[at]) == 0);
    CHECK(rmdir("inherited/child") == 0 && rmdir("inherited") == 0 && rmdir("hidden") == 0);
    CHECK(rmdir("sticky") == 0 && chdir("/") == 0 && rmdir(temporary) == 0);
    if (keep_owner) {
        file("/tmp/persisted-owner", 65537, 131073, 0640);
        struct stat persisted;
        CHECK(stat("/tmp/persisted-owner", &persisted) == 0 && persisted.st_uid == 65537 &&
              persisted.st_gid == 131073);
        puts("CREDENTIAL_PERSIST_PASS uid=65537 gid=131073 mode=0640");
    }
    printf("CREDENTIAL_TEST_PASS linkage=%s\n", CREDENTIAL_LINKAGE);
    return 0;
}
