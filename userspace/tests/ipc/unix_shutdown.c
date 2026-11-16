// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "UNIX_SHUTDOWN_FAIL line=%d expression=%s errno=%d\n", __LINE__,       \
                    #value, errno);                                                                \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void exchange(int first, int second) {
    char value;
    CHECK(send(first, "a", 1, MSG_NOSIGNAL) == 1 && recv(second, &value, 1, 0) == 1 &&
          value == 'a');
    CHECK(send(second, "b", 1, MSG_NOSIGNAL) == 1 && recv(first, &value, 1, 0) == 1 &&
          value == 'b');
}

static void listeners(void) {
    unsigned cases = 0;
    for (int how = SHUT_RD; how <= SHUT_RDWR; how++) {
        for (int pending = 0; pending < 2; pending++) {
            for (int pathname = 0; pathname < 2; pathname++) {
                for (int duplicate = 0; duplicate < 2; duplicate++) {
                    struct sockaddr_un address = {.sun_family = AF_UNIX};
                    char name[96];
                    CHECK(snprintf(name, sizeof(name), "/tmp/ax-shutdown-%ld-%u", (long)getpid(),
                                   cases) > 0);
                    if (pathname)
                        strcpy(address.sun_path, name);
                    else
                        strcpy(address.sun_path + 1, name);
                    socklen_t length = offsetof(struct sockaddr_un, sun_path) + strlen(name) + 1;
                    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                    CHECK(listener >= 0);
                    CHECK(!bind(listener, (struct sockaddr*)&address, length) &&
                          !listen(listener, 2));
                    if (duplicate) {
                        int copy = fcntl(listener, F_DUPFD_CLOEXEC, 0);
                        CHECK(copy >= 0 && !close(listener));
                        listener = copy;
                    }
                    int client = -1;
                    if (pending) {
                        client = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                        CHECK(client >= 0 && !connect(client, (struct sockaddr*)&address, length));
                    }
                    CHECK(!shutdown(listener, how) && !shutdown(listener, how));
                    errno = 0;
                    int accepted = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                    if (pending) {
                        CHECK(accepted >= 0);
                        exchange(client, accepted);
                        CHECK(!close(accepted) && !close(client));
                    } else {
                        CHECK(accepted == -1 && errno == EAGAIN);
                    }
                    int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                    CHECK(probe >= 0);
                    errno = 0;
                    int result = connect(probe, (struct sockaddr*)&address, length);
                    if (how == SHUT_WR) {
                        CHECK(!result);
                        accepted = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                        CHECK(accepted >= 0);
                        exchange(probe, accepted);
                        CHECK(!close(accepted));
                    } else {
                        CHECK(result == -1 && errno == ECONNREFUSED);
                    }
                    CHECK(!close(probe) && !close(listener));
                    if (pathname)
                        CHECK(!unlink(name));
                    cases++;
                }
            }
        }
    }
    CHECK(cases == 24);
    puts("UNIX_SHUTDOWN_LISTENER_PASS cases=24 names=abstract,path duplicate repeated pending "
         "exchange");
}

int main(int argc, char** argv) {
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")));
    if (argc == 2) {
        CHECK(!geteuid() && !setgroups(0, NULL) && !setresgid(65534, 65534, 65534) &&
              !setresuid(65534, 65534, 65534));
    }
    printf("UNIX_SHUTDOWN_IDENTITY uid=%u euid=%u gid=%u egid=%u groups=%d\n", getuid(), geteuid(),
           getgid(), getegid(), getgroups(0, NULL));
    listeners();
    puts("UNIX_SHUTDOWN_PASS groups=1");
    return 0;
}
