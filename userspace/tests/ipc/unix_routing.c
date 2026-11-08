// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stddef.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "UNIX_ROUTING_FAIL line=%d expression=%s errno=%d\n", __LINE__,        \
                    #value, errno);                                                                \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

struct named {
    int fd;
    struct sockaddr_un address;
    socklen_t length;
};

static struct named endpoint(char tag) {
    struct named value = {.fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0),
                          .address = {.sun_family = AF_UNIX}};
    CHECK(value.fd >= 0);
    int n = snprintf(value.address.sun_path + 1, sizeof(value.address.sun_path) - 1,
                     "ax-route-%ld-%c", (long)getpid(), tag);
    CHECK(n > 0 && n < 100);
    value.length = offsetof(struct sockaddr_un, sun_path) + 1 + n;
    CHECK(!bind(value.fd, (struct sockaddr*)&value.address, value.length));
    return value;
}

static void connect_to(int fd, const struct named* peer) {
    CHECK(!connect(fd, (const struct sockaddr*)&peer->address, peer->length));
}

static void peer_is(int fd, const struct named* peer) {
    struct sockaddr_un actual;
    socklen_t length = sizeof(actual);
    CHECK(!getpeername(fd, (struct sockaddr*)&actual, &length) && length == peer->length &&
          !memcmp(&actual, &peer->address, length));
}

static ssize_t send_to(int fd, const char* data, const struct named* peer) {
    return sendto(fd, data, strlen(data), 0, (const struct sockaddr*)&peer->address, peer->length);
}

static void receive(int fd, const char* expected, const struct named* sender) {
    unsigned char bytes[64];
    struct sockaddr_un source;
    memset(&source, 0xa5, sizeof(source));
    socklen_t size = sizeof(source);
    CHECK(recvfrom(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&source, &size) ==
              (ssize_t)strlen(expected) &&
          !memcmp(bytes, expected, strlen(expected)));
    CHECK(sender ? size == sender->length && !memcmp(&source, &sender->address, size)
                 : !size && ((unsigned char*)&source)[0] == 0xa5);
}

static void empty(int fd) {
    char byte;
    CHECK(recv(fd, &byte, 1, 0) == -1 && errno == EAGAIN);
}

static void named_exchange(void) {
    struct named receiver = endpoint('r'), alternate = endpoint('t');
    int client = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    CHECK(client >= 0 && send_to(client, "unnamed", &receiver) == 7);
    receive(receiver.fd, "unnamed", NULL);
    CHECK(!close(client));
    struct named sender = endpoint('s');
    connect_to(sender.fd, &receiver);
    peer_is(sender.fd, &receiver);
    CHECK(write(sender.fd, "default", 7) == 7);
    receive(receiver.fd, "default", &sender);
    struct iovec vectors[] = {{"one", 3}, {"two", 3}};
    struct msghdr message = {.msg_name = &alternate.address,
                             .msg_namelen = alternate.length,
                             .msg_iov = vectors,
                             .msg_iovlen = 2};
    CHECK(sendmsg(sender.fd, &message, 0) == 6);
    receive(alternate.fd, "onetwo", &sender);
    empty(receiver.fd);
    peer_is(sender.fd, &receiver);
    CHECK(send(sender.fd, "again", 5, 0) == 5);
    receive(receiver.fd, "again", &sender);
    struct ucred credential;
    socklen_t length = sizeof(credential);
    CHECK(!getsockopt(sender.fd, SOL_SOCKET, SO_PEERCRED, &credential, &length) &&
          length == sizeof(credential) && !credential.pid && credential.uid == (uid_t)-1 &&
          credential.gid == (gid_t)-1);
    CHECK(!close(sender.fd) && !close(receiver.fd) && !close(alternate.fd));
    puts("UNIX_ROUTING_EXCHANGE_PASS named_vectors unnamed_source connected_override default_peer");
}

static void reconnect(void) {
    struct named a = endpoint('a'), b = endpoint('b'), c = endpoint('c');
    connect_to(a.fd, &b);
    connect_to(b.fd, &a);
    CHECK(send(a.fd, "lost", 4, 0) == 4);
    connect_to(b.fd, &c);
    empty(b.fd);
    struct pollfd event = {.fd = a.fd, .events = POLLIN | POLLOUT};
    CHECK(poll(&event, 1, 0) == 1 && (event.revents & POLLERR));
    int error = 0;
    socklen_t size = sizeof(error);
    CHECK(!getsockopt(a.fd, SOL_SOCKET, SO_ERROR, &error, &size) && error == ECONNRESET);
    CHECK(!getsockopt(a.fd, SOL_SOCKET, SO_ERROR, &error, &size) && !error);
    CHECK(send(a.fd, "old", 3, 0) == -1 && errno == EPERM);
    CHECK(send_to(c.fd, "new", &b) == 3);
    receive(b.fd, "new", &c);
    struct sockaddr unspecified = {.sa_family = AF_UNSPEC};
    CHECK(!connect(b.fd, &unspecified, sizeof(sa_family_t)));
    CHECK(send(b.fd, "x", 1, 0) == -1 && errno == ENOTCONN);
    peer_is(a.fd, &b);
    CHECK(send(a.fd, "allowed", 7, 0) == 7);
    // A first connection does not discard an unconnected receiver's existing queue.
    connect_to(b.fd, &c);
    receive(b.fd, "allowed", &a);
    CHECK(!close(a.fd) && !close(b.fd) && !close(c.fd));
    puts("UNIX_ROUTING_RECONNECT_PASS filter queue_retirement reset_error disconnect "
         "retained_queue");
}

static void close_reuse(void) {
    struct named first = endpoint('f'), second = endpoint('g'), receiver = endpoint('h');
    connect_to(first.fd, &receiver);
    connect_to(second.fd, &receiver);
    CHECK(!close(first.fd));
    CHECK(send(second.fd, "live", 4, 0) == 4);
    receive(receiver.fd, "live", &second);
    CHECK(!close(receiver.fd));
    peer_is(second.fd, &receiver);
    int replacement = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    CHECK(replacement >= 0 &&
          !bind(replacement, (struct sockaddr*)&receiver.address, receiver.length));
    CHECK(send(second.fd, "old", 3, 0) == -1 && errno == ECONNREFUSED);
    CHECK(send(second.fd, "none", 4, 0) == -1 && errno == ENOTCONN);
    CHECK(send_to(second.fd, "named", &receiver) == 5);
    receive(replacement, "named", &second);
    connect_to(second.fd, &receiver);
    CHECK(send(second.fd, "rebound", 7, 0) == 7);
    receive(replacement, "rebound", &second);
    CHECK(!close(second.fd) && !close(replacement));
    struct named mutual = endpoint('v'), closed = endpoint('w');
    connect_to(mutual.fd, &closed);
    connect_to(closed.fd, &mutual);
    CHECK(send(mutual.fd, "lost", 4, 0) == 4 && !close(closed.fd));
    peer_is(mutual.fd, &closed);
    CHECK(send(mutual.fd, "closed", 6, 0) == -1 && errno == ECONNREFUSED);
    CHECK(send(mutual.fd, "none", 4, 0) == -1 && errno == ENOTCONN);
    CHECK(!close(mutual.fd));
    puts("UNIX_ROUTING_CLOSE_PASS multiple_clients retained_peer_name generation_reuse reconnect "
         "mutual_unread_close");
}

static void filesystem(void) {
    char directory[] = "/tmp/axiom-route-XXXXXX", path[108], alias[108], regular[108];
    CHECK(mkdtemp(directory));
    CHECK(snprintf(path, sizeof(path), "%s/socket", directory) > 0);
    CHECK(snprintf(alias, sizeof(alias), "%s/alias", directory) > 0);
    CHECK(snprintf(regular, sizeof(regular), "%s/regular", directory) > 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, strlen(path) + 1);
    socklen_t size = offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;
    int receiver = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct named sender = endpoint('p');
    CHECK(receiver >= 0 && !bind(receiver, (struct sockaddr*)&address, size));
    CHECK(!link(path, alias) && !unlink(path));
    CHECK(sendto(sender.fd, "missing", 7, 0, (struct sockaddr*)&address, size) == -1 &&
          errno == ENOENT);
    memcpy(address.sun_path, alias, strlen(alias) + 1);
    size = offsetof(struct sockaddr_un, sun_path) + strlen(alias) + 1;
    CHECK(sendto(sender.fd, "inode", 5, 0, (struct sockaddr*)&address, size) == 5);
    receive(receiver, "inode", &sender);
    CHECK(!chmod(alias, 0));
    if (geteuid())
        CHECK(sendto(sender.fd, "denied", 6, 0, (struct sockaddr*)&address, size) == -1 &&
              errno == EACCES);
    CHECK(!chmod(alias, 0600) && !close(receiver));
    CHECK(sendto(sender.fd, "stale", 5, 0, (struct sockaddr*)&address, size) == -1 &&
          errno == ECONNREFUSED);
    int fd = open(regular, O_CREAT | O_WRONLY | O_EXCL, 0600);
    CHECK(fd >= 0 && !close(fd));
    memcpy(address.sun_path, regular, strlen(regular) + 1);
    size = offsetof(struct sockaddr_un, sun_path) + strlen(regular) + 1;
    CHECK(sendto(sender.fd, "file", 4, 0, (struct sockaddr*)&address, size) == -1 &&
          errno == ECONNREFUSED);
    CHECK(!close(sender.fd) && !unlink(alias) && !unlink(regular) && !rmdir(directory));
    puts("UNIX_ROUTING_FILESYSTEM_PASS inode_alias missing_path permissions stale_node "
         "regular_file");
}

static void backlog(void) {
    struct named sender = endpoint('q'), receiver = endpoint('u');
    connect_to(sender.fd, &receiver);
    unsigned count = 0;
    while (!send(sender.fd, "", 0, MSG_DONTWAIT))
        CHECK(++count < 1000);
    CHECK(errno == EAGAIN && count == 11);
    struct pollfd event = {.fd = sender.fd, .events = POLLOUT};
    CHECK(!poll(&event, 1, 0));
    char byte;
    CHECK(!recv(receiver.fd, &byte, 1, 0));
    CHECK(poll(&event, 1, 0) == 1 && event.revents == POLLOUT);
    CHECK(!send(sender.fd, "", 0, 0));
    CHECK(!shutdown(receiver.fd, SHUT_RD));
    CHECK(send(sender.fd, "x", 1, 0) == -1 && errno == EPIPE);
    CHECK(!close(sender.fd) && !close(receiver.fd));
    puts("UNIX_ROUTING_BACKLOG_PASS default_limit readiness receive_shutdown queued_records");
}

int main(int argc, char** argv) {
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")));
    if (argc == 2) {
        CHECK(!geteuid() && !setgroups(0, NULL));
        CHECK(!setresgid(65534, 65534, 65534) && !setresuid(65534, 65534, 65534));
    }
    printf("UNIX_ROUTING_IDENTITY uid=%u euid=%u gid=%u egid=%u groups=%d\n", getuid(), geteuid(),
           getgid(), getegid(), getgroups(0, NULL));
    named_exchange();
    reconnect();
    close_reuse();
    filesystem();
    backlog();
    puts("UNIX_ROUTING_PASS groups=5");
}
