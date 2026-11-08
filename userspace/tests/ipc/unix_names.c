// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "UNIX_NAMES_FAIL line=%d expression=%s errno=%d\n", __LINE__, #value,  \
                    errno);                                                                        \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static int endpoint(void) {
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    return fd;
}

static void name(int fd, const unsigned char* expected, socklen_t actual, int peer) {
    for (socklen_t capacity = 0; capacity <= actual + 1; capacity++) {
        unsigned char output[113];
        memset(output, 0xa5, sizeof(output));
        socklen_t length = capacity;
        int result = peer ? getpeername(fd, (struct sockaddr*)output, &length)
                          : getsockname(fd, (struct sockaddr*)output, &length);
        CHECK(!result && length == actual);
        size_t copied = capacity < actual ? capacity : actual;
        CHECK(!memcmp(output, expected, copied));
        for (size_t n = copied; n < sizeof(output); n++)
            CHECK(output[n] == 0xa5);
    }
    socklen_t length = 0;
    CHECK(!(peer ? getpeername(fd, NULL, &length) : getsockname(fd, NULL, &length)) &&
          length == actual);
}

static socklen_t abstract(struct sockaddr_un* address, char tag) {
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    CHECK(snprintf(address->sun_path + 1, sizeof(address->sun_path) - 1, "ax-%ld-%c",
                   (long)getpid(), tag) > 0);
    // Preserve an embedded zero followed by nonzero and trailing zero bytes.
    size_t length = strlen(address->sun_path + 1) + 2;
    address->sun_path[length++] = 'Q';
    address->sun_path[length++] = 0;
    return offsetof(struct sockaddr_un, sun_path) + length;
}

static void abstract_bindings(void) {
    int first = endpoint(), second = endpoint();
    struct sockaddr_un address;
    socklen_t length = abstract(&address, 'a');
    CHECK(!bind(first, (struct sockaddr*)&address, length));
    name(first, (unsigned char*)&address, length, 0);
    CHECK(bind(second, (struct sockaddr*)&address, length) == -1 && errno == EADDRINUSE);
    CHECK(!bind(second, (struct sockaddr*)&address, length - 1));
    name(second, (unsigned char*)&address, length - 1, 0);
    CHECK(!close(first) && !close(second));
    first = endpoint();
    CHECK(!bind(first, (struct sockaddr*)&address, length) && !close(first));
    puts("UNIX_NAMES_ABSTRACT_PASS exact_length embedded_zero trailing_zero release_rebind");
}

static void automatic_bindings(void) {
    int fd = endpoint(), duplicate = endpoint();
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    CHECK(!bind(fd, (struct sockaddr*)&address, sizeof(sa_family_t)));
    socklen_t length = sizeof(address);
    CHECK(!getsockname(fd, (struct sockaddr*)&address, &length) && length == 8 &&
          address.sun_family == AF_UNIX && !address.sun_path[0]);
    for (unsigned n = 1; n <= 5; n++)
        CHECK((address.sun_path[n] >= '0' && address.sun_path[n] <= '9') ||
              (address.sun_path[n] >= 'a' && address.sun_path[n] <= 'f'));
    name(fd, (unsigned char*)&address, length, 0);
    CHECK(bind(duplicate, (struct sockaddr*)&address, length) == -1 && errno == EADDRINUSE);
    CHECK(!close(fd));
    CHECK(!bind(duplicate, (struct sockaddr*)&address, length) && !close(duplicate));
    puts("UNIX_NAMES_AUTOMATIC_PASS abstract_hex unique_namespace release_rebind");
}

static void filesystem_bindings(void) {
    char directory[] = "/tmp/axiom-names-XXXXXX";
    CHECK(mkdtemp(directory));
    struct sockaddr_un address;
    memset(&address, 'q', sizeof(address));
    address.sun_family = AF_UNIX;
    int count = snprintf(address.sun_path, sizeof(address.sun_path), "%s/peer", directory);
    CHECK(count > 0 && (size_t)count + 1 < sizeof(address.sun_path));
    int fd = endpoint(), duplicate = endpoint();
    CHECK(!bind(fd, (struct sockaddr*)&address, sizeof(address)));
    socklen_t length = offsetof(struct sockaddr_un, sun_path) + count + 1;
    name(fd, (unsigned char*)&address, length, 0);
    CHECK(!close(fd));
    CHECK(bind(duplicate, (struct sockaddr*)&address, length) == -1 && errno == EADDRINUSE);
    CHECK(!unlink(address.sun_path));
    CHECK(!bind(duplicate, (struct sockaddr*)&address, length));
    CHECK(!close(duplicate) && !unlink(address.sun_path));
    memset(&address, 'x', sizeof(address));
    address.sun_family = AF_UNIX;
    size_t prefix = strlen(directory);
    CHECK(prefix + 1 < sizeof(address.sun_path));
    memcpy(address.sun_path, directory, prefix);
    address.sun_path[prefix] = '/';
    char path[109];
    memcpy(path, address.sun_path, 108);
    path[108] = 0;
    fd = endpoint();
    CHECK(!bind(fd, (struct sockaddr*)&address, sizeof(address)));
    unsigned char full[111];
    memcpy(full, &address, sizeof(address));
    full[110] = 0;
    name(fd, full, sizeof(full), 0);
    CHECK(!close(fd) && !unlink(path) && !rmdir(directory));
    puts("UNIX_NAMES_FILESYSTEM_PASS terminator trailing_bytes persistent_node full_108_path");
}

static void source_lifetime(void) {
    int pair[2];
    CHECK(!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, pair));
    struct sockaddr_un source;
    socklen_t length = abstract(&source, 's');
    CHECK(!bind(pair[0], (struct sockaddr*)&source, length));
    name(pair[1], (unsigned char*)&source, length, 1);
    CHECK(send(pair[0], "named", 5, 0) == 5 && send(pair[0], "peek", 4, 0) == 4 &&
          send(pair[0], "consume", 7, 0) == 7 && !send(pair[0], "", 0, 0) && !close(pair[0]));
    int replacement = endpoint();
    struct sockaddr_un other;
    socklen_t other_length = abstract(&other, 'r');
    CHECK(!bind(replacement, (struct sockaddr*)&other, other_length));
    for (socklen_t capacity = 0; capacity <= length + 1; capacity++) {
        char bytes[8] = {0};
        unsigned char address[113];
        memset(address, 0xa5, sizeof(address));
        struct iovec vector = {bytes, sizeof(bytes)};
        struct msghdr message = {
            .msg_name = address, .msg_namelen = capacity, .msg_iov = &vector, .msg_iovlen = 1};
        CHECK(recvmsg(pair[1], &message, MSG_PEEK) == 5 && !message.msg_flags &&
              message.msg_namelen == length && !message.msg_controllen &&
              !memcmp(bytes, "named", 5));
        size_t copied = capacity < length ? capacity : length;
        CHECK(!memcmp(address, &source, copied));
        for (size_t n = copied; n < sizeof(address); n++)
            CHECK(address[n] == 0xa5);
    }
    char byte[8];
    unsigned char address[113];
    socklen_t capacity = sizeof(address);
    CHECK(recvfrom(pair[1], byte, sizeof(byte), 0, (struct sockaddr*)address, &capacity) == 5 &&
          capacity == length && !memcmp(address, &source, length) && !memcmp(byte, "named", 5));
    void* inaccessible = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(inaccessible != MAP_FAILED);
    struct iovec vector = {byte, sizeof(byte)};
    struct msghdr message = {
        .msg_name = inaccessible, .msg_namelen = 110, .msg_iov = &vector, .msg_iovlen = 1};
    CHECK(recvmsg(pair[1], &message, MSG_PEEK) == -1 && errno == EFAULT &&
          !memcmp(byte, "peek", 4));
    CHECK(recvmsg(pair[1], &message, 0) == -1 && errno == EFAULT && !memcmp(byte, "peek", 4));
    CHECK(!munmap(inaccessible, 4096));
    capacity = sizeof(address);
    CHECK(recvfrom(pair[1], byte, sizeof(byte), 0, (struct sockaddr*)address, &capacity) == 7 &&
          capacity == length && !memcmp(address, &source, length) && !memcmp(byte, "consume", 7));
    capacity = sizeof(address);
    CHECK(!recvfrom(pair[1], byte, sizeof(byte), 0, (struct sockaddr*)address, &capacity) &&
          capacity == length && !memcmp(address, &source, length));
    CHECK(!close(pair[1]) && !close(replacement));
    puts("UNIX_NAMES_SOURCE_PASS copied_name peek truncated_output sender_close slot_reuse "
         "source_fault_consume empty_record");
}

static void invalid_addresses(void) {
    int fd = endpoint();
    unsigned char address[111] = {AF_UNIX, 0};
    CHECK(bind(fd, (struct sockaddr*)address, 1) == -1 && errno == EINVAL);
    CHECK(bind(fd, (struct sockaddr*)address, sizeof(address)) == -1 && errno == EINVAL);
    address[0] = AF_INET;
    CHECK(bind(fd, (struct sockaddr*)address, 3) == -1 && errno == EINVAL);
    address[0] = AF_UNIX;
    CHECK(bind(fd, NULL, 3) == -1 && errno == EFAULT);
    socklen_t size = (socklen_t)-1;
    CHECK(getsockname(fd, (struct sockaddr*)address, &size) == -1 && errno == EINVAL);
    size = sizeof(address);
    CHECK(getsockname(fd, NULL, &size) == -1 && errno == EFAULT);
    CHECK(getsockname(fd, (struct sockaddr*)address, NULL) == -1 && errno == EFAULT);
    size = 0;
    uintptr_t ignored = UINTPTR_MAX - (uintptr_t)getpid();
    CHECK(!getsockname(fd, (struct sockaddr*)ignored, &size) && size == 2);
    CHECK(!close(fd));
    puts("UNIX_NAMES_INVALID_PASS length family input_fault output_fault negative_capacity");
}

int main(int argc, char** argv) {
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")));
    if (argc == 2) {
        CHECK(!geteuid() && !setgroups(0, NULL));
        CHECK(!setresgid(65534, 65534, 65534) && !setresuid(65534, 65534, 65534));
    }
    printf("UNIX_NAMES_IDENTITY uid=%u euid=%u gid=%u egid=%u groups=%d\n", getuid(), geteuid(),
           getgid(), getegid(), getgroups(0, NULL));
    abstract_bindings();
    automatic_bindings();
    filesystem_bindings();
    source_lifetime();
    invalid_addresses();
    puts("UNIX_NAMES_PASS groups=5");
}
