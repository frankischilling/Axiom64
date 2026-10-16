// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "transaction.h"
#include "home.h"
#include "protected.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

enum { header_size = 106, record_limit = header_size + 4095 + 4 };

static const char stage_name[] = "home-prepare", intent_name[] = "home-intent";
static const char intent_attribute[] = "trusted.axiom64.intent";
static const char generation_attribute[] = "trusted.axiom64.generation";

struct account_transaction {
    int directory, fd, attempted, recovered;
    char before[35], after[35];
    char* path;
    uid_t uid;
    gid_t gid;
    struct account_home_key key;
    struct account_home* home;
};

static int failed(int error) {
    errno = error;
    return -1;
}

static int generation_valid(const char* value, int empty) {
    size_t size = value ? strnlen(value, 35) : 35;
    if (!size && empty)
        return 1;
    if (size != 34 || value[0] != 'g' || value[1] != '-')
        return 0;
    for (unsigned i = 2; i < 34; i++)
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    return 1;
}

static uint32_t checksum(const unsigned char* data, size_t size) {
    uint32_t value = UINT32_MAX;
    for (size_t i = 0; i < size; i++) {
        value ^= data[i];
        for (unsigned bit = 0; bit < 8; bit++)
            value = (value >> 1) ^ (0xedb88320u & (0u - (value & 1u)));
    }
    return ~value;
}

static uint32_t read32(const unsigned char* data) {
    return (uint32_t)data[0] | (uint32_t)data[1] << 8 | (uint32_t)data[2] << 16 |
           (uint32_t)data[3] << 24;
}

static void write32(unsigned char* data, uint32_t value) {
    for (unsigned i = 0; i < 4; i++)
        data[i] = (unsigned char)(value >> (8 * i));
}

static int transfer(int fd, void* bytes, size_t size, int writing) {
    for (size_t offset = 0; offset < size;) {
        ssize_t count = writing ? write(fd, (unsigned char*)bytes + offset, size - offset)
                                : read(fd, (unsigned char*)bytes + offset, size - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return failed(count < 0 ? errno : EIO);
        offset += (size_t)count;
    }
    return 0;
}

static int claimed(int fd, const char* attribute, const struct account_home_key* expected) {
    struct account_home_key actual;
    ssize_t size = fgetxattr(fd, attribute, actual.bytes, sizeof(actual.bytes));
    if (size < 0)
        return errno == ENODATA || errno == ERANGE ? failed(ESTALE) : -1;
    if ((size_t)size != sizeof(actual.bytes))
        return failed(ESTALE);
    unsigned char nonzero = 0;
    for (unsigned i = 0; i < sizeof(actual.bytes); i++)
        nonzero |= actual.bytes[i];
    return nonzero && (!expected || !memcmp(&actual, expected, sizeof(actual))) ? 0
                                                                                : failed(ESTALE);
}

static int same_entry(int directory, const char* name, int fd) {
    struct stat held, entry;
    if (fstat(fd, &held) < 0 || fstatat(directory, name, &entry, AT_SYMLINK_NOFOLLOW) < 0)
        return -1;
    return held.st_dev == entry.st_dev && held.st_ino == entry.st_ino ? 0 : failed(ESTALE);
}

static int remove_stage(int directory) {
    struct stat value;
    if (fstatat(directory, stage_name, &value, AT_SYMLINK_NOFOLLOW) < 0)
        return errno == ENOENT ? 0 : -1;
    int fd = account_file_open(directory, stage_name, O_RDONLY, 0600, 0);
    if (fd < 0)
        return -1;
    int error = fstat(fd, &value) < 0 ? errno : 0;
    if (!error && (value.st_size < 0 || value.st_size > record_limit))
        error = EUCLEAN;
    // Only this reserved, attested staging file is reclaimable. Staging never
    // starts home creation; the synchronized published intent is authoritative.
    if (!error &&
        (claimed(fd, intent_attribute, NULL) < 0 || same_entry(directory, stage_name, fd) < 0 ||
         unlinkat(directory, stage_name, 0) < 0 || fsync(directory) < 0))
        error = errno;
    if (close(fd) < 0 && !error)
        error = errno;
    return error ? failed(error) : 0;
}

int account_transaction_published(const struct account_transaction* transaction,
                                  const char* current) {
    if (!transaction || !generation_valid(current, 1))
        return failed(EINVAL);
    if (!strcmp(current, transaction->after))
        return 1;
    return !strcmp(current, transaction->before) ? 0 : failed(EUCLEAN);
}

const char* account_transaction_generation(const struct account_transaction* transaction) {
    return transaction ? transaction->after : NULL;
}

int account_transaction_mark_generation(const struct account_transaction* transaction,
                                        int directory) {
    if (fsetxattr(directory, generation_attribute, transaction->key.bytes,
                  sizeof(transaction->key.bytes), XATTR_CREATE) < 0 ||
        fsync(directory) < 0 || fsync(transaction->directory) < 0)
        return -1;
    return 0;
}

int account_transaction_check_generation(const struct account_transaction* transaction,
                                         int directory) {
    return claimed(directory, generation_attribute, &transaction->key);
}

void account_transaction_close(struct account_transaction* transaction) {
    if (!transaction)
        return;
    if (transaction->home)
        account_home_finish(transaction->home, 1);
    if (transaction->fd >= 0)
        close(transaction->fd);
    free(transaction->path);
    explicit_bzero(transaction, sizeof(*transaction));
    free(transaction);
}

int account_transaction_prepare(int directory, const char* current, const char* generation,
                                const char* path, uid_t uid, gid_t gid,
                                struct account_transaction** output) {
    if (!output || !generation_valid(current, 1) || !generation_valid(generation, 0) ||
        !strcmp(current, generation) || uid == (uid_t)-1 || gid == (gid_t)-1)
        return failed(EINVAL);
    *output = NULL;
    if (account_home_path_valid(path) < 0)
        return -1;
    struct account_transaction* transaction = calloc(1, sizeof(*transaction));
    if (!transaction)
        return -1;
    transaction->directory = directory;
    transaction->fd = -1;
    transaction->uid = uid;
    transaction->gid = gid;
    memcpy(transaction->before, current, strlen(current) + 1);
    memcpy(transaction->after, generation, 35);
    transaction->path = strdup(path);
    if (!transaction->path || account_home_key_new(&transaction->key) < 0) {
        int error = errno;
        account_transaction_close(transaction);
        return failed(error);
    }
    *output = transaction;
    struct stat value;
    if (fstatat(directory, intent_name, &value, AT_SYMLINK_NOFOLLOW) == 0)
        return failed(EALREADY);
    if (errno != ENOENT)
        return -1;
    transaction->fd =
        openat(directory, stage_name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (transaction->fd < 0) {
        transaction->attempted = errno != EEXIST;
        return -1;
    }
    transaction->attempted = 1;
    if (fstat(transaction->fd, &value) < 0)
        return -1;
    if (!S_ISREG(value.st_mode) || value.st_uid || value.st_gid || value.st_nlink != 1)
        return failed(EACCES);
    if (fchmod(transaction->fd, 0600) < 0 ||
        fsetxattr(transaction->fd, intent_attribute, transaction->key.bytes,
                  sizeof(transaction->key.bytes), XATTR_CREATE) < 0)
        return -1;
    size_t length = strlen(path), size = header_size + length + 4;
    unsigned char data[record_limit] = {0};
    memcpy(data, "A64HOM01", 8);
    memcpy(data + 8, transaction->before, 35);
    memcpy(data + 43, transaction->after, 35);
    memcpy(data + 78, transaction->key.bytes, 16);
    write32(data + 94, uid);
    write32(data + 98, gid);
    write32(data + 102, (uint32_t)length);
    memcpy(data + header_size, path, length);
    write32(data + header_size + length, checksum(data, header_size + length));
    if (transfer(transaction->fd, data, size, 1) < 0 || fsync(transaction->fd) < 0 ||
        fsync(directory) < 0 || same_entry(directory, stage_name, transaction->fd) < 0 ||
        syscall(SYS_renameat2, directory, stage_name, directory, intent_name, 1u) < 0 ||
        fsync(directory) < 0)
        return -1;
    return account_home_create_key(path, uid, gid, &transaction->key, &transaction->home);
}

int account_transaction_recover(int directory, const char* current,
                                struct account_transaction** output) {
    if (!output || !generation_valid(current, 1))
        return failed(EINVAL);
    *output = NULL;
    struct stat value;
    if (fstatat(directory, intent_name, &value, AT_SYMLINK_NOFOLLOW) < 0)
        return errno == ENOENT ? remove_stage(directory) : -1;
    struct account_transaction* transaction = calloc(1, sizeof(*transaction));
    if (!transaction)
        return -1;
    transaction->directory = directory;
    transaction->fd = account_file_open(directory, intent_name, O_RDONLY, 0600, 0);
    int error = transaction->fd < 0 ? errno : 0;
    if (!error && fstat(transaction->fd, &value) < 0)
        error = errno;
    if (!error && (value.st_size < header_size + 6 || value.st_size > record_limit))
        error = EUCLEAN;
    unsigned char data[record_limit];
    if (!error && transfer(transaction->fd, data, (size_t)value.st_size, 0) < 0)
        error = errno;
    size_t length = error ? 0 : read32(data + 102);
    if (!error &&
        (length < 2 || length > 4095 || (size_t)value.st_size != header_size + length + 4 ||
         memcmp(data, "A64HOM01", 8) || memchr(data + header_size, 0, length) ||
         read32(data + header_size + length) != checksum(data, header_size + length)))
        error = EUCLEAN;
    if (!error) {
        memcpy(transaction->before, data + 8, 35);
        memcpy(transaction->after, data + 43, 35);
        memcpy(transaction->key.bytes, data + 78, 16);
        transaction->uid = read32(data + 94);
        transaction->gid = read32(data + 98);
        unsigned char empty[35] = {0};
        if (!generation_valid(transaction->before, 1) || !generation_valid(transaction->after, 0) ||
            (!*transaction->before && memcmp(transaction->before, empty, sizeof(empty))) ||
            !strcmp(transaction->before, transaction->after) || transaction->uid == (uid_t)-1 ||
            transaction->gid == (gid_t)-1)
            error = EUCLEAN;
        transaction->path = malloc(length + 1);
        if (!transaction->path)
            error = ENOMEM;
        else {
            memcpy(transaction->path, data + header_size, length);
            transaction->path[length] = 0;
            if (account_home_path_valid(transaction->path) < 0)
                error = EUCLEAN;
        }
    }
    int published = error ? -1 : account_transaction_published(transaction, current);
    if (!error && published < 0)
        error = errno;
    if (!error && (claimed(transaction->fd, intent_attribute, &transaction->key) < 0 ||
                   same_entry(directory, intent_name, transaction->fd) < 0))
        error = errno;
    if (error) {
        account_transaction_close(transaction);
        return failed(error);
    }
    transaction->recovered = 1;
    *output = transaction;
    return account_home_recover(transaction->path, &transaction->key, published);
}

int account_transaction_finish(struct account_transaction* transaction, const char* current) {
    if (!transaction)
        return 0;
    int published = account_transaction_published(transaction, current);
    int error = published < 0 ? errno : 0;
    if (!error && transaction->home) {
        if (account_home_finish(transaction->home, published) < 0)
            error = errno;
        transaction->home = NULL;
    } else if (!error && (transaction->recovered || published) &&
               account_home_recover(transaction->path, &transaction->key, published) < 0)
        error = errno;
    if (!error && transaction->fd < 0 && transaction->attempted) {
        struct stat value;
        if (fstatat(transaction->directory, stage_name, &value, AT_SYMLINK_NOFOLLOW) == 0)
            error = EIO;
        else if (errno != ENOENT)
            error = errno;
    }
    if (!error && transaction->fd >= 0 && fsync(transaction->directory) < 0)
        error = errno;
    const char* names[] = {stage_name, intent_name};
    for (unsigned i = 0; !error && transaction->fd >= 0 && i < 2; i++) {
        struct stat value;
        if (fstatat(transaction->directory, names[i], &value, AT_SYMLINK_NOFOLLOW) < 0) {
            if (errno != ENOENT)
                error = errno;
        } else if (same_entry(transaction->directory, names[i], transaction->fd) < 0 ||
                   unlinkat(transaction->directory, names[i], 0) < 0)
            error = errno;
    }
    if (!error && transaction->fd >= 0 && fsync(transaction->directory) < 0)
        error = errno;
    if (transaction->fd >= 0 && close(transaction->fd) < 0 && !error)
        error = errno;
    transaction->fd = -1;
    account_transaction_close(transaction);
    return error ? failed(error) : 0;
}
