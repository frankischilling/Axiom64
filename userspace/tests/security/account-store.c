// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/store.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "ACCOUNT_STORE_FAIL line=%d errno=%d\n", __LINE__, errno);             \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static struct account_store* begin(const char* path, int provision) {
    struct account_store* result = NULL;
    CHECK(account_store_begin(path, provision, &result) == 0 && result);
    return result;
}

static void contents(unsigned epoch, char data[ACCOUNT_FILE_COUNT][256],
                     struct account_content files[ACCOUNT_FILE_COUNT]) {
    CHECK(snprintf(data[0], 256,
                   "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:epoch%u:/home/alice:/bin/sh\n",
                   epoch) < 256);
    CHECK(snprintf(data[1], 256, "root:x:0:\nusers:x:1000:alice\nepoch%u:x:1001:\n", epoch) < 256);
    CHECK(snprintf(data[2], 256, "root:!:1:0:99999:7:::\nalice:!:%u:0:99999:7:::\n", epoch) < 256);
    for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++)
        files[i] = (struct account_content){data[i], strlen(data[i])};
}

static unsigned epoch(const struct account_store* store) {
    const struct account_content* files = account_store_snapshot(store);
    CHECK(files);
    const char* start = strstr(files[0].data, ":epoch");
    unsigned result = 0;
    CHECK(start && sscanf(start, ":epoch%u:", &result) == 1);
    char data[ACCOUNT_FILE_COUNT][256];
    struct account_content expected[ACCOUNT_FILE_COUNT];
    contents(result, data, expected);
    for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++)
        CHECK(files[i].size == expected[i].size &&
              !memcmp(files[i].data, expected[i].data, expected[i].size));
    return result;
}

static void commit(struct account_store* store, unsigned next) {
    char data[ACCOUNT_FILE_COUNT][256];
    struct account_content files[ACCOUNT_FILE_COUNT];
    contents(next, data, files);
    int published = 0;
    CHECK(account_store_commit(store, files, &published) == 0 && published == 1);
    published = 7;
    CHECK(account_store_commit(store, files, &published) < 0 && errno == EALREADY &&
          published == 0);
    explicit_bzero(data, sizeof(data));
}

static void wait_child(pid_t child) {
    int status;
    CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
          WEXITSTATUS(status) == 0);
}

static void denied(const char* path, int provision, int error) {
    struct account_store* store = NULL;
    CHECK(account_store_begin(path, provision, &store) < 0 && errno == error && !store);
}

static void metadata(const char* path, mode_t mode) {
    struct stat value;
    CHECK(stat(path, &value) == 0 && value.st_uid == 0 && value.st_gid == 0 &&
          (value.st_mode & 07777) == mode);
    CHECK(S_ISDIR(value.st_mode) || (S_ISREG(value.st_mode) && value.st_nlink == 1));
}

int main(int argc, char** argv) {
    CHECK(argc == 2 && !geteuid() && !getegid());
    CHECK(mkdir(argv[1], 0755) == 0 || errno == EEXIST);
    CHECK(chmod(argv[1], 0755) == 0);
    char path[4096], shadow[4096], passwd[4096], current[4096], alias[4096], lock[4096];
    CHECK(snprintf(path, sizeof(path), "%s/db", argv[1]) < (int)sizeof(path));
    CHECK(snprintf(shadow, sizeof(shadow), "%s/current/shadow", path) < (int)sizeof(shadow));
    CHECK(snprintf(passwd, sizeof(passwd), "%s/current/passwd", path) < (int)sizeof(passwd));
    CHECK(snprintf(current, sizeof(current), "%s/current", path) < (int)sizeof(current));
    CHECK(snprintf(lock, sizeof(lock), "%s/lock", path) < (int)sizeof(lock));
    CHECK(snprintf(alias, sizeof(alias), "%s/alias", argv[1]) < (int)sizeof(alias));
    umask(0777);
    struct account_store* store = begin(path, 1);
    CHECK(!account_store_snapshot(store));
    commit(store, 1);
    account_store_end(store);
    umask(0077);
    metadata(path, 0755);
    metadata(current, 0755);
    metadata(passwd, 0644);
    metadata(shadow, 0600);
    metadata(lock, 0600);

    store = begin(path, 0);
    CHECK(epoch(store) == 1);
    struct account_content broken[ACCOUNT_FILE_COUNT] = {
        {"incomplete", 10}, {"group\n", 6}, {"shadow\n", 7}};
    int published = 1;
    CHECK(account_store_commit(store, broken, &published) < 0 && errno == EINVAL && !published);
    account_store_end(store);
    store = begin(path, 0);
    CHECK(epoch(store) == 1);
    account_store_end(store);

    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setgroups(0, NULL) == 0 && setgid(1000) == 0 && setuid(1000) == 0);
        denied(path, 1, EPERM);
        int fd = open(passwd, O_RDONLY);
        CHECK(fd >= 0 && close(fd) == 0);
        CHECK(open(passwd, O_WRONLY) < 0 && errno == EACCES);
        CHECK(open(shadow, O_RDONLY) < 0 && errno == EACCES);
        _exit(0);
    }
    wait_child(child);
    pid_t workers[4];
    for (unsigned i = 0; i < 4; i++) {
        workers[i] = fork();
        CHECK(workers[i] >= 0);
        if (!workers[i]) {
            for (unsigned update = 0; update < 3; update++) {
                store = begin(path, 0);
                commit(store, epoch(store) + 1);
                account_store_end(store);
            }
            _exit(0);
        }
    }
    for (unsigned i = 0; i < 4; i++)
        wait_child(workers[i]);
    store = begin(path, 0);
    CHECK(epoch(store) == 13);
    account_store_end(store);
    DIR* directory = opendir(path);
    CHECK(directory);
    unsigned generations = 0;
    struct dirent* entry;
    while ((entry = readdir(directory)))
        if (!strncmp(entry->d_name, "g-", 2))
            generations++;
    CHECK(closedir(directory) == 0 && generations == 2);

    CHECK(chmod(shadow, 0644) == 0);
    denied(path, 0, EACCES);
    CHECK(chmod(shadow, 0600) == 0 && chown(shadow, 1000, 1000) == 0);
    denied(path, 0, EACCES);
    CHECK(chown(shadow, 0, 0) == 0 && link(shadow, alias) == 0);
    denied(path, 0, EACCES);
    CHECK(unlink(alias) == 0);
    char target[35];
    CHECK(readlink(current, target, 34) == 34);
    target[34] = 0;
    CHECK(unlink(current) == 0);
    denied(path, 1, EUCLEAN);
    CHECK(symlink("/etc", current) == 0);
    denied(path, 1, EINVAL);
    CHECK(unlink(current) == 0 && symlink(target, current) == 0);
    store = begin(path, 0);
    CHECK(epoch(store) == 13);
    account_store_end(store);
    metadata(shadow, 0600);
    printf("ACCOUNT_STORE_PASS generations=2 concurrent_updates=12 epoch=13 ordinary_denials=3 "
           "protected_rejections=5 fixture=%s\n",
           argv[1]);
    return 0;
}
