// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "logbook.h"
#include "protected.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <unistd.h>

struct account_logbook {
    int directory, lock, journal;
    char* path;
    struct account_login_frame* frames;
    size_t count;
};

struct account_session_lease {
    int directory, descriptor;
    char* path;
    char name[35];
    struct account_login_frame start;
};

static int failed(int error) {
    errno = error;
    return -1;
}

static int authorized(void) {
    return geteuid() || getegid() || (uid_t)setfsuid(-1) || (gid_t)setfsgid(-1) ? failed(EPERM) : 0;
}

static int write_all(int fd, const void* bytes, size_t size, off_t position, int positioned) {
    for (size_t done = 0; done < size;) {
        ssize_t count =
            positioned ? pwrite(fd, (const char*)bytes + done, size - done, position + (off_t)done)
                       : write(fd, (const char*)bytes + done, size - done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return failed(count < 0 ? errno : EIO);
        done += (size_t)count;
    }
    return 0;
}

static int nonce_name(const char* name, char prefix) {
    if (strlen(name) != 34 || name[0] != prefix || name[1] != '-')
        return 0;
    for (size_t i = 2; i < 34; i++)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f')))
            return 0;
    return 1;
}

static int fresh(int directory) {
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    DIR* stream = fdopendir(fd);
    if (!stream) {
        close(fd);
        return -1;
    }
    int error = 0;
    for (;;) {
        errno = 0;
        struct dirent* entry = readdir(stream);
        if (!entry) {
            error = errno;
            break;
        }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..") &&
            strcmp(entry->d_name, "lock")) {
            error = EUCLEAN;
            break;
        }
    }
    if (closedir(stream) < 0 && !error)
        error = errno;
    return error ? failed(error) : 0;
}

static int load(struct account_logbook* book) {
    struct stat value;
    if (fstat(book->journal, &value) < 0)
        return -1;
    if (value.st_size < 0 || value.st_size > ACCOUNT_LOGIN_JOURNAL_LIMIT)
        return failed(EFBIG);
    size_t count = (size_t)value.st_size / sizeof(struct account_login_frame);
    struct account_login_frame* frames = count ? malloc(count * sizeof(*frames)) : NULL;
    if (count && !frames)
        return -1;
    int error = 0;
    size_t bytes = count * sizeof(*frames);
    for (size_t done = 0; !error && done < bytes;) {
        ssize_t size = pread(book->journal, (char*)frames + done, bytes - done, (off_t)done);
        if (size < 0 && errno == EINTR)
            continue;
        if (size <= 0)
            error = size < 0 ? errno : EIO;
        else
            done += (size_t)size;
    }
    for (size_t i = 0; !error && i < count; i++)
        if (!account_login_frame_valid(&frames[i], i + 1))
            error = EUCLEAN;
    for (size_t i = 0; !error && i < count; i++) {
        const struct account_login_frame* frame = &frames[i];
        if (frame->kind == ACCOUNT_LOGIN_START) {
            for (size_t previous = 0; previous < i; previous++)
                if (frames[previous].kind == ACCOUNT_LOGIN_START &&
                    !memcmp(frames[previous].token, frame->token, 16))
                    error = EUCLEAN;
        } else if (frame->kind == ACCOUNT_LOGIN_END || frame->kind == ACCOUNT_LOGIN_RECOVERED) {
            const struct account_login_frame* start = NULL;
            for (size_t previous = 0; previous < i; previous++) {
                if (memcmp(frames[previous].token, frame->token, 16))
                    continue;
                if (frames[previous].kind == ACCOUNT_LOGIN_START)
                    start = &frames[previous];
                else if (frames[previous].kind == ACCOUNT_LOGIN_END ||
                         frames[previous].kind == ACCOUNT_LOGIN_RECOVERED)
                    error = EUCLEAN;
            }
            if (!start || start->uid != frame->uid || start->gid != frame->gid ||
                start->entry.pid != frame->entry.pid ||
                memcmp(start->entry.user, frame->entry.user, 32) ||
                memcmp(start->entry.line, frame->entry.line, 32))
                error = EUCLEAN;
        }
    }
    if (!error && (size_t)value.st_size != bytes &&
        (ftruncate(book->journal, (off_t)bytes) < 0 || fsync(book->journal) < 0))
        error = errno;
    if (error) {
        free(frames);
        return failed(error);
    }
    free(book->frames);
    book->frames = frames;
    book->count = count;
    return 0;
}

static int same_token(const struct account_login_frame* first,
                      const struct account_login_frame* second) {
    return !memcmp(first->token, second->token, 16);
}

static int ended(const struct account_logbook* book, size_t start) {
    for (size_t i = start + 1; i < book->count; i++)
        if ((book->frames[i].kind == ACCOUNT_LOGIN_END ||
             book->frames[i].kind == ACCOUNT_LOGIN_RECOVERED) &&
            same_token(&book->frames[start], &book->frames[i]))
            return 1;
    return 0;
}

static int append(struct account_logbook* book, struct account_login_frame* frame, int* published) {
    *published = 0;
    if ((book->count + 1) * sizeof(*frame) > ACCOUNT_LOGIN_JOURNAL_LIMIT)
        return failed(EFBIG);
    struct account_login_frame* next = realloc(book->frames, (book->count + 1) * sizeof(*next));
    if (!next)
        return -1;
    book->frames = next;
    account_login_frame_seal(frame, book->count + 1);
    if (!account_login_frame_valid(frame, book->count + 1))
        return failed(EINVAL);
    off_t position = (off_t)(book->count * sizeof(*frame));
    if (write_all(book->journal, frame, sizeof(*frame), position, 1) < 0) {
        int error = errno;
        // A partial append is not an event. On an additional rollback failure,
        // the next transaction validates all full frames before trimming tail.
        if (ftruncate(book->journal, position) == 0)
            fsync(book->journal);
        return failed(error);
    }
    book->frames[book->count++] = *frame;
    *published = 1;
    return fsync(book->journal);
}

static int recover(struct account_logbook* book) {
    for (size_t i = 0; i < book->count; i++) {
        if (book->frames[i].kind != ACCOUNT_LOGIN_START || ended(book, i))
            continue;
        char name[35];
        account_nonce_name(name, 'l', book->frames[i].token);
        int fd = account_file_open(book->directory, name, O_RDWR, 0600, 0);
        if (fd < 0)
            return failed(errno == ENOENT ? EUCLEAN : errno);
        if (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) < 0) {
            int error = errno;
            close(fd);
            if (error == EWOULDBLOCK || error == EAGAIN)
                continue;
            return failed(error);
        }
        struct account_login_frame dead = book->frames[i];
        char user[33] = {0};
        memcpy(user, dead.entry.user, 32);
        if (account_login_frame_make(&dead, ACCOUNT_LOGIN_RECOVERED, user, dead.uid, dead.gid,
                                     dead.entry.pid, dead.entry.line, NULL, 0, dead.token) < 0) {
            if (fd >= 0)
                close(fd);
            return -1;
        }
        int published;
        int error = append(book, &dead, &published) < 0 ? errno : 0;
        if (fd >= 0) {
            close(fd);
            if (published && unlinkat(book->directory, name, 0) < 0 && !error)
                error = errno;
        }
        if (error)
            return failed(error);
    }
    return 0;
}

struct projection {
    struct account_logbook* book;
    unsigned kind;
};

static int write_projection(int fd, void* context) {
    struct projection* projection = context;
    struct account_logbook* book = projection->book;
    if (projection->kind == 0) {
        // utmp keeps the latest occupant of each terminal. An older session's
        // delayed logout cannot clear a newer occupant of the same path.
        size_t* slots = book->count ? malloc(book->count * sizeof(*slots)) : NULL;
        if (book->count && !slots)
            return -1;
        size_t count = 0;
        for (size_t i = 0; i < book->count; i++) {
            const struct account_login_frame* frame = &book->frames[i];
            if (frame->kind != ACCOUNT_LOGIN_START && frame->kind != ACCOUNT_LOGIN_END &&
                frame->kind != ACCOUNT_LOGIN_RECOVERED)
                continue;
            size_t slot = 0;
            while (slot < count && strcmp(book->frames[slots[slot]].entry.line, frame->entry.line))
                slot++;
            if (frame->kind == ACCOUNT_LOGIN_START) {
                if (slot == count)
                    count++;
                slots[slot] = i;
            } else if (slot < count && same_token(&book->frames[slots[slot]], frame))
                slots[slot] = i;
        }
        int error = 0;
        for (size_t i = 0; !error && i < count; i++) {
            struct account_login_entry entry = book->frames[slots[i]].entry;
            if (entry.type == 8)
                memset(entry.user, 0, sizeof(entry.user));
            if (write_all(fd, &entry, sizeof(entry), 0, 0) < 0)
                error = errno;
        }
        free(slots);
        return error ? failed(error) : 0;
    }
    for (size_t i = 0; i < book->count; i++) {
        const struct account_login_frame* frame = &book->frames[i];
        if (projection->kind == 1 &&
            (frame->kind == ACCOUNT_LOGIN_START || frame->kind == ACCOUNT_LOGIN_END ||
             frame->kind == ACCOUNT_LOGIN_RECOVERED || frame->kind == ACCOUNT_LOGIN_BOOT)) {
            struct account_login_entry entry = frame->entry;
            if (entry.type == 8)
                memset(entry.user, 0, sizeof(entry.user));
            if (write_all(fd, &entry, sizeof(entry), 0, 0) < 0)
                return -1;
        } else if (projection->kind == 2 && frame->kind == ACCOUNT_LOGIN_DENIED) {
            if (write_all(fd, &frame->entry, sizeof(frame->entry), 0, 0) < 0)
                return -1;
        } else if (projection->kind == 3) {
            char user[33] = {0}, target[257] = {0}, line[512];
            memcpy(user, frame->entry.user, 32);
            memcpy(target, frame->entry.host, 256);
            int count = snprintf(line, sizeof(line),
                                 "%lld.%06d seq=%llu event=%s user=%s uid=%u gid=%u pid=%d tty=%s "
                                 "target=%s status=%d\n",
                                 (long long)frame->seconds, frame->entry.microseconds,
                                 (unsigned long long)frame->sequence,
                                 account_login_kind_name(frame->kind), user, frame->uid, frame->gid,
                                 frame->entry.pid, frame->entry.line, target, frame->status);
            if (count < 0 || count >= (int)sizeof(line))
                return failed(EOVERFLOW);
            if (write_all(fd, line, (size_t)count, 0, 0) < 0)
                return -1;
        }
    }
    return 0;
}

static int publish(struct account_logbook* book) {
    static const char* names[] = {"utmp", "wtmp", "btmp", "auth.log"};
    for (unsigned kind = 0; kind < 4; kind++) {
        struct projection projection = {book, kind};
        if (account_file_publish(book->directory, names[kind], kind < 2 ? 0644 : 0600,
                                 write_projection, &projection) < 0)
            return -1;
    }
    return 0;
}

static int collect(struct account_logbook* book) {
    int fd = openat(book->directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    DIR* stream = fdopendir(fd);
    if (!stream) {
        close(fd);
        return -1;
    }
    int error = 0;
    for (;;) {
        errno = 0;
        struct dirent* entry = readdir(stream);
        if (!entry) {
            error = errno;
            break;
        }
        int temporary = nonce_name(entry->d_name, 't');
        int lease = nonce_name(entry->d_name, 'l');
        if (!temporary && !lease)
            continue;
        if (lease) {
            int live = 0;
            for (size_t i = 0; i < book->count; i++) {
                if (book->frames[i].kind != ACCOUNT_LOGIN_START || ended(book, i))
                    continue;
                char name[35];
                account_nonce_name(name, 'l', book->frames[i].token);
                live |= !strcmp(name, entry->d_name);
            }
            if (live)
                continue;
        }
        mode_t mode = 0600;
        struct stat value;
        if (fstatat(book->directory, entry->d_name, &value, AT_SYMLINK_NOFOLLOW) < 0) {
            error = errno;
            break;
        }
        if (temporary && (value.st_mode & 07777) == 0644)
            mode = 0644;
        int file = account_file_open(book->directory, entry->d_name, O_RDWR, mode, 0);
        if (file < 0) {
            error = errno;
            break;
        }
        if (flock(file, LOCK_EX | LOCK_NB) < 0) {
            error = errno;
            close(file);
            if (lease && (error == EWOULDBLOCK || error == EAGAIN)) {
                error = 0;
                continue;
            }
            break;
        }
        if (unlinkat(book->directory, entry->d_name, 0) < 0)
            error = errno;
        close(file);
        if (error)
            break;
    }
    if (closedir(stream) < 0 && !error)
        error = errno;
    if (!error && fsync(book->directory) < 0)
        error = errno;
    return error ? failed(error) : 0;
}

void account_logbook_close(struct account_logbook* book) {
    if (!book)
        return;
    if (book->journal >= 0)
        close(book->journal);
    if (book->lock >= 0)
        close(book->lock);
    if (book->directory >= 0)
        close(book->directory);
    free(book->path);
    free(book->frames);
    free(book);
}

int account_logbook_open(const char* path, int create, struct account_logbook** output) {
    if (!output)
        return failed(EINVAL);
    *output = NULL;
    struct account_logbook* book = calloc(1, sizeof(*book));
    if (!book)
        return -1;
    book->directory = book->lock = book->journal = -1;
    book->path = path ? strdup(path) : NULL;
    int error = book->path ? 0 : EINVAL;
    if (!error && (book->directory = account_directory_open(path, 0755, create)) < 0)
        error = errno;
    if (!error &&
        (book->lock = account_file_open(book->directory, "lock", O_RDWR, 0600, create)) < 0)
        error = errno;
    if (!error && flock(book->lock, LOCK_EX) < 0)
        error = errno;
    if (!error) {
        book->journal = account_file_open(book->directory, "journal", O_RDWR, 0600, 0);
        if (book->journal < 0 && errno == ENOENT && create) {
            if (fresh(book->directory) < 0)
                error = errno;
            else
                book->journal = account_file_open(book->directory, "journal", O_RDWR, 0600, 1);
        }
        if (book->journal < 0 && !error)
            error = errno;
    }
    static const char* projections[] = {"utmp", "wtmp", "btmp", "auth.log"};
    for (unsigned i = 0; !error && i < 4; i++)
        if (account_file_check(book->directory, projections[i], i < 2 ? 0644 : 0600) < 0)
            error = errno;
    if (!error && (load(book) < 0 || recover(book) < 0 || publish(book) < 0 || collect(book) < 0))
        error = errno;
    if (error) {
        account_logbook_close(book);
        return failed(error);
    }
    *output = book;
    return 0;
}

int account_logbook_active(const struct account_logbook* book, uid_t uid) {
    if (authorized() < 0)
        return -1;
    if (!book || uid == (uid_t)-1)
        return failed(EINVAL);
    for (size_t i = 0; i < book->count; i++)
        if (book->frames[i].kind == ACCOUNT_LOGIN_START && book->frames[i].uid == uid &&
            !ended(book, i))
            return 1;
    return 0;
}

int account_logbook_begin(struct account_logbook* book, const struct account_profile* profile,
                          pid_t child, const char* terminal,
                          struct account_session_lease** output) {
    if (authorized() < 0)
        return -1;
    if (!book || !profile || !output || child <= 0)
        return failed(EINVAL);
    *output = NULL;
    if (getsid(child) != child || getpgid(child) != child)
        return failed(EINVAL);
    struct account_session_lease* lease = calloc(1, sizeof(*lease));
    if (!lease)
        return -1;
    lease->directory = lease->descriptor = -1;
    lease->path = strdup(book->path);
    int error = lease->path ? 0 : ENOMEM;
    unsigned char nonce[16];
    if (!error && account_nonce(nonce) < 0)
        error = errno;
    if (!error &&
        account_login_frame_make(&lease->start, ACCOUNT_LOGIN_START, profile->name, profile->uid,
                                 profile->gid, child, terminal, NULL, 0, nonce) < 0)
        error = errno;
    if (!error) {
        account_nonce_name(lease->name, 'l', nonce);
        lease->descriptor = openat(book->directory, lease->name,
                                   O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (lease->descriptor < 0 || fchmod(lease->descriptor, 0600) < 0 ||
            flock(lease->descriptor, LOCK_EX | LOCK_NB) < 0 || fsync(lease->descriptor) < 0 ||
            fsync(book->directory) < 0)
            error = errno;
        if (!error)
            lease->directory = fcntl(book->directory, F_DUPFD_CLOEXEC, 3);
        if (!error && lease->directory < 0)
            error = errno;
    }
    int published = 0;
    if (!error && append(book, &lease->start, &published) < 0)
        error = errno;
    if (!error && publish(book) < 0)
        error = errno;
    if (published) {
        *output = lease;
        return error ? failed(error) : 0;
    }
    if (lease->descriptor >= 0) {
        close(lease->descriptor);
        unlinkat(book->directory, lease->name, 0);
    }
    if (lease->directory >= 0)
        close(lease->directory);
    free(lease->path);
    free(lease);
    return failed(error ? error : EIO);
}

int account_logbook_end(struct account_session_lease* lease, int status) {
    if (!lease)
        return 0;
    struct account_logbook* book = NULL;
    int error = account_logbook_open(lease->path, 0, &book) < 0 ? errno : 0;
    int published = 0;
    if (!error) {
        struct account_login_frame dead;
        char user[33] = {0};
        memcpy(user, lease->start.entry.user, 32);
        if (account_login_frame_make(&dead, ACCOUNT_LOGIN_END, user, lease->start.uid,
                                     lease->start.gid, lease->start.entry.pid,
                                     lease->start.entry.line, NULL, status,
                                     lease->start.token) < 0 ||
            append(book, &dead, &published) < 0)
            error = errno;
        if (!error && publish(book) < 0)
            error = errno;
    }
    close(lease->descriptor);
    if (published && unlinkat(lease->directory, lease->name, 0) < 0 && !error)
        error = errno;
    if (published && fsync(lease->directory) < 0 && !error)
        error = errno;
    account_logbook_close(book);
    close(lease->directory);
    free(lease->path);
    free(lease);
    return error ? failed(error) : 0;
}

int account_logbook_audit(struct account_logbook* book, enum account_login_kind kind,
                          const char* name, uid_t uid, const char* target, const char* terminal,
                          int status) {
    if (authorized() < 0)
        return -1;
    if (!book || kind == ACCOUNT_LOGIN_START || kind == ACCOUNT_LOGIN_END ||
        kind == ACCOUNT_LOGIN_RECOVERED)
        return failed(EINVAL);
    if (kind == ACCOUNT_LOGIN_BOOT)
        for (size_t i = 0; i < book->count; i++)
            if (book->frames[i].kind == ACCOUNT_LOGIN_START && !ended(book, i))
                return failed(EBUSY);
    struct account_login_frame frame;
    if (account_login_frame_make(&frame, kind, name, uid,
                                 kind == ACCOUNT_LOGIN_DENIED ? (gid_t)-1 : 0, getpid(), terminal,
                                 target, status, NULL) < 0)
        return -1;
    int published;
    if (append(book, &frame, &published) < 0)
        return -1;
    return publish(book);
}
