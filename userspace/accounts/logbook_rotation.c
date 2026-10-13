// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "logbook_internal.h"
#include "protected.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define STATE_MAGIC UINT32_C(0x53423641)
#define ROTATION_MAGIC UINT32_C(0x52423641)

struct rotation {
    uint32_t magic, version, size, crc;
    struct account_logbook_state before, after;
    uint64_t frames;
    uint32_t original_crc, carried_crc;
};

_Static_assert(sizeof(struct account_logbook_state) == 40, "Logbook state wire size");
_Static_assert(sizeof(struct rotation) == 112, "Logbook rotation wire size");

static const char* archive_files[] = {"journal", "wtmp", "btmp", "auth.log", "state"};
static const mode_t archive_modes[] = {0600, 0644, 0600, 0600, 0600};

static int failed(int error) {
    errno = error;
    return -1;
}

static uint32_t checksum(const void* data, size_t size) {
    const unsigned char* bytes = data;
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < size; i++) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
    }
    return crc ^ UINT32_MAX;
}

static void seal(void* data, size_t size, uint32_t magic) {
    uint32_t* header = data;
    header[0] = magic;
    header[1] = 1;
    header[2] = (uint32_t)size;
    header[3] = 0;
    header[3] = checksum(data, size);
}

static int valid(const void* data, size_t size, uint32_t magic) {
    const uint32_t* header = data;
    unsigned char copy[sizeof(struct rotation)];
    if (size > sizeof(copy) || header[0] != magic || header[1] != 1 || header[2] != size)
        return 0;
    memcpy(copy, data, size);
    uint32_t saved;
    memcpy(&saved, copy + 12, sizeof(saved));
    memset(copy + 12, 0, sizeof(saved));
    return saved == checksum(copy, size);
}

static int state_valid(const struct account_logbook_state* state) {
    return valid(state, sizeof(*state), STATE_MAGIC) && state->generation &&
           state->carried <= ACCOUNT_LOGIN_LIVE_LIMIT &&
           state->carried < ACCOUNT_LOGIN_JOURNAL_LIMIT / sizeof(struct account_login_frame) &&
           (state->generation != 1 || (!state->carried && !state->previous_events));
}

static int read_all(int fd, void* output, size_t size, off_t offset) {
    for (size_t done = 0; done < size;) {
        ssize_t count = pread(fd, (char*)output + done, size - done, offset + (off_t)done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return failed(count < 0 ? errno : EUCLEAN);
        done += (size_t)count;
    }
    return 0;
}

static int read_record(int directory, const char* name, void* output, size_t size) {
    int fd = account_file_open(directory, name, O_RDONLY, 0600, 0);
    if (fd < 0)
        return -1;
    struct stat value;
    int error = fstat(fd, &value) < 0 ? errno : 0;
    if (!error && value.st_size != (off_t)size)
        error = EUCLEAN;
    if (!error && read_all(fd, output, size, 0) < 0)
        error = errno;
    if (close(fd) < 0 && !error)
        error = errno;
    return error ? failed(error) : 0;
}

struct bytes {
    const void* data;
    size_t size;
};

static int write_bytes(int fd, void* context) {
    const struct bytes* bytes = context;
    for (size_t done = 0; done < bytes->size;) {
        ssize_t count = write(fd, (const char*)bytes->data + done, bytes->size - done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return failed(count < 0 ? errno : EIO);
        done += (size_t)count;
    }
    return 0;
}

static int publish_bytes(int directory, const char* name, const void* data, size_t size) {
    struct bytes bytes = {data, size};
    return account_file_publish(directory, name, 0600, write_bytes, &bytes);
}

static void archive_name(char name[25], uint64_t generation) {
    snprintf(name, 25, "archive-%016llx", (unsigned long long)generation);
}

static int archive_generation(const char* name, uint64_t* output) {
    if (strlen(name) != 24 || strncmp(name, "archive-", 8))
        return 0;
    uint64_t value = 0;
    for (unsigned i = 8; i < 24; i++) {
        char digit = name[i];
        if (!((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f')))
            return 0;
        value = (value << 4) | (unsigned)(digit <= '9' ? digit - '0' : digit - 'a' + 10);
    }
    if (!value)
        return 0;
    *output = value;
    return 1;
}

static int archive_open(const struct account_logbook* book, uint64_t generation, int create) {
    char name[25], path[4096];
    archive_name(name, generation);
    int size = snprintf(path, sizeof(path), "%s/%s", book->path, name);
    if (size < 0 || size >= (int)sizeof(path))
        return failed(ENAMETOOLONG);
    return account_directory_open(path, 0755, create);
}

// Interrupted provisional publication may leave only protected temporary files.
// Closed generations and expiry never admit arbitrary directory contents.
static int archive_entries(int directory, int provisional) {
    int copy = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (copy < 0)
        return -1;
    DIR* stream = fdopendir(copy);
    if (!stream) {
        close(copy);
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
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        unsigned kind;
        for (kind = 0; kind < 5 && strcmp(entry->d_name, archive_files[kind]); kind++)
            ;
        int temporary =
            provisional && strlen(entry->d_name) == 34 && !strncmp(entry->d_name, "t-", 2);
        for (unsigned i = 2; temporary && i < 34; i++)
            temporary = (entry->d_name[i] >= '0' && entry->d_name[i] <= '9') ||
                        (entry->d_name[i] >= 'a' && entry->d_name[i] <= 'f');
        if (kind == 5 && !temporary) {
            error = EUCLEAN;
            break;
        }
        mode_t mode = kind < 5 ? archive_modes[kind] : 0600;
        if (temporary) {
            struct stat value;
            if (fstatat(directory, entry->d_name, &value, AT_SYMLINK_NOFOLLOW) < 0) {
                error = errno;
                break;
            }
            if ((value.st_mode & 07777) == 0644)
                mode = 0644;
        }
        int fd = account_file_open(directory, entry->d_name, O_RDONLY, mode, 0);
        if (fd < 0) {
            error = errno;
            break;
        }
        if (close(fd) < 0 || (temporary && unlinkat(directory, entry->d_name, 0) < 0)) {
            error = errno;
            break;
        }
    }
    if (closedir(stream) < 0 && !error)
        error = errno;
    if (!error && provisional && fsync(directory) < 0)
        error = errno;
    return error ? failed(error) : 0;
}

static int compare_bytes(int fd, const void* expected, size_t size, off_t* position) {
    unsigned char buffer[512];
    const unsigned char* bytes = expected;
    for (size_t done = 0; done < size;) {
        size_t count = size - done < sizeof(buffer) ? size - done : sizeof(buffer);
        if (read_all(fd, buffer, count, *position + (off_t)done) < 0)
            return -1;
        if (memcmp(buffer, bytes + done, count))
            return failed(EUCLEAN);
        done += count;
    }
    *position += (off_t)size;
    return 0;
}

static int projection_valid(struct account_logbook* book, unsigned kind) {
    int fd =
        account_file_open(book->directory, archive_files[kind], O_RDONLY, archive_modes[kind], 0);
    if (fd < 0)
        return -1;
    off_t position = 0;
    int error = 0;
    for (size_t i = book->state.carried; !error && i < book->count; i++) {
        const struct account_login_frame* frame = &book->frames[i];
        if ((kind == 1 &&
             (frame->kind == ACCOUNT_LOGIN_START || frame->kind == ACCOUNT_LOGIN_END ||
              frame->kind == ACCOUNT_LOGIN_RECOVERED || frame->kind == ACCOUNT_LOGIN_BOOT)) ||
            (kind == 2 && frame->kind == ACCOUNT_LOGIN_DENIED)) {
            struct account_login_entry entry = frame->entry;
            if (entry.type == 8)
                memset(entry.user, 0, sizeof(entry.user));
            if (compare_bytes(fd, &entry, sizeof(entry), &position) < 0)
                error = errno;
        } else if (kind == 3) {
            char line[512];
            int count = account_logbook_auth_line(book, i, line, sizeof(line));
            if (count < 0 || compare_bytes(fd, line, (size_t)count, &position) < 0)
                error = errno;
        }
    }
    struct stat value;
    if (!error && fstat(fd, &value) < 0)
        error = errno;
    if (!error && value.st_size != position)
        error = EUCLEAN;
    if (close(fd) < 0 && !error)
        error = errno;
    return error ? failed(error) : 0;
}

static void archive_close(struct account_logbook* archive) {
    if (archive->journal >= 0)
        close(archive->journal);
    if (archive->directory >= 0)
        close(archive->directory);
    free(archive->frames);
}

static int archive_load(const struct account_logbook* book, uint64_t generation,
                        struct account_logbook* archive) {
    memset(archive, 0, sizeof(*archive));
    archive->directory = archive->journal = -1;
    archive->immutable = 1;
    int error = 0;
    if ((archive->directory = archive_open(book, generation, 0)) < 0)
        error = errno;
    if (!error &&
        (archive_entries(archive->directory, 0) < 0 ||
         read_record(archive->directory, "state", &archive->state, sizeof(archive->state)) < 0))
        error = errno;
    if (!error && (!state_valid(&archive->state) || archive->state.generation != generation))
        error = EUCLEAN;
    if (!error && (archive->journal =
                       account_file_open(archive->directory, "journal", O_RDONLY, 0600, 0)) < 0)
        error = errno;
    if (!error && account_logbook_load(archive) < 0)
        error = errno;
    for (unsigned kind = 1; !error && kind < 4; kind++)
        if (projection_valid(archive, kind) < 0)
            error = errno;
    if (error) {
        archive_close(archive);
        return failed(error);
    }
    return 0;
}

static int carry(const struct account_logbook* book, struct account_login_frame** output,
                 size_t* count) {
    *output = NULL;
    *count = 0;
    for (size_t i = 0; i < book->count; i++)
        *count += book->frames[i].kind == ACCOUNT_LOGIN_START && !account_logbook_ended(book, i);
    if (*count > ACCOUNT_LOGIN_LIVE_LIMIT ||
        *count >= ACCOUNT_LOGIN_JOURNAL_LIMIT / sizeof(struct account_login_frame))
        return failed(ENOSPC);
    struct account_login_frame* frames = *count ? malloc(*count * sizeof(*frames)) : NULL;
    if (*count && !frames)
        return -1;
    for (size_t i = 0, next = 0; i < book->count; i++) {
        if (book->frames[i].kind != ACCOUNT_LOGIN_START || account_logbook_ended(book, i))
            continue;
        frames[next] = book->frames[i];
        account_login_frame_seal(&frames[next], next + 1);
        next++;
    }
    *output = frames;
    return 0;
}

static int archive_prepare(struct account_logbook* book) {
    int directory = archive_open(book, book->state.generation, 1);
    if (directory < 0)
        return -1;
    int error = archive_entries(directory, 1) < 0 ? errno : 0;
    if (!error &&
        publish_bytes(directory, "journal", book->frames, book->count * sizeof(*book->frames)) < 0)
        error = errno;
    for (unsigned kind = 1; !error && kind < 4; kind++) {
        struct account_logbook_projection projection = {book, kind};
        if (account_file_publish(directory, archive_files[kind], archive_modes[kind],
                                 account_logbook_write_projection, &projection) < 0)
            error = errno;
    }
    if (!error && publish_bytes(directory, "state", &book->state, sizeof(book->state)) < 0)
        error = errno;
    if (!error && (fsync(directory) < 0 || fsync(book->directory) < 0))
        error = errno;
    if (close(directory) < 0 && !error)
        error = errno;
    // The archived source must reproduce exactly the source being replaced.
    struct account_logbook archive;
    if (!error && archive_load(book, book->state.generation, &archive) < 0)
        error = errno;
    else if (!error) {
        if (archive.count != book->count ||
            memcmp(&archive.state, &book->state, sizeof(book->state)) ||
            (book->count &&
             memcmp(archive.frames, book->frames, book->count * sizeof(*book->frames))))
            error = EUCLEAN;
        archive_close(&archive);
    }
    return error ? failed(error) : 0;
}

static int current_matches(int fd, const struct account_login_frame* frames, size_t count) {
    struct stat value;
    if (fstat(fd, &value) < 0)
        return -1;
    if (value.st_size != (off_t)(count * sizeof(*frames)))
        return 0;
    off_t position = 0;
    if (compare_bytes(fd, frames, count * sizeof(*frames), &position) < 0)
        return errno == EUCLEAN ? 0 : -1;
    return 1;
}

static int finish_rotation(struct account_logbook* book, const struct rotation* record) {
    if (!valid(record, sizeof(*record), ROTATION_MAGIC) || !state_valid(&record->before) ||
        !state_valid(&record->after) || record->before.generation == UINT64_MAX ||
        record->after.generation != record->before.generation + 1 ||
        record->frames > ACCOUNT_LOGIN_JOURNAL_LIMIT / sizeof(struct account_login_frame) ||
        record->frames < record->before.carried ||
        record->before.previous_events > UINT64_MAX - (record->frames - record->before.carried) ||
        record->after.previous_events !=
            record->before.previous_events + record->frames - record->before.carried)
        return failed(EUCLEAN);
    struct account_logbook archive;
    if (archive_load(book, record->before.generation, &archive) < 0)
        return -1;
    int error = 0;
    if (archive.count != record->frames ||
        memcmp(&archive.state, &record->before, sizeof(archive.state)) ||
        checksum(archive.frames, archive.count * sizeof(*archive.frames)) != record->original_crc)
        error = EUCLEAN;
    struct account_login_frame* frames = NULL;
    size_t count = 0;
    if (!error && carry(&archive, &frames, &count) < 0)
        error = errno;
    if (!error && (count != record->after.carried ||
                   checksum(frames, count * sizeof(*frames)) != record->carried_crc))
        error = EUCLEAN;
    struct account_logbook_state state;
    if (!error && read_record(book->directory, "state", &state, sizeof(state)) < 0) {
        if (errno != ENOENT || record->before.generation != 1)
            error = errno;
        else
            state = record->before;
    }
    if (!error && memcmp(&state, &record->before, sizeof(state)) &&
        memcmp(&state, &record->after, sizeof(state)))
        error = EUCLEAN;
    int is_new = 0;
    if (!error && (is_new = current_matches(book->journal, frames, count)) < 0)
        error = errno;
    if (!error && !is_new) {
        int is_old = current_matches(book->journal, archive.frames, archive.count);
        if (is_old <= 0)
            error = is_old < 0 ? errno : EUCLEAN;
        else if (publish_bytes(book->directory, "journal", frames, count * sizeof(*frames)) < 0)
            error = errno;
    }
    if (!error) {
        // rename leaves the original descriptor attached to the archived inode.
        // Every subsequent append must use the newly published current file.
        if (close(book->journal) < 0)
            error = errno;
        book->journal = -1;
        if (!error &&
            (book->journal = account_file_open(book->directory, "journal", O_RDWR, 0600, 0)) < 0)
            error = errno;
    }
    if (!error && (fsync(book->journal) < 0 || fsync(book->directory) < 0 ||
                   publish_bytes(book->directory, "state", &record->after, sizeof(state)) < 0))
        error = errno;
    if (!error && (unlinkat(book->directory, "rotation", 0) < 0 || fsync(book->directory) < 0))
        error = errno;
    if (!error)
        book->state = record->after;
    free(frames);
    archive_close(&archive);
    return error ? failed(error) : 0;
}

int account_logbook_rotation_open(struct account_logbook* book) {
    struct rotation record;
    if (read_record(book->directory, "rotation", &record, sizeof(record)) == 0) {
        if (finish_rotation(book, &record) < 0)
            return -1;
    } else if (errno != ENOENT)
        return -1;
    if (read_record(book->directory, "state", &book->state, sizeof(book->state)) < 0) {
        if (errno != ENOENT)
            return -1;
        memset(&book->state, 0, sizeof(book->state));
        book->state.generation = 1;
        seal(&book->state, sizeof(book->state), STATE_MAGIC);
    }
    return state_valid(&book->state) ? 0 : failed(EUCLEAN);
}

static int carry_matches(const struct account_logbook* previous,
                         const struct account_logbook* next) {
    struct account_login_frame* frames = NULL;
    size_t count = 0;
    if (carry(previous, &frames, &count) < 0)
        return -1;
    int matched = count == next->state.carried &&
                  (!count || !memcmp(frames, next->frames, count * sizeof(*frames)));
    free(frames);
    if (!matched ||
        previous->state.previous_events >
            UINT64_MAX - (previous->count - previous->state.carried) ||
        next->state.previous_events !=
            previous->state.previous_events + previous->count - previous->state.carried)
        return failed(EUCLEAN);
    return 0;
}

int account_logbook_rotation_validate(struct account_logbook* book) {
    uint64_t first = book->state.generation > ACCOUNT_LOGIN_ARCHIVE_LIMIT
                         ? book->state.generation - ACCOUNT_LOGIN_ARCHIVE_LIMIT
                         : 1;
    struct account_logbook previous;
    int have_previous = 0;
    int error = 0;
    for (uint64_t generation = first; !error && generation < book->state.generation; generation++) {
        struct account_logbook next;
        if (archive_load(book, generation, &next) < 0) {
            error = errno == ENOENT ? EUCLEAN : errno;
            break;
        }
        if (have_previous && carry_matches(&previous, &next) < 0)
            error = errno;
        if (have_previous)
            archive_close(&previous);
        previous = next;
        have_previous = 1;
    }
    if (!error && have_previous && carry_matches(&previous, book) < 0)
        error = errno;
    if (have_previous)
        archive_close(&previous);
    return error ? failed(error) : 0;
}

int account_logbook_rotate(struct account_logbook* book) {
    if (book->state.generation == UINT64_MAX ||
        book->state.previous_events > UINT64_MAX - (book->count - book->state.carried))
        return failed(EOVERFLOW);
    struct account_login_frame* frames = NULL;
    size_t count = 0;
    if (carry(book, &frames, &count) < 0)
        return -1;
    struct rotation record = {0};
    record.before = book->state;
    record.after.generation = book->state.generation + 1;
    record.after.carried = count;
    record.after.previous_events = book->state.previous_events + book->count - book->state.carried;
    seal(&record.after, sizeof(record.after), STATE_MAGIC);
    record.frames = book->count;
    record.original_crc = checksum(book->frames, book->count * sizeof(*book->frames));
    record.carried_crc = checksum(frames, count * sizeof(*frames));
    seal(&record, sizeof(record), ROTATION_MAGIC);
    free(frames);
    if (archive_prepare(book) < 0 ||
        publish_bytes(book->directory, "rotation", &record, sizeof(record)) < 0 ||
        finish_rotation(book, &record) < 0 || account_logbook_load(book) < 0 ||
        account_logbook_rotation_validate(book) < 0 || account_logbook_rotation_collect(book) < 0)
        return -1;
    return 0;
}

int account_logbook_rotation_collect(struct account_logbook* book) {
    int copy = openat(book->directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (copy < 0)
        return -1;
    DIR* stream = fdopendir(copy);
    if (!stream) {
        close(copy);
        return -1;
    }
    uint64_t first = book->state.generation > ACCOUNT_LOGIN_ARCHIVE_LIMIT
                         ? book->state.generation - ACCOUNT_LOGIN_ARCHIVE_LIMIT
                         : 1;
    int error = 0;
    for (;;) {
        errno = 0;
        struct dirent* entry = readdir(stream);
        if (!entry) {
            error = errno;
            break;
        }
        uint64_t generation;
        if (strncmp(entry->d_name, "archive-", 8))
            continue;
        if (!archive_generation(entry->d_name, &generation) ||
            generation > book->state.generation) {
            error = EUCLEAN;
            break;
        }
        int directory = archive_open(book, generation, 0);
        if (directory < 0) {
            error = errno;
            break;
        }
        if (archive_entries(directory, generation == book->state.generation) < 0)
            error = errno;
        if (!error && generation == book->state.generation) {
            // A provisional archive is legal only while its source is still
            // current. This also detects a removed state file after rotation.
            int journal = account_file_open(directory, "journal", O_RDONLY, 0600, 0);
            if (journal < 0 && errno != ENOENT)
                error = errno;
            else if (journal >= 0) {
                int matched = current_matches(journal, book->frames, book->count);
                if (matched <= 0)
                    error = matched < 0 ? errno : EUCLEAN;
                if (close(journal) < 0 && !error)
                    error = errno;
            }
            struct account_logbook_state state;
            if (!error && read_record(directory, "state", &state, sizeof(state)) < 0) {
                if (errno != ENOENT)
                    error = errno;
            } else if (!error && memcmp(&state, &book->state, sizeof(state)))
                error = EUCLEAN;
        }
        if (!error && generation < first) {
            for (unsigned kind = 0; !error && kind < 5; kind++)
                if (unlinkat(directory, archive_files[kind], 0) < 0 && errno != ENOENT)
                    error = errno;
            if (!error && fsync(directory) < 0)
                error = errno;
        }
        if (close(directory) < 0 && !error)
            error = errno;
        if (!error && generation < first &&
            unlinkat(book->directory, entry->d_name, AT_REMOVEDIR) < 0)
            error = errno;
        if (error)
            break;
    }
    if (closedir(stream) < 0 && !error)
        error = errno;
    if (!error && fsync(book->directory) < 0)
        error = errno;
    return error ? failed(error) : 0;
}
