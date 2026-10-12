// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "record.h"
#include "password.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(uid_t) == 4 && sizeof(gid_t) == 4, "Linux account ID widths");

static int failed(int error) {
    errno = error;
    return -1;
}

int account_name_valid(const char* value) {
    if (!value)
        return 0;
    size_t length = strnlen(value, ACCOUNT_NAME_MAX + 1);
    if (!length || length > ACCOUNT_NAME_MAX ||
        !((value[0] >= 'a' && value[0] <= 'z') || value[0] == '_'))
        return 0;
    for (size_t i = 1; i < length; i++)
        if (!((value[i] >= 'a' && value[i] <= 'z') || (value[i] >= '0' && value[i] <= '9') ||
              value[i] == '_' || value[i] == '-'))
            return 0;
    return 1;
}

int account_id_parse(const char* value, uint32_t* output) {
    if (!value || !*value || !output)
        return failed(EINVAL);
    uint32_t result = 0;
    for (size_t i = 0; value[i]; i++) {
        if (value[i] < '0' || value[i] > '9')
            return failed(EINVAL);
        unsigned digit = (unsigned)(value[i] - '0');
        if (result > (UINT32_MAX - 1 - digit) / 10)
            return failed(ERANGE);
        result = result * 10 + digit;
    }
    *output = result;
    return 0;
}

static int text_valid(const char* value, size_t limit) {
    if (!value || strnlen(value, limit + 1) > limit)
        return 0;
    for (size_t i = 0; value[i]; i++)
        if ((unsigned char)value[i] < 32 || (unsigned char)value[i] == 127 || value[i] == ':')
            return 0;
    return 1;
}

static int path_valid(const char* value, int empty) {
    if (!text_valid(value, 4095))
        return 0;
    size_t length = strlen(value);
    if (!length)
        return empty;
    if (value[0] != '/')
        return 0;
    for (size_t start = 1, end; start < length; start = end + 1) {
        end = start;
        while (end < length && value[end] != '/')
            end++;
        size_t size = end - start;
        if (!size || size > 255 || (size == 1 && value[start] == '.') ||
            (size == 2 && value[start] == '.' && value[start + 1] == '.'))
            return 0;
    }
    return length == 1 || value[length - 1] != '/';
}

int account_record_user_valid(const struct account_user* user) {
    if (!user || !account_name_valid(user->name) || user->uid == (uid_t)-1 ||
        user->gid == (gid_t)-1 || ((!user->uid) != (!strcmp(user->name, "root"))) ||
        (!user->uid && user->gid) || !text_valid(user->password, ACCOUNT_PASSWORD_HASH_SIZE - 1) ||
        !text_valid(user->gecos, 255) || !path_valid(user->home, 0) || !path_valid(user->shell, 1))
        return failed(EINVAL);
    for (unsigned i = 0; i < 6; i++)
        if (user->age[i] < -1)
            return failed(EINVAL);
    if (user->age[1] >= 0 && user->age[2] >= 0 && user->age[1] > user->age[2])
        return failed(EINVAL);
    return 0;
}

static void free_text(const char* value) {
    if (value) {
        explicit_bzero((void*)value, strlen(value) + 1);
        free((void*)value);
    }
}

void account_record_free_user(struct account_user* user) {
    free_text(user->name);
    free_text(user->password);
    free_text(user->gecos);
    free_text(user->home);
    free_text(user->shell);
    explicit_bzero(user, sizeof(*user));
}

void account_record_free_group(struct account_group* group) {
    free_text(group->name);
    free((void*)group->members);
    memset(group, 0, sizeof(*group));
}

int account_record_validate(const struct account_database* db) {
    if (!db || !db->user_count || !db->group_count)
        return failed(EUCLEAN);
    const struct account_user* root = account_database_uid(db, 0);
    const struct account_group* group = account_database_gid(db, 0);
    if (!root || !group || strcmp(root->name, "root") || strcmp(group->name, "root"))
        return failed(EUCLEAN);
    for (size_t i = 0; i < db->user_count; i++) {
        const struct account_user* user = &db->users[i];
        if (account_record_user_valid(user) < 0 || !account_database_gid(db, user->gid))
            return failed(EUCLEAN);
        for (size_t j = 0; j < i; j++)
            if (db->users[j].uid == user->uid || !strcmp(db->users[j].name, user->name))
                return failed(EUCLEAN);
    }
    for (size_t i = 0; i < db->group_count; i++) {
        const struct account_group* value = &db->groups[i];
        if (!account_name_valid(value->name) || value->gid == (gid_t)-1 ||
            ((!value->gid) != (!strcmp(value->name, "root"))))
            return failed(EUCLEAN);
        for (size_t j = 0; j < i; j++)
            if (db->groups[j].gid == value->gid || !strcmp(db->groups[j].name, value->name))
                return failed(EUCLEAN);
        for (size_t j = 0; j < value->member_count; j++) {
            if (!account_database_uid(db, value->members[j]))
                return failed(EUCLEAN);
            for (size_t k = 0; k < j; k++)
                if (value->members[k] == value->members[j])
                    return failed(EUCLEAN);
        }
    }
    return 0;
}

static int fields(char* line, char** output, unsigned expected) {
    output[0] = line;
    unsigned count = 1;
    for (char* at = line; *at; at++)
        if (*at == ':') {
            *at = 0;
            if (count == expected)
                return failed(EUCLEAN);
            output[count++] = at + 1;
        }
    return count == expected ? 0 : failed(EUCLEAN);
}

static char* line(char** cursor) {
    if (!**cursor)
        return NULL;
    char* result = *cursor;
    char* end = strchr(result, '\n');
    if (!end)
        return NULL;
    *end = 0;
    *cursor = end + 1;
    return result;
}

static int age_parse(const char* value, int64_t* output) {
    if (!*value) {
        *output = -1;
        return 0;
    }
    int64_t result = 0;
    for (size_t i = 0; value[i]; i++) {
        if (value[i] < '0' || value[i] > '9')
            return failed(EUCLEAN);
        unsigned digit = (unsigned)(value[i] - '0');
        if (result > (INT64_MAX - digit) / 10)
            return failed(EUCLEAN);
        result = result * 10 + digit;
    }
    *output = result;
    return 0;
}

struct deferred {
    char* name;
    char* members;
};

int account_record_decode(const struct account_content contents[ACCOUNT_FILE_COUNT],
                          struct account_database* db) {
    char* copies[ACCOUNT_FILE_COUNT] = {0};
    struct deferred* deferred = NULL;
    size_t count = 0;
    unsigned char* seen = NULL;
    int error = 0;
    for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++) {
        if (!contents[i].data || !contents[i].size || contents[i].size > ACCOUNT_FILE_LIMIT ||
            contents[i].data[contents[i].size - 1] != '\n' ||
            memchr(contents[i].data, 0, contents[i].size)) {
            error = EUCLEAN;
            goto done;
        }
        copies[i] = malloc(contents[i].size + 1);
        if (!copies[i]) {
            error = ENOMEM;
            goto done;
        }
        memcpy(copies[i], contents[i].data, contents[i].size);
        copies[i][contents[i].size] = 0;
    }
    errno = 0;
    char *cursor = copies[ACCOUNT_GROUP], *record;
    while ((record = line(&cursor))) {
        char* value[4];
        uint32_t gid;
        if (fields(record, value, 4) < 0 || strcmp(value[1], "x") ||
            account_id_parse(value[2], &gid) < 0)
            goto invalid;
        struct account_group group = {value[0], gid, NULL, 0};
        if (account_database_put_group(db, NULL, &group) < 0)
            goto invalid;
        struct deferred* resized = realloc(deferred, (count + 1) * sizeof(*deferred));
        if (!resized) {
            error = ENOMEM;
            goto done;
        }
        deferred = resized;
        deferred[count++] = (struct deferred){value[0], value[3]};
    }
    cursor = copies[ACCOUNT_PASSWD];
    while ((record = line(&cursor))) {
        char* value[7];
        uint32_t uid, gid;
        if (fields(record, value, 7) < 0 || strcmp(value[1], "x") ||
            account_id_parse(value[2], &uid) < 0 || account_id_parse(value[3], &gid) < 0)
            goto invalid;
        struct account_user user = {value[0], "!", value[4], value[5],
                                    value[6], uid, gid,      {-1, -1, -1, -1, -1, -1}};
        if (account_database_put_user(db, NULL, &user) < 0)
            goto invalid;
    }
    seen = calloc(db->user_count ? db->user_count : 1, 1);
    if (!seen) {
        error = ENOMEM;
        goto done;
    }
    cursor = copies[ACCOUNT_SHADOW];
    while ((record = line(&cursor))) {
        char* value[9];
        if (fields(record, value, 9) < 0 || *value[8])
            goto invalid;
        const struct account_user* user = account_database_user(db, value[0]);
        if (!user)
            goto invalid;
        size_t index = (size_t)(user - db->users);
        if (seen[index])
            goto invalid;
        struct account_user updated = *user;
        updated.password = value[1];
        for (unsigned i = 0; i < 6; i++)
            if (age_parse(value[i + 2], &updated.age[i]) < 0)
                goto invalid;
        if (account_database_put_user(db, user->name, &updated) < 0)
            goto invalid;
        seen[index] = 1;
    }
    for (size_t i = 0; i < db->user_count; i++)
        if (!seen[i])
            goto invalid;
    for (size_t i = 0; i < count; i++) {
        char* member = deferred[i].members;
        while (*member) {
            char* comma = strchr(member, ',');
            if (comma)
                *comma = 0;
            const struct account_user* user = account_database_user(db, member);
            const struct account_group* group = account_database_group(db, deferred[i].name);
            if (!user || !group)
                goto invalid;
            for (size_t j = 0; j < group->member_count; j++)
                if (group->members[j] == user->uid)
                    goto invalid;
            if (account_database_member(db, group->name, user->name, 1) < 0)
                goto invalid;
            if (!comma)
                break;
            member = comma + 1;
            if (!*member)
                goto invalid;
        }
    }
    if (account_record_validate(db) < 0)
        goto invalid;
    goto done;
invalid:
    error = errno == ENOMEM ? ENOMEM : EUCLEAN;
done:
    free(seen);
    free(deferred);
    for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++)
        if (copies[i]) {
            explicit_bzero(copies[i], contents[i].size + 1);
            free(copies[i]);
        }
    return error ? failed(error) : 0;
}

struct buffer {
    char* data;
    size_t size, capacity;
};

static int append(struct buffer* buffer, const char* value) {
    size_t size = strlen(value);
    if (size > ACCOUNT_FILE_LIMIT - buffer->size)
        return failed(EFBIG);
    size_t wanted = buffer->size + size + 1;
    if (wanted > buffer->capacity) {
        size_t capacity = buffer->capacity ? buffer->capacity : 256;
        while (capacity < wanted)
            capacity =
                capacity < (ACCOUNT_FILE_LIMIT + 1) / 2 ? capacity * 2 : ACCOUNT_FILE_LIMIT + 1;
        char* resized = malloc(capacity);
        if (!resized)
            return failed(ENOMEM);
        if (buffer->data) {
            memcpy(resized, buffer->data, buffer->size + 1);
            explicit_bzero(buffer->data, buffer->size + 1);
            free(buffer->data);
        }
        buffer->data = resized;
        buffer->capacity = capacity;
    }
    memcpy(buffer->data + buffer->size, value, size + 1);
    buffer->size += size;
    return 0;
}

static int number(struct buffer* buffer, int64_t value) {
    if (value < 0)
        return 0;
    char text[24];
    snprintf(text, sizeof(text), "%" PRId64, value);
    return append(buffer, text);
}

void account_record_free_files(struct account_content files[ACCOUNT_FILE_COUNT]) {
    for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++)
        if (files[i].data) {
            explicit_bzero((void*)files[i].data, files[i].size + 1);
            free((void*)files[i].data);
            files[i] = (struct account_content){0};
        }
}

int account_record_encode(const struct account_database* db,
                          struct account_content files[ACCOUNT_FILE_COUNT]) {
    struct buffer buffers[ACCOUNT_FILE_COUNT] = {0};
    int error = 0;
    struct buffer *passwd = &buffers[ACCOUNT_PASSWD], *group = &buffers[ACCOUNT_GROUP],
                  *shadow = &buffers[ACCOUNT_SHADOW];
    for (size_t i = 0; i < db->user_count && !error; i++) {
        const struct account_user* user = &db->users[i];
        if (append(passwd, user->name) < 0 || append(passwd, ":x:") < 0 ||
            number(passwd, user->uid) < 0 || append(passwd, ":") < 0 ||
            number(passwd, user->gid) < 0 || append(passwd, ":") < 0 ||
            append(passwd, user->gecos) < 0 || append(passwd, ":") < 0 ||
            append(passwd, user->home) < 0 || append(passwd, ":") < 0 ||
            append(passwd, user->shell) < 0 || append(passwd, "\n") < 0 ||
            append(shadow, user->name) < 0 || append(shadow, ":") < 0 ||
            append(shadow, user->password) < 0)
            error = errno;
        for (unsigned j = 0; j < 6 && !error; j++)
            if (append(shadow, ":") < 0 || number(shadow, user->age[j]) < 0)
                error = errno;
        if (!error && append(shadow, ":\n") < 0)
            error = errno;
    }
    for (size_t i = 0; i < db->group_count && !error; i++) {
        const struct account_group* value = &db->groups[i];
        if (append(group, value->name) < 0 || append(group, ":x:") < 0 ||
            number(group, value->gid) < 0 || append(group, ":") < 0)
            error = errno;
        for (size_t j = 0; j < value->member_count && !error; j++) {
            const struct account_user* user = account_database_uid(db, value->members[j]);
            if (!user) {
                error = EUCLEAN;
                break;
            }
            if ((j && append(group, ",") < 0) || append(group, user->name) < 0)
                error = errno;
        }
        if (!error && append(group, "\n") < 0)
            error = errno;
    }
    for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++)
        files[i] = (struct account_content){buffers[i].data, buffers[i].size};
    if (error) {
        account_record_free_files(files);
        return failed(error);
    }
    return 0;
}
