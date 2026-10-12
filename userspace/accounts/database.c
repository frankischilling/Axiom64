// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "record.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int failed(int error) {
    errno = error;
    return -1;
}

const struct account_user* account_database_user(const struct account_database* db,
                                                 const char* name) {
    if (db && name)
        for (size_t i = 0; i < db->user_count; i++)
            if (!strcmp(db->users[i].name, name))
                return &db->users[i];
    return NULL;
}

const struct account_user* account_database_uid(const struct account_database* db, uid_t uid) {
    if (db)
        for (size_t i = 0; i < db->user_count; i++)
            if (db->users[i].uid == uid)
                return &db->users[i];
    return NULL;
}

const struct account_group* account_database_group(const struct account_database* db,
                                                   const char* name) {
    if (db && name)
        for (size_t i = 0; i < db->group_count; i++)
            if (!strcmp(db->groups[i].name, name))
                return &db->groups[i];
    return NULL;
}

const struct account_group* account_database_gid(const struct account_database* db, gid_t gid) {
    if (db)
        for (size_t i = 0; i < db->group_count; i++)
            if (db->groups[i].gid == gid)
                return &db->groups[i];
    return NULL;
}

void account_database_end(struct account_database* db) {
    if (!db)
        return;
    for (size_t i = 0; i < db->user_count; i++)
        account_record_free_user(&db->users[i]);
    for (size_t i = 0; i < db->group_count; i++)
        account_record_free_group(&db->groups[i]);
    free(db->users);
    free(db->groups);
    account_store_end(db->store);
    explicit_bzero(db, sizeof(*db));
    free(db);
}

int account_database_fresh(const struct account_database* db) {
    return db && db->fresh;
}

const char* account_database_revision(const struct account_database* db) {
    return db ? account_store_revision(db->store) : NULL;
}

int account_database_begin(const char* path, int provision, struct account_database** output) {
    if (!output)
        return failed(EINVAL);
    *output = NULL;
    struct account_database* db = calloc(1, sizeof(*db));
    if (!db)
        return -1;
    int error = account_store_begin(path, provision, &db->store) < 0 ? errno : 0;
    const struct account_content* contents = error ? NULL : account_store_snapshot(db->store);
    if (!error && contents) {
        if (account_record_decode(contents, db) < 0)
            error = errno;
    } else if (!error) {
        db->fresh = 1;
        struct account_group group = {"root", 0, NULL, 0};
        struct account_user user = {"root",    "!", "root", "/root",
                                    "/bin/sh", 0,   0,      {-1, -1, -1, -1, -1, -1}};
        if (account_database_put_group(db, NULL, &group) < 0 ||
            account_database_put_user(db, NULL, &user) < 0)
            error = errno;
    }
    if (error) {
        account_database_end(db);
        return failed(error);
    }
    *output = db;
    return 0;
}

static int copy_user(const struct account_user* input, struct account_user* output) {
    *output = *input;
    output->name = strdup(input->name);
    output->password = strdup(input->password);
    output->gecos = strdup(input->gecos);
    output->home = strdup(input->home);
    output->shell = strdup(input->shell);
    if (!output->name || !output->password || !output->gecos || !output->home || !output->shell) {
        account_record_free_user(output);
        return failed(ENOMEM);
    }
    return 0;
}

int account_database_put_user(struct account_database* db, const char* previous,
                              const struct account_user* input) {
    if (!db || !input || account_record_user_valid(input) < 0)
        return failed(EINVAL);
    const struct account_user* old = previous ? account_database_user(db, previous) : NULL;
    if (previous && !old)
        return failed(ENOENT);
    if (old && !old->uid && (input->uid || input->gid || strcmp(input->name, "root")))
        return failed(EPERM);
    const struct account_user* by_name = account_database_user(db, input->name);
    const struct account_user* by_id = account_database_uid(db, input->uid);
    if ((by_name && by_name != old) || (by_id && by_id != old))
        return failed(EEXIST);
    if (!account_database_gid(db, input->gid))
        return failed(ENOENT);
    size_t index = old ? (size_t)(old - db->users) : db->user_count;
    uid_t old_uid = old ? old->uid : input->uid;
    struct account_user copied;
    if (copy_user(input, &copied) < 0)
        return -1;
    if (!old) {
        if (db->user_count >= ACCOUNT_FILE_LIMIT / 8) {
            account_record_free_user(&copied);
            return failed(EFBIG);
        }
        struct account_user* users = realloc(db->users, (db->user_count + 1) * sizeof(*users));
        if (!users) {
            account_record_free_user(&copied);
            return failed(ENOMEM);
        }
        db->users = users;
        db->user_count++;
    } else {
        account_record_free_user(&db->users[index]);
        for (size_t i = 0; i < db->group_count; i++) {
            uid_t* members = (uid_t*)db->groups[i].members;
            for (size_t j = 0; j < db->groups[i].member_count; j++)
                if (members[j] == old_uid)
                    members[j] = copied.uid;
        }
    }
    db->users[index] = copied;
    return 0;
}

int account_database_put_group(struct account_database* db, const char* previous,
                               const struct account_group* input) {
    if (!db || !input || !account_name_valid(input->name) || input->gid == (gid_t)-1 ||
        (!input->gid != !strcmp(input->name, "root")) || (input->member_count && !input->members) ||
        input->member_count > ACCOUNT_FILE_LIMIT / 2)
        return failed(EINVAL);
    const struct account_group* old = previous ? account_database_group(db, previous) : NULL;
    if (previous && !old)
        return failed(ENOENT);
    if (old && !old->gid && (input->gid || strcmp(input->name, "root")))
        return failed(EPERM);
    const struct account_group* by_name = account_database_group(db, input->name);
    const struct account_group* by_id = account_database_gid(db, input->gid);
    if ((by_name && by_name != old) || (by_id && by_id != old))
        return failed(EEXIST);
    for (size_t i = 0; i < input->member_count; i++) {
        if (!account_database_uid(db, input->members[i]))
            return failed(ENOENT);
        for (size_t j = 0; j < i; j++)
            if (input->members[j] == input->members[i])
                return failed(EEXIST);
    }
    size_t index = old ? (size_t)(old - db->groups) : db->group_count;
    gid_t old_gid = old ? old->gid : input->gid;
    struct account_group copied = {strdup(input->name), input->gid, NULL, input->member_count};
    if (input->member_count) {
        uid_t* members = malloc(input->member_count * sizeof(*members));
        if (members)
            memcpy(members, input->members, input->member_count * sizeof(*members));
        copied.members = members;
    }
    if (!copied.name || (copied.member_count && !copied.members)) {
        account_record_free_group(&copied);
        return failed(ENOMEM);
    }
    if (!old) {
        if (db->group_count >= ACCOUNT_FILE_LIMIT / 5) {
            account_record_free_group(&copied);
            return failed(EFBIG);
        }
        struct account_group* groups = realloc(db->groups, (db->group_count + 1) * sizeof(*groups));
        if (!groups) {
            account_record_free_group(&copied);
            return failed(ENOMEM);
        }
        db->groups = groups;
        db->group_count++;
    } else {
        account_record_free_group(&db->groups[index]);
        for (size_t i = 0; i < db->user_count; i++)
            if (db->users[i].gid == old_gid)
                db->users[i].gid = copied.gid;
    }
    db->groups[index] = copied;
    return 0;
}

int account_database_remove_user(struct account_database* db, const char* name) {
    const struct account_user* user = account_database_user(db, name);
    if (!user)
        return failed(ENOENT);
    if (!user->uid)
        return failed(EPERM);
    uid_t uid = user->uid;
    size_t index = (size_t)(user - db->users);
    account_record_free_user(&db->users[index]);
    memmove(db->users + index, db->users + index + 1,
            (db->user_count - index - 1) * sizeof(*db->users));
    db->user_count--;
    for (size_t i = 0; i < db->group_count; i++) {
        struct account_group* group = &db->groups[i];
        uid_t* members = (uid_t*)group->members;
        for (size_t j = 0; j < group->member_count;)
            if (members[j] == uid) {
                memmove(members + j, members + j + 1,
                        (group->member_count - j - 1) * sizeof(*members));
                group->member_count--;
            } else
                j++;
    }
    return 0;
}

int account_database_remove_group(struct account_database* db, const char* name) {
    const struct account_group* group = account_database_group(db, name);
    if (!group)
        return failed(ENOENT);
    if (!group->gid)
        return failed(EPERM);
    for (size_t i = 0; i < db->user_count; i++)
        if (db->users[i].gid == group->gid)
            return failed(EBUSY);
    size_t index = (size_t)(group - db->groups);
    account_record_free_group(&db->groups[index]);
    memmove(db->groups + index, db->groups + index + 1,
            (db->group_count - index - 1) * sizeof(*db->groups));
    db->group_count--;
    return 0;
}

int account_database_member(struct account_database* db, const char* group_name,
                            const char* user_name, int present) {
    const struct account_group* group = account_database_group(db, group_name);
    const struct account_user* user = account_database_user(db, user_name);
    if (!group || !user)
        return failed(ENOENT);
    if (present != 0 && present != 1)
        return failed(EINVAL);
    size_t index = (size_t)(group - db->groups);
    struct account_group* target = &db->groups[index];
    uid_t* members = (uid_t*)target->members;
    for (size_t i = 0; i < target->member_count; i++)
        if (members[i] == user->uid) {
            if (!present) {
                memmove(members + i, members + i + 1,
                        (target->member_count - i - 1) * sizeof(*members));
                target->member_count--;
            }
            return 0;
        }
    if (!present)
        return 0;
    if (target->member_count >= ACCOUNT_FILE_LIMIT / 2)
        return failed(EFBIG);
    members = realloc(members, (target->member_count + 1) * sizeof(*members));
    if (!members)
        return failed(ENOMEM);
    members[target->member_count++] = user->uid;
    target->members = members;
    return 0;
}

int account_database_groups(const struct account_database* db, uid_t uid, gid_t* output,
                            size_t capacity, size_t* size) {
    const struct account_user* user = account_database_uid(db, uid);
    if (!user)
        return failed(ENOENT);
    if (!size || (!output && capacity))
        return failed(EINVAL);
    size_t count = 1;
    if (capacity)
        output[0] = user->gid;
    for (size_t i = 0; i < db->group_count; i++) {
        const struct account_group* group = &db->groups[i];
        if (group->gid == user->gid)
            continue;
        for (size_t j = 0; j < group->member_count; j++)
            if (group->members[j] == uid) {
                if (count < capacity)
                    output[count] = group->gid;
                count++;
                break;
            }
    }
    *size = count;
    return count <= capacity ? 0 : failed(ERANGE);
}

int account_database_commit(struct account_database* db, int* published) {
    if (!db || !published)
        return failed(EINVAL);
    *published = 0;
    if (account_record_validate(db) < 0)
        return -1;
    struct account_content files[ACCOUNT_FILE_COUNT] = {0};
    int result = account_record_encode(db, files);
    if (!result)
        result = account_store_commit(db->store, files, published);
    int error = errno;
    account_record_free_files(files);
    return result < 0 ? failed(error) : 0;
}
