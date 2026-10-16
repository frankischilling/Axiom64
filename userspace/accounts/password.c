// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "password.h"
#include <crypt.h>
#include <errno.h>
#include <string.h>
#include <sys/random.h>

_Static_assert(CRYPT_OUTPUT_SIZE == ACCOUNT_PASSWORD_HASH_SIZE, "password hash buffer contract");
_Static_assert(CRYPT_MAX_PASSPHRASE_SIZE > ACCOUNT_PASSWORD_MAX, "password input contract");

void account_password_clear(void* memory, size_t size) {
    explicit_bzero(memory, size);
}

static int input(const char* password) {
    if (!password) {
        errno = EINVAL;
        return -1;
    }
    if (strnlen(password, ACCOUNT_PASSWORD_MAX + 1) > ACCOUNT_PASSWORD_MAX) {
        errno = E2BIG;
        return -1;
    }
    return 0;
}

int account_password_hash(const char* password, char output[ACCOUNT_PASSWORD_HASH_SIZE]) {
    if (!output) {
        errno = EINVAL;
        return -1;
    }
    output[0] = 0;
    if (input(password) < 0)
        return -1;
    unsigned char entropy[32] = {0};
    char salt[CRYPT_GENSALT_OUTPUT_SIZE] = {0};
    struct crypt_data state = {0};
    int error = 0;
    for (size_t offset = 0; offset < sizeof(entropy);) {
        ssize_t count = getrandom(entropy + offset, sizeof(entropy) - offset, 0);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            error = errno;
            goto done;
        }
        if (!count) {
            error = EIO;
            goto done;
        }
        offset += (size_t)count;
    }
    // The maintained library selects its default yescrypt work factor.
    errno = 0;
    if (!crypt_gensalt_rn("$y$", 0, (const char*)entropy, sizeof(entropy), salt, sizeof(salt))) {
        error = errno ? errno : EINVAL;
        goto done;
    }
    errno = 0;
    char* result = crypt_r(password, salt, &state);
    if (!result || result[0] == '*' || strncmp(result, "$y$", 3)) {
        error = errno ? errno : EINVAL;
        goto done;
    }
    size_t length = strnlen(result, ACCOUNT_PASSWORD_HASH_SIZE);
    if (length == ACCOUNT_PASSWORD_HASH_SIZE) {
        error = EOVERFLOW;
        goto done;
    }
    memcpy(output, result, length + 1);
done:
    account_password_clear(entropy, sizeof(entropy));
    account_password_clear(salt, sizeof(salt));
    account_password_clear(&state, sizeof(state));
    if (error) {
        account_password_clear(output, ACCOUNT_PASSWORD_HASH_SIZE);
        errno = error;
        return -1;
    }
    return 0;
}

int account_password_verify(const char* password, const char* encoded) {
    if (input(password) < 0)
        return -1;
    if (!encoded || !encoded[0] || encoded[0] == '!' || encoded[0] == '*')
        return 0;
    size_t length = strnlen(encoded, ACCOUNT_PASSWORD_HASH_SIZE);
    if (length == ACCOUNT_PASSWORD_HASH_SIZE) {
        errno = EOVERFLOW;
        return -1;
    }
    struct crypt_data state = {0};
    errno = 0;
    char* result = crypt_r(password, encoded, &state);
    int error = errno;
    int operational_error = (!result || result[0] == '*') && error == ENOMEM;
    int matches = 0;
    if (result && result[0] != '*' && strnlen(result, ACCOUNT_PASSWORD_HASH_SIZE) == length) {
        volatile unsigned difference = 0;
        for (size_t index = 0; index < length; ++index)
            difference |= (unsigned char)result[index] ^ (unsigned char)encoded[index];
        matches = difference == 0;
    }
    account_password_clear(&state, sizeof(state));
    if (operational_error) {
        errno = error;
        return -1;
    }
    return matches;
}
