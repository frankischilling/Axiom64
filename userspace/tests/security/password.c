// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "accounts/password.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

static unsigned observations;

static int expect(int condition, const char* name) {
    ++observations;
    if (!condition) {
        printf("PASSWORD_LIBRARY_FAIL case=%s error=%d\n", name, errno);
        return 0;
    }
    printf("PASSWORD_LIBRARY_OBSERVATION case=%s passed=1\n", name);
    return 1;
}

int main(void) {
    char first[ACCOUNT_PASSWORD_HASH_SIZE], second[ACCOUNT_PASSWORD_HASH_SIZE];
    const char* password = "fictional-local-account-fixture";
    int valid = 1;
    valid &= expect(account_password_hash(password, first) == 0, "initialized-hash");
    valid &= expect(!strncmp(first, "$y$", 3), "maintained-yescrypt");
    valid &= expect(account_password_verify(password, first) == 1, "correct-password");
    valid &= expect(account_password_verify("wrong-local-fixture", first) == 0, "wrong-password");
    valid &= expect(account_password_verify("", first) == 0, "empty-password-denied");
    valid &= expect(account_password_hash(password, second) == 0, "independent-hash");
    valid &= expect(strcmp(first, second) != 0, "fresh-initialized-salts");
    valid &= expect(account_password_verify(password, second) == 1, "second-password");
    for (unsigned index = 0; index < 5; ++index) {
        const char* denied[] = {"", "!", "!!", "*", "!$y$locked"};
        valid &= expect(account_password_verify(password, denied[index]) == 0, "locked-or-missing");
    }
    valid &= expect(account_password_verify(password, "malformed-setting") == 0, "malformed-hash");
    char maximum[ACCOUNT_PASSWORD_MAX + 1];
    memset(maximum, 'm', sizeof(maximum) - 1);
    maximum[sizeof(maximum) - 1] = 0;
    valid &= expect(account_password_hash(maximum, second) == 0, "full-password-length");
    valid &= expect(account_password_verify(maximum, second) == 1, "full-password-verified");
    maximum[sizeof(maximum) - 2] = 'n';
    valid &= expect(account_password_verify(maximum, second) == 0, "no-password-truncation");
    char too_long[ACCOUNT_PASSWORD_MAX + 2];
    memset(too_long, 'z', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = 0;
    errno = 0;
    valid &=
        expect(account_password_hash(too_long, second) == -1 && errno == E2BIG && second[0] == 0,
               "oversized-password");
    char oversized_hash[ACCOUNT_PASSWORD_HASH_SIZE + 1];
    memset(oversized_hash, 'q', sizeof(oversized_hash) - 1);
    oversized_hash[sizeof(oversized_hash) - 1] = 0;
    errno = 0;
    valid &= expect(account_password_verify(password, oversized_hash) == -1 && errno == EOVERFLOW,
                    "oversized-hash");
    errno = 0;
    valid &= expect(account_password_hash(NULL, second) == -1 && errno == EINVAL && second[0] == 0,
                    "missing-password-input");
    valid &= expect(account_password_verify(password, NULL) == 0, "missing-shadow-hash");
    account_password_clear(first, sizeof(first));
    account_password_clear(second, sizeof(second));
    unsigned remaining = 0;
    for (unsigned index = 0; index < sizeof(first); ++index)
        remaining |= (unsigned char)first[index] | (unsigned char)second[index];
    valid &= expect(!remaining, "explicit-sensitive-buffer-clear");
    if (!valid)
        return 1;
    printf("PASSWORD_LIBRARY_PASS observations=%u\n", observations);
    return 0;
}
