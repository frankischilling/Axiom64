// SPDX-License-Identifier: GPL-3.0-or-later
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int* values = malloc(100 * sizeof(int));
    if (!values)
        return 1;
    int sum = 0;
    for (int i = 0; i < 100; i++) {
        values[i] = i;
        sum += values[i];
    }
    free(values);
    if (sum != 4950)
        return 2;
    puts("NATIVE_C_PASS");
    return 0;
}
