// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    const char* test=getenv("AXIOM64_TEST");
    if(test && *test=='1') execl("/bin/busybox","busybox","sh","/etc/boot-test.sh",(char*)0);
    else {
        puts("Axiom64 console. Type commands at the ash prompt.");
        execl("/bin/busybox","busybox","sh","-i",(char*)0);
    }
    perror("init: exec"); return 1;
}
