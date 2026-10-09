// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/manager/runtime.hpp"
#include <errno.h>
#include <stdio.h>
#include <string.h>

namespace {
volatile sig_atomic_t stopping;

void stop(int) {
    stopping = 1;
}
} // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    ax::net::ManagerPaths paths;
    for (int i = 1; i < argc; i += 2) {
        const char** destination = !strcmp(argv[i], "--runtime") ? &paths.runtime
                                   : !strcmp(argv[i], "--saved") ? &paths.saved
                                   : !strcmp(argv[i], "--resolver-runtime")
                                       ? &paths.resolver_runtime
                                   : !strcmp(argv[i], "--resolver-target") ? &paths.resolver_target
                                                                           : nullptr;
        if (!destination || i + 1 >= argc) {
            fprintf(stderr, "usage: network-manager [--runtime DIR] [--saved DIR] "
                            "[--resolver-runtime DIR] [--resolver-target FILE]\n");
            return 64;
        }
        *destination = argv[i + 1];
    }
    struct sigaction action{};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, nullptr) < 0 || sigaction(SIGINT, &action, nullptr) < 0) {
        perror("network-manager: signals");
        return 1;
    }
    int error = ax::net::run_manager(paths, stopping);
    if (error)
        fprintf(stderr, "network-manager: %s (%d)\n", strerror(error), error);
    printf("NETWORK_MANAGER_EXIT status=%d\n", error ? 1 : 0);
    return error ? 1 : 0;
}
