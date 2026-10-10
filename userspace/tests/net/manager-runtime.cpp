// SPDX-License-Identifier: GPL-3.0-or-later
// Use the actual private runtime lifecycle with real Client and saved Store.
#define AXIOM64_MANAGER_RUNTIME_TEST
#include "../../net/manager/runtime.cpp"
#include <stdlib.h>

namespace ax::net {
namespace {
struct RuntimeTests {
    static bool hint(const char* root, const char* scenario) {
        char saved[512], runtime[512], resolver[512], target[512];
        snprintf(saved, sizeof(saved), "%s/%s", root, scenario);
        snprintf(runtime, sizeof(runtime), "%s/runtime", root);
        snprintf(resolver, sizeof(resolver), "%s/resolver", root);
        snprintf(target, sizeof(target), "%s/resolv.conf", root);
        Manager manager({runtime, saved, resolver, target});
        auto& entry = manager.entries_[1];
        entry.interface.index = 2;
        strcpy(entry.interface.name, "eth1");
        const unsigned char mac[]{0x52, 0x54, 0, 0x12, 0x34, 0x11};
        memcpy(entry.interface.identity.mac, mac, sizeof(mac));
        strcpy(entry.interface.identity.hostname, "manager-link");
        constexpr uint32_t address = 0x0a170228;
        bool passed = manager.saved_.write_hint("eth1", entry.interface.identity, address) == 0;
        const bool accepted = strcmp(scenario, "unaccepted") != 0;
        entry.installed = accepted;
        entry.active = true;
        // The captured failure withdraws on carrier loss before receive sees EIO.
        if (!strcmp(scenario, "carrier-first"))
            passed &= manager.withdraw(entry, false) == 0;
        manager.retire(entry);
        uint32_t retained = 0;
        passed &= manager.saved_.read_hint("eth1", entry.interface.identity, retained) == 0 &&
                  retained == address;
        bool invalidated = !strcmp(scenario, "invalidated");
        if (invalidated) {
            dhcp::Action forget;
            forget.operation = dhcp::Operation::forget;
            passed &= manager.execute(entry, forget) == 0;
        }
        // A fresh failed-interface retry has no accepted lease in its Client.
        entry.client = dhcp::Client(entry.interface.identity);
        entry.client.advance({dhcp::Input::start, nullptr, 0, address}, manager.now_, 1);
        entry.client.advance({dhcp::Input::link_down}, manager.now_, 1);
        entry.active = true;
        entry.stop_sent = false;
        unsigned budget = 2;
        manager.stop(entry, budget);
        uint32_t result = 0;
        int error = manager.saved_.read_hint("eth1", entry.interface.identity, result);
        passed &= accepted && !invalidated ? !error && result == address : error == ENOENT;
        printf("MANAGER_RUNTIME_HINT_%s scenario=%s saved_error=%d hint=%08x\n",
               passed ? "PASS" : "FAIL", scenario, error, result);
        passed &= manager.saved_.forget_hint("eth1") == 0;
        passed &= rmdir(saved) == 0;
        return passed;
    }
};
} // namespace

int runtime_tests(const char* root) {
    bool passed = true;
    const char* scenarios[]{"carrier-first", "eio-first", "unaccepted", "invalidated"};
    for (const char* scenario : scenarios)
        passed &= RuntimeTests::hint(root, scenario);
    if (passed)
        puts("MANAGER_RUNTIME_PASS carrier_and_EIO_order accepted_hint unaccepted_hint "
             "invalidation");
    return passed ? 0 : 1;
}
} // namespace ax::net

int main() {
    char temporary[] = "/tmp/axiom64-manager-runtime-XXXXXX";
    if (!mkdtemp(temporary))
        return 2;
    int result = ax::net::runtime_tests(temporary);
    return rmdir(temporary) == 0 ? result : 3;
}
