// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/manager/static.hpp"
#include <stdio.h>
#include <stdlib.h>

using namespace ax::dhcp;
using ax::net::StaticAddress;
using ax::net::StaticPhase;

static void check(bool value, const char* reason) {
    if (!value) {
        fprintf(stderr, "STATIC_ADDRESS_FAIL %s\n", reason);
        exit(1);
    }
}

static ax::net::Profile profile() {
    ax::net::Profile result;
    result.method = ax::net::Method::fixed;
    result.address = 0x0a1f0128;
    result.parameters.has_mask = true;
    result.parameters.mask = 0xffffff00;
    return result;
}

static Action done(StaticAddress& client, const Action& action, uint64_t now, bool success = true,
                   uint32_t random = 0) {
    check(action.operation != Operation::none && action.token, "checked completion token");
    Event event;
    event.input = Input::completion;
    event.token = action.token;
    event.success = success;
    return client.advance(event, now, random);
}

static Action installation(StaticAddress& client) {
    auto action = client.advance({Input::start}, 0, 0);
    for (uint64_t now = 0; now < 3000; now += 1000) {
        if (now)
            action = client.advance({}, now, 0);
        check(action.operation == Operation::probe && action.lease.address == profile().address,
              "three zero-source ARP probe requests precede installation");
        check(done(client, action, now).operation == Operation::none, "probe wait begins");
    }
    check(client.advance({}, 3999, 0).operation == Operation::none, "last probe waits two seconds");
    action = client.advance({}, 4000, 0);
    check(action.operation == Operation::install, "install after all probes");
    return action;
}

static void bound(StaticAddress& client) {
    auto action = installation(client);
    action = done(client, action, 4000);
    check(action.operation == Operation::announce && client.configured(),
          "successful ownership announces immediately");
    check(done(client, action, 4000).operation == Operation::none, "announcement spacing");
    check(client.advance({}, 5999, 0).operation == Operation::none, "second announcement wait");
    action = client.advance({}, 6000, 0);
    check(action.operation == Operation::announce &&
              done(client, action, 6000).operation == Operation::none &&
              client.phase() == StaticPhase::bound && client.deadline() == never,
          "two announcements produce stable static ownership without a lease timer");
}

int main() {
    StaticAddress invalid;
    check(invalid.advance({Input::start}, 0, 0).operation == Operation::none &&
              invalid.phase() == StaticPhase::stopped,
          "DHCP/default profile cannot enter static acquisition");
    {
        StaticAddress client(profile());
        auto action = client.advance({Input::start}, 0, 1000);
        check(action.operation == Operation::none && client.deadline() == 1000,
              "initial random wait is bounded by one second");
        action = client.advance({}, 1000, 0);
        check(action.operation == Operation::probe, "first probe deadline");
        uint32_t token = action.token;
        check(done(client, action, 1000, false).operation == Operation::none &&
                  client.advance({}, 1099, 0).operation == Operation::none,
              "failed send is not acknowledged or immediately spun");
        action = client.advance({}, 1100, 0);
        check(action.operation == Operation::probe && action.token == token,
              "retry retains the uncompleted action token");
        done(client, action, 1100, true, 1000);
        check(client.deadline() == 3100, "inter-probe random wait reaches two seconds");
    }
    {
        StaticAddress client(profile());
        client.advance({Input::start}, 0, 1000);
        check(client.advance({Input::conflict}, 100, 0).operation == Operation::none &&
                  client.phase() == StaticPhase::conflicted && !client.conflict_address(),
              "conflict during initial wait prevents even the first probe/install");
        client.advance({Input::link_down}, 1000, 0);
        client.advance({Input::link_up}, 2000, 0);
        check(client.advance({}, 60000, 0).operation == Operation::none &&
                  client.phase() == StaticPhase::conflicted,
              "known static conflict survives link changes without DHCP fallback");
    }
    {
        StaticAddress client(profile());
        auto installing = installation(client);
        auto withdrawal = client.advance({Input::conflict}, 4000, 0);
        check(withdrawal.operation == Operation::withdraw && withdrawal.token != installing.token &&
                  !client.configured(),
              "pending installation is withdrawn on conflict");
        done(client, installing, 4000);
        check(client.phase() == StaticPhase::conflicted && !client.configured(),
              "stale successful completion cannot resurrect a conflicting address");
        done(client, withdrawal, 4000);
        check(client.deadline() == never, "conflict blocks repeated acquisition");
    }
    {
        StaticAddress client(profile());
        bound(client);
        auto defense = client.advance({Input::conflict}, 8000, 0);
        check(defense.operation == Operation::announce && client.configured(),
              "first conflict permits one defense");
        done(client, defense, 8000, false);
        auto withdrawal = client.advance({Input::conflict}, 8100, 0);
        check(withdrawal.operation == Operation::withdraw &&
                  client.phase() == StaticPhase::conflicted,
              "second conflict within ten seconds requires relinquishment");
        done(client, defense, 8100);
        done(client, withdrawal, 8100);
        check(!client.configured() && client.advance({}, 100000, 0).operation == Operation::none,
              "failed defense and stale completions do not bypass relinquishment");
    }
    {
        StaticAddress client(profile());
        bound(client);
        auto defense = client.advance({Input::conflict}, 8000, 0);
        done(client, defense, 8000);
        defense = client.advance({Input::conflict}, 18000, 0);
        check(defense.operation == Operation::announce && client.configured(),
              "ten-second boundary permits another defense");
        done(client, defense, 18000);
        auto withdrawal = client.advance({Input::link_down}, 19000, 0);
        check(withdrawal.operation == Operation::withdraw, "lost carrier withdraws ownership");
        done(client, withdrawal, 19000);
        check(!client.configured() && client.phase() == StaticPhase::waiting_link,
              "link withdrawal waits for carrier");
        check(client.advance({Input::link_up}, 20000, 1000).operation == Operation::none &&
                  client.advance({}, 21000, 0).operation == Operation::probe,
              "new link probes again before reinstating a fixed address");
    }
    {
        StaticAddress client(profile());
        auto action = installation(client);
        auto withdrawal = done(client, action, 4000, false);
        check(withdrawal.operation == Operation::withdraw && !client.configured(),
              "failed coordinated install requests cleanup before retry");
        done(client, withdrawal, 4000);
        check(client.advance({}, 4999, 0).operation == Operation::none &&
                  client.advance({}, 5000, 0).operation == Operation::probe,
              "failed installation retries the same fixed method with new probes");
    }
    {
        StaticAddress client(profile());
        auto installing = installation(client);
        auto withdrawal = client.advance({Input::stop}, 4000, 0);
        check(withdrawal.operation == Operation::withdraw, "signal stops pending installation");
        done(client, installing, 4000);
        done(client, withdrawal, 4000);
        check(client.phase() == StaticPhase::stopped && client.deadline() == never &&
                  !client.configured(),
              "checked teardown is complete");
    }
    puts("STATIC_ADDRESS_PASS probes=3 announcements=2 defense=checked conflicts=blocked "
         "teardown=checked");
    return 0;
}
