// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/manager/runtime.hpp"
#include "net/manager/ownership.hpp"
#include "net/manager/static.hpp"
#include "net/config/configuration.hpp"
#include "net/config/resolver.hpp"
#include "net/dhcp/transport.hpp"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

namespace ax::net {
namespace {
uint64_t after(uint64_t now, uint64_t duration) {
    return duration > dhcp::never - now ? dhcp::never : now + duration;
}

int milliseconds(uint64_t& output) {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return errno;
    if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000 ||
        uint64_t(now.tv_sec) > (UINT64_MAX - 999) / 1000)
        return EOVERFLOW;
    output = uint64_t(now.tv_sec) * 1000 + uint64_t(now.tv_nsec) / 1000000;
    return 0;
}

const char* method(Method value) {
    return value == Method::fixed ? "static" : value == Method::disabled ? "disabled" : "dhcp";
}

struct Entry {
    dhcp::Interface interface;
    Profile profile;
    dhcp::Transport transport;
    Configuration configuration;
    dhcp::Client client{dhcp::Identity{}};
    StaticAddress fixed;
    uint64_t retry_at = 0, carrier_at = 0;
    unsigned generation = 0;
    int last_error = 0, cleanup_error = 0;
    bool active = false, disabled = false, configuration_open = false;
    bool carrier = false, installed = false, stop_sent = false;
    // A fresh Client during a failed-interface retry has no accepted lease.
    // Preserve the previous accepted hint until install or explicit invalidation.
    bool interrupted_hint = false;

    bool is_fixed() const {
        return profile.method == Method::fixed;
    }

    uint64_t deadline() const {
        return is_fixed() ? fixed.deadline() : client.deadline();
    }

    bool finished() const {
        return deadline() == dhcp::never &&
               (is_fixed() ? fixed.phase() == StaticPhase::stopped && !fixed.configured()
                           : client.phase() == dhcp::Phase::stopped && !client.configured());
    }
};

class Manager {
  public:
    explicit Manager(const ManagerPaths& paths)
        : paths_(paths), runtime_(paths.runtime), saved_(paths.saved),
          resolver_store_(paths.resolver_runtime) {
    }

    int run(const volatile sig_atomic_t& stopping);

  private:
    ManagerPaths paths_;
    Store runtime_, saved_, resolver_store_;
    Ownership ownership_;
    Resolver resolver_;
    Entry entries_[8];
    uint64_t now_ = 0;
    uint32_t random_ = 0;
    int fatal_ = 0;
    bool resolver_open_ = false;
    bool sample();
    void report(Entry&, const char* operation, int error);
    int withdraw(Entry&, bool forget);
    void retire(Entry&, bool forget = false);
    void prepare(Entry&, unsigned index);
    dhcp::Action advance(Entry&, const dhcp::Event&);
    int execute(Entry&, const dhcp::Action&);
    void actions(Entry&, dhcp::Action, unsigned& budget);
    void event(Entry&, const dhcp::Event&, unsigned& budget);
    void receive(Entry&, unsigned& budget);
    int finish(int error);
};

bool Manager::sample() {
    int error = milliseconds(now_);
    if (!error) {
        ssize_t count;
        do {
            count = getrandom(&random_, sizeof(random_), GRND_NONBLOCK);
        } while (count < 0 && errno == EINTR);
        if (count != ssize_t(sizeof(random_)))
            error = count < 0 ? errno : EIO;
    }
    if (error && !fatal_)
        fatal_ = error;
    return !error;
}

void Manager::report(Entry& entry, const char* operation, int error) {
    if (error && error != entry.last_error)
        fprintf(stderr, "NETWORK_MANAGER_ERROR index=%u operation=%s errno=%d\n",
                entry.interface.index, operation, error);
    entry.last_error = error;
}

int Manager::withdraw(Entry& entry, bool forget) {
    int error = entry.configuration_open ? entry.configuration.withdraw() : 0;
    int result = entry.transport.configured(0);
    if (!error)
        error = result;
    if (resolver_open_) {
        result = resolver_.withdraw(entry.interface.index);
        if (!error)
            error = result;
    }
    if (forget && !entry.is_fixed()) {
        result = saved_.forget_hint(entry.interface.name);
        if (!result)
            entry.interrupted_hint = false;
        if (!error)
            error = result;
    }
    if (!error && entry.installed) {
        printf("NETWORK_MANAGER_WITHDRAWN index=%u\n", entry.interface.index);
        entry.installed = false;
    }
    entry.cleanup_error = error;
    return error;
}

void Manager::retire(Entry& entry, bool forget) {
    if (!forget && !entry.is_fixed() && entry.installed)
        entry.interrupted_hint = true;
    int error = withdraw(entry, forget);
    int result = entry.transport.close();
    if (!error)
        error = result;
    result = entry.configuration.close();
    if (!error)
        error = result;
    entry.configuration_open = entry.active = false;
    entry.cleanup_error = error;
    report(entry, "cleanup", error);
    if (sample())
        entry.retry_at = after(now_, 1000);
}

dhcp::Action Manager::advance(Entry& entry, const dhcp::Event& input) {
    if (!sample())
        return {};
    return entry.is_fixed() ? entry.fixed.advance(input, now_, random_)
                            : entry.client.advance(input, now_, random_);
}

void Manager::prepare(Entry& entry, unsigned index) {
    dhcp::Interface information;
    int error = dhcp::query_interface(index, information);
    if (sample())
        entry.retry_at = after(now_, 1000);
    if (error) {
        if (error != ENODEV && error != ENOENT && error != EAFNOSUPPORT) {
            entry.interface.index = index;
            report(entry, "discover", error);
        }
        return;
    }
    entry.interface = information;
    entry.profile = {};
    error = entry.configuration.open(entry.interface, runtime_);
    if (error) {
        int closed = entry.configuration.close();
        entry.cleanup_error = closed ? closed : error;
        report(entry, "recover", error);
        return;
    }
    entry.configuration_open = true;
    entry.cleanup_error = 0;
    error = saved_.read_profile(information.name, entry.profile);
    if (error == ENOENT)
        error = 0;
    if (error) {
        report(entry, "profile", error);
        retire(entry);
        return;
    }
    memcpy(entry.interface.identity.hostname, entry.profile.hostname,
           sizeof(entry.interface.identity.hostname));
    printf("NETWORK_MANAGER_INTERFACE index=%u name=%s method=%s\n", index, information.name,
           method(entry.profile.method));
    if (entry.profile.method == Method::disabled) {
        entry.disabled = true;
        entry.configuration_open = false;
        entry.cleanup_error = entry.configuration.close();
        report(entry, "close", entry.cleanup_error);
        return;
    }
    uint32_t hint = 0;
    if (!entry.is_fixed()) {
        error = saved_.read_hint(information.name, entry.interface.identity, hint);
        if (error == EINVAL || error == ESTALE) {
            error = saved_.forget_hint(information.name);
            if (!error)
                entry.interrupted_hint = false;
        } else if (error == ENOENT) {
            entry.interrupted_hint = false;
            error = 0;
        }
    }
    if (!error)
        error = entry.transport.open(entry.interface);
    if (!error)
        error = entry.transport.carrier(entry.carrier);
    if (error) {
        report(entry, "open", error);
        retire(entry);
        return;
    }
    entry.active = true;
    entry.stop_sent = false;
    entry.client = dhcp::Client(entry.interface.identity);
    entry.fixed = StaticAddress(entry.profile);
    dhcp::Event start;
    start.input = dhcp::Input::start;
    start.hint = hint;
    dhcp::Action action = advance(entry, start);
    unsigned budget = 2;
    if (!entry.carrier)
        event(entry, {dhcp::Input::link_down}, budget);
    else
        actions(entry, action, budget);
    entry.carrier_at = after(now_, 250);
}

int Manager::execute(Entry& entry, const dhcp::Action& action) {
    using dhcp::Operation;
    if (action.operation == Operation::transmit || action.operation == Operation::probe ||
        action.operation == Operation::announce)
        return entry.transport.transmit(action);
    if (action.operation == Operation::forget) {
        int error = saved_.forget_hint(entry.interface.name);
        if (!error)
            entry.interrupted_hint = false;
        return error;
    }
    if (action.operation == Operation::withdraw)
        return withdraw(entry, action.forget_hint);
    if (action.operation != Operation::install)
        return EINVAL;
    uint64_t checked;
    int error = milliseconds(checked);
    if (!error && action.lease.expires_at != dhcp::never && checked >= action.lease.expires_at)
        error = ETIMEDOUT;
    if (!error)
        error = entry.configuration.apply(action.lease.address, action.lease.parameters,
                                          entry.profile.metric, entry.is_fixed() ? 4 : 16);
    if (!error)
        error = entry.transport.configured(action.lease.address);
    if (!error)
        error =
            resolver_.update(entry.interface.index, action.lease.parameters, entry.profile.metric);
    if (!error && !entry.is_fixed())
        error =
            saved_.write_hint(entry.interface.name, entry.interface.identity, action.lease.address);
    if (error) {
        int cleanup = withdraw(entry, !entry.is_fixed());
        if (cleanup)
            report(entry, "rollback", cleanup);
        return cleanup ? cleanup : error;
    }
    entry.installed = true;
    entry.interrupted_hint = false;
    printf("NETWORK_MANAGER_BOUND index=%u method=%s address=%08x generation=%u\n",
           entry.interface.index, method(entry.profile.method), action.lease.address,
           ++entry.generation);
    if (resolver_.limited())
        printf("NETWORK_MANAGER_RESOLVER_LIMITED index=%u\n", entry.interface.index);
    return 0;
}

void Manager::actions(Entry& entry, dhcp::Action action, unsigned& budget) {
    while (!fatal_ && entry.active && budget && action.operation != dhcp::Operation::none) {
        budget--;
        int error = execute(entry, action);
        report(entry, "action", error);
        dhcp::Event completion;
        completion.input = dhcp::Input::completion;
        completion.token = action.token;
        completion.success = !error;
        bool wire = action.operation == dhcp::Operation::transmit ||
                    action.operation == dhcp::Operation::probe ||
                    action.operation == dhcp::Operation::announce;
        action = advance(entry, completion);
        if (error == ENODEV || (wire && (error == EIO || error == ENETDOWN))) {
            retire(entry);
            break;
        }
    }
    // The state machine retains an unexecuted action and retries it after 100 ms.
    // Each completion rereads the clock, including after all synchronous writes.
}

void Manager::event(Entry& entry, const dhcp::Event& input, unsigned& budget) {
    actions(entry, advance(entry, input), budget);
}

void Manager::receive(Entry& entry, unsigned& budget) {
    for (unsigned work = 0; entry.active && work < 4 && !fatal_; work++) {
        dhcp::Reply reply;
        dhcp::Received received;
        uint32_t address =
            entry.is_fixed() ? entry.fixed.conflict_address() : entry.client.conflict_address();
        bool probing = entry.is_fixed() ? entry.fixed.probing()
                                        : entry.client.phase() == dhcp::Phase::probing ||
                                              entry.client.phase() == dhcp::Phase::installing;
        int error = entry.transport.receive(entry.is_fixed() ? 0 : entry.client.transaction(),
                                            address, probing, reply, received);
        if (error) {
            report(entry, "receive", error);
            retire(entry);
            return;
        }
        if (received == dhcp::Received::empty)
            return;
        if (received == dhcp::Received::conflict)
            event(entry, {dhcp::Input::conflict}, budget);
        else if (received == dhcp::Received::reply && !entry.is_fixed())
            event(entry, {dhcp::Input::reply, &reply}, budget);
    }
}

int Manager::finish(int error) {
    for (auto& entry : entries_) {
        if (entry.configuration_open || entry.active)
            retire(entry);
        if (!error)
            error = entry.cleanup_error;
    }
    resolver_.close();
    resolver_open_ = false;
    if (!error)
        error = fatal_;
    int closed = ownership_.close();
    return error ? error : closed;
}

int Manager::run(const volatile sig_atomic_t& stopping) {
    int error = ownership_.open(paths_.runtime);
    if (error)
        return error;
    error = resolver_.open(resolver_store_, paths_.resolver_target);
    if (error)
        return finish(error);
    resolver_open_ = true;
    for (unsigned index = 1; index <= 8 && !fatal_; index++)
        prepare(entries_[index - 1], index);
    unsigned active = 0;
    for (const auto& entry : entries_)
        active += entry.active;
    printf("NETWORK_MANAGER_READY pid=%ld interfaces=%u\n", long(getpid()), active);
    bool shutting = false;
    uint64_t shutdown_until = dhcp::never;
    unsigned cursor = 0;
    while (!fatal_ && sample()) {
        if (stopping && !shutting) {
            shutting = true;
            shutdown_until = after(now_, 2000);
        }
        for (unsigned offset = 0; offset < 8 && !fatal_; offset++) {
            auto& entry = entries_[(cursor + offset) % 8];
            if (!entry.active) {
                if (!shutting && !entry.disabled && now_ >= entry.retry_at)
                    prepare(entry, unsigned(&entry - entries_) + 1);
                continue;
            }
            unsigned budget = 2;
            if (shutting && !entry.stop_sent) {
                entry.stop_sent = true;
                if (entry.interrupted_hint && !entry.is_fixed() && !entry.client.configured()) {
                    retire(entry);
                    continue;
                }
                event(entry, {dhcp::Input::stop}, budget);
            }
            if (now_ >= entry.carrier_at && entry.active) {
                bool carrier;
                error = entry.transport.carrier(carrier);
                if (error) {
                    report(entry, "carrier", error);
                    retire(entry);
                    continue;
                }
                if (!sample())
                    break;
                entry.carrier_at = after(now_, 250);
                if (carrier != entry.carrier) {
                    entry.carrier = carrier;
                    printf("NETWORK_MANAGER_LINK index=%u up=%u\n", entry.interface.index,
                           unsigned(carrier));
                    event(entry, {carrier ? dhcp::Input::link_up : dhcp::Input::link_down}, budget);
                }
            }
            // Drain bounded input before the next install/probe timer action.
            if (entry.active)
                receive(entry, budget);
            if (entry.active)
                event(entry, {}, budget);
        }
        cursor = (cursor + 1) % 8;
        if (!sample())
            break;
        if (shutting) {
            bool done = true;
            for (const auto& entry : entries_)
                done &= !entry.active || entry.finished();
            if (done || now_ >= shutdown_until)
                break;
        }
        pollfd descriptors[24];
        size_t count = 0;
        uint64_t due = after(now_, 250);
        if (shutting && shutdown_until < due)
            due = shutdown_until;
        for (const auto& entry : entries_) {
            uint64_t next = entry.active ? entry.deadline() : entry.retry_at;
            if ((entry.active || (!entry.disabled && !shutting)) && next < due)
                due = next;
            if (entry.active)
                count += entry.transport.descriptors(descriptors + count, 24 - count);
        }
        int timeout = due <= now_ ? 0 : int(due - now_);
        if (poll(descriptors, count, timeout) < 0 && errno != EINTR)
            fatal_ = errno;
    }
    int result = fatal_;
    if (shutting)
        for (const auto& entry : entries_)
            if (!result && entry.active && !entry.finished())
                result = entry.last_error ? entry.last_error : ETIMEDOUT;
    return finish(result);
}
} // namespace

int run_manager(const ManagerPaths& paths, const volatile sig_atomic_t& stopping) {
    if (!paths.runtime || !paths.saved || !paths.resolver_runtime || !paths.resolver_target)
        return EINVAL;
    Manager manager(paths);
    return manager.run(stopping);
}
} // namespace ax::net
