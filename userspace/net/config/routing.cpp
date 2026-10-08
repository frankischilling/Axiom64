// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/config/routing.hpp"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

namespace ax::net {
namespace {
int milliseconds(uint64_t& value) {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return errno;
    if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000 ||
        uint64_t(now.tv_sec) > (UINT64_MAX - 999) / 1000)
        return EOVERFLOW;
    value = uint64_t(now.tv_sec) * 1000 + uint64_t(now.tv_nsec) / 1000000;
    return 0;
}

int reply_deadline(uint64_t& value) {
    int error = milliseconds(value);
    if (error)
        return error;
    if (value > UINT64_MAX - 1000)
        return EOVERFLOW;
    value += 1000;
    return 0;
}

unsigned prefix(uint32_t mask) {
    unsigned count = 0;
    while (mask & 0x80000000) {
        count++;
        mask <<= 1;
    }
    return count;
}

void attribute(uint8_t* packet, size_t& size, unsigned type, uint32_t value) {
    rtattr field{};
    field.rta_type = type;
    field.rta_len = 8;
    memcpy(packet + size, &field, sizeof(field));
    memcpy(packet + size + sizeof(field), &value, 4);
    size += 8;
}
} // namespace

Routing::~Routing() {
    close();
}

void Routing::close() {
    if (fd_ >= 0)
        ::close(fd_);
    fd_ = -1;
    port_ = 0;
}

int Routing::open() {
    close();
    fd_ = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd_ < 0)
        return errno;
    int one = 1;
    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    socklen_t length = sizeof(address);
    int error = 0;
    if (setsockopt(fd_, SOL_NETLINK, NETLINK_CAP_ACK, &one, sizeof(one)) < 0 ||
        setsockopt(fd_, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &one, sizeof(one)) < 0 ||
        bind(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 ||
        getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &length) < 0)
        error = errno;
    else if (length != sizeof(address) || address.nl_family != AF_NETLINK || !address.nl_pid ||
             address.nl_groups)
        error = EPROTO;
    if (error)
        close();
    else
        port_ = address.nl_pid;
    return error;
}

int Routing::send(void* packet, size_t size, uint32_t& sequence) {
    if (fd_ < 0)
        return EBADF;
    nlmsghdr header;
    memcpy(&header, packet, sizeof(header));
    header.nlmsg_len = size;
    if (!++sequence_)
        sequence_++;
    header.nlmsg_seq = sequence = sequence_;
    header.nlmsg_pid = port_;
    memcpy(packet, &header, sizeof(header));
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    ssize_t sent = sendto(fd_, packet, size, MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&kernel),
                          sizeof(kernel));
    return sent < 0 ? errno : size_t(sent) == size ? 0 : EIO;
}

int Routing::receive(void* packet, size_t capacity, size_t& size, uint64_t deadline) {
    for (;;) {
        uint64_t now;
        if (int error = milliseconds(now))
            return error;
        if (now >= deadline)
            return ETIMEDOUT;
        pollfd ready{fd_, POLLIN, 0};
        int timeout = deadline - now > 1000 ? 1000 : int(deadline - now);
        int result = poll(&ready, 1, timeout);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            return errno;
        }
        if (!result)
            continue;
        if (ready.revents & (POLLERR | POLLHUP | POLLNVAL))
            return EIO;
        sockaddr_nl sender{};
        socklen_t length = sizeof(sender);
        ssize_t received = recvfrom(fd_, packet, capacity, MSG_DONTWAIT | MSG_TRUNC,
                                    reinterpret_cast<sockaddr*>(&sender), &length);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            return errno;
        }
        if (size_t(received) > capacity || length != sizeof(sender) ||
            sender.nl_family != AF_NETLINK || sender.nl_pid || sender.nl_groups)
            return EPROTO;
        size = received;
        return 0;
    }
}

int Routing::change(const Route& route, bool remove) {
    uint32_t host = ~route.mask;
    if ((host & (host + 1)) || (route.destination & route.mask) != route.destination ||
        !route.index || !route.metric || !route.protocol ||
        (route.gateway ? route.scope != RT_SCOPE_UNIVERSE : route.scope != RT_SCOPE_LINK))
        return EINVAL;
    uint8_t packet[128]{};
    nlmsghdr header{};
    header.nlmsg_type = remove ? RTM_DELROUTE : RTM_NEWROUTE;
    header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (remove ? 0 : NLM_F_CREATE | NLM_F_EXCL);
    rtmsg body{};
    body.rtm_family = AF_INET;
    body.rtm_dst_len = prefix(route.mask);
    body.rtm_table = RT_TABLE_MAIN;
    body.rtm_protocol = route.protocol;
    body.rtm_scope = route.scope;
    body.rtm_type = RTN_UNICAST;
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &body, sizeof(body));
    size_t size = sizeof(header) + sizeof(body);
    if (route.mask)
        attribute(packet, size, RTA_DST, htonl(route.destination));
    if (route.gateway)
        attribute(packet, size, RTA_GATEWAY, htonl(route.gateway));
    attribute(packet, size, RTA_PRIORITY, route.metric);
    attribute(packet, size, RTA_OIF, route.index);
    uint32_t sequence;
    uint64_t deadline;
    int error = reply_deadline(deadline);
    if (error)
        return error;
    error = send(packet, size, sequence);
    if (error)
        return error;
    memcpy(&header, packet, sizeof(header));
    uint8_t reply[128];
    error = receive(reply, sizeof(reply), size, deadline);
    if (error) {
        close();
        return error;
    }
    nlmsghdr response, echo;
    int status;
    if (size != 36) {
        close();
        return EPROTO;
    }
    memcpy(&response, reply, sizeof(response));
    memcpy(&status, reply + sizeof(response), 4);
    memcpy(&echo, reply + sizeof(response) + 4, sizeof(echo));
    if (response.nlmsg_len != size || response.nlmsg_type != NLMSG_ERROR ||
        response.nlmsg_seq != sequence || response.nlmsg_pid != port_ ||
        response.nlmsg_flags != NLM_F_CAPPED || status > 0 || status < -4095 ||
        memcmp(&echo, &header, sizeof(header))) {
        close();
        return EPROTO;
    }
    return -status;
}

int Routing::list(Route* output, size_t capacity, size_t& count, unsigned index, uint8_t protocol) {
    if (capacity > 64 || (capacity && !output))
        return EINVAL;
    uint8_t request[64]{};
    nlmsghdr header{};
    header.nlmsg_type = RTM_GETROUTE;
    header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    rtmsg body{};
    body.rtm_family = AF_INET;
    body.rtm_table = RT_TABLE_MAIN;
    body.rtm_protocol = protocol;
    memcpy(request, &header, sizeof(header));
    memcpy(request + sizeof(header), &body, sizeof(body));
    size_t size = sizeof(header) + sizeof(body);
    if (index)
        attribute(request, size, RTA_OIF, index);
    uint32_t sequence;
    uint64_t deadline;
    int error = reply_deadline(deadline);
    if (error)
        return error;
    error = send(request, size, sequence);
    if (error)
        return error;
    Route saved[64];
    size_t copied = 0;
    bool overflow = false;
    for (unsigned packets = 0; packets < 16; packets++) {
        uint8_t reply[16384];
        error = receive(reply, sizeof(reply), size, deadline);
        if (error)
            break;
        for (size_t at = 0; at < size;) {
            if (size - at < sizeof(header)) {
                error = EPROTO;
                break;
            }
            memcpy(&header, reply + at, sizeof(header));
            if (header.nlmsg_len < 16 || header.nlmsg_len > size - at ||
                header.nlmsg_seq != sequence || header.nlmsg_pid != port_) {
                error = EPROTO;
                break;
            }
            if (header.nlmsg_type == NLMSG_DONE && header.nlmsg_len == 20) {
                int status;
                memcpy(&status, reply + at + 16, 4);
                if (status > 0 || status < -4095 || (header.nlmsg_flags & NLM_F_DUMP_INTR))
                    error = EPROTO;
                else if (status)
                    error = -status;
                else if (overflow || copied > capacity)
                    return ENOSPC;
                else {
                    if (copied)
                        memcpy(output, saved, copied * sizeof(Route));
                    count = copied;
                    return 0;
                }
                break;
            }
            if (header.nlmsg_type == NLMSG_ERROR && header.nlmsg_len >= 36) {
                int status;
                memcpy(&status, reply + at + 16, 4);
                error = status < 0 && status >= -4095 ? -status : EPROTO;
                break;
            }
            if (header.nlmsg_type != RTM_NEWROUTE || header.nlmsg_len < 28 ||
                !(header.nlmsg_flags & NLM_F_MULTI) || (header.nlmsg_flags & NLM_F_DUMP_INTR)) {
                error = EPROTO;
                break;
            }
            memcpy(&body, reply + at + 16, sizeof(body));
            if (body.rtm_family != AF_INET || body.rtm_dst_len > 32 ||
                body.rtm_type != RTN_UNICAST || body.rtm_table != RT_TABLE_MAIN) {
                error = EPROTO;
                break;
            }
            Route value;
            value.mask = body.rtm_dst_len ? UINT32_MAX << (32 - body.rtm_dst_len) : 0;
            value.protocol = body.rtm_protocol;
            value.scope = body.rtm_scope;
            for (size_t field_at = 28; field_at < header.nlmsg_len;) {
                rtattr field;
                if (header.nlmsg_len - field_at < 4) {
                    error = EPROTO;
                    break;
                }
                memcpy(&field, reply + at + field_at, sizeof(field));
                if (field.rta_len < 4 || field.rta_len > header.nlmsg_len - field_at) {
                    error = EPROTO;
                    break;
                }
                if (field.rta_type == RTA_DST || field.rta_type == RTA_GATEWAY ||
                    field.rta_type == RTA_PRIORITY || field.rta_type == RTA_OIF) {
                    if (field.rta_len != 8) {
                        error = EPROTO;
                        break;
                    }
                    uint32_t number;
                    memcpy(&number, reply + at + field_at + 4, 4);
                    if (field.rta_type == RTA_DST)
                        value.destination = ntohl(number);
                    else if (field.rta_type == RTA_GATEWAY)
                        value.gateway = ntohl(number);
                    else if (field.rta_type == RTA_PRIORITY)
                        value.metric = number;
                    else
                        value.index = number;
                }
                field_at += RTA_ALIGN(field.rta_len);
            }
            if (error)
                break;
            if ((index && value.index != index) || (protocol && value.protocol != protocol)) {
                error = EPROTO;
                break;
            }
            if (copied == 64)
                overflow = true;
            else
                saved[copied++] = value;
            at += NLMSG_ALIGN(header.nlmsg_len);
        }
        if (error)
            break;
    }
    close();
    return error ? error : EPROTO;
}
} // namespace ax::net
