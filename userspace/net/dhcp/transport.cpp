// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/dhcp/transport.hpp"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace ax::dhcp {
namespace {
int control_socket() {
    return socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
}

bool unicast(uint32_t address) {
    unsigned first = address >> 24;
    return first && first != 127 && first < 224;
}
} // namespace

int query_interface(unsigned index, Interface& output) {
    int fd = control_socket();
    if (fd < 0)
        return errno;
    Interface information;
    ifreq request{};
    request.ifr_ifindex = index;
    int error = 0;
    if (ioctl(fd, SIOCGIFNAME, &request) < 0)
        error = errno;
    else {
        memcpy(information.name, request.ifr_name, sizeof(information.name));
        information.name[15] = 0;
        information.index = index;
        if (ioctl(fd, SIOCGIFHWADDR, &request) < 0)
            error = errno;
        else if (request.ifr_hwaddr.sa_family != 1)
            error = EAFNOSUPPORT;
        else {
            memcpy(information.identity.mac, request.ifr_hwaddr.sa_data, 6);
            memcpy(information.identity.hostname, "axiom64", 8);
            if (ioctl(fd, SIOCGIFFLAGS, &request) < 0)
                error = errno;
            else {
                information.up = request.ifr_flags & IFF_UP;
                information.carrier = request.ifr_flags & IFF_RUNNING;
            }
        }
    }
    if (::close(fd) < 0 && !error)
        error = errno;
    if (!error)
        output = information;
    return error;
}

int query_address(const char* interface, uint32_t& address, uint32_t& mask) {
    if (strnlen(interface, 16) == 16)
        return EINVAL;
    int fd = control_socket();
    if (fd < 0)
        return errno;
    ifreq request{};
    memcpy(request.ifr_name, interface, strlen(interface) + 1);
    int error = 0;
    uint32_t found_address = 0, found_mask = 0;
    if (ioctl(fd, SIOCGIFADDR, &request) < 0) {
        if (errno != EADDRNOTAVAIL)
            error = errno;
    } else {
        sockaddr_in endpoint;
        memcpy(&endpoint, &request.ifr_addr, sizeof(endpoint));
        found_address = ntohl(endpoint.sin_addr.s_addr);
        if (ioctl(fd, SIOCGIFNETMASK, &request) < 0)
            error = errno;
        else {
            memcpy(&endpoint, &request.ifr_netmask, sizeof(endpoint));
            found_mask = ntohl(endpoint.sin_addr.s_addr);
        }
    }
    if (::close(fd) < 0 && !error)
        error = errno;
    if (!error) {
        address = found_address;
        mask = found_mask;
    }
    return error;
}

Transport::~Transport() {
    close();
}

void Transport::close() {
    const int descriptors[]{unicast_, broadcast_, packet_, control_};
    for (int fd : descriptors)
        if (fd >= 0)
            ::close(fd);
    control_ = packet_ = broadcast_ = unicast_ = -1;
    address_ = 0;
    local_count_ = 0;
}

int Transport::udp(uint32_t address) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);
    if (fd < 0)
        return -errno;
    int one = 1;
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(68);
    endpoint.sin_addr.s_addr = htonl(address);
    int error = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface_.name, strlen(interface_.name) + 1) <
            0 ||
        bind(fd, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) < 0)
        error = errno;
    if (error) {
        ::close(fd);
        return -error;
    }
    return fd;
}

int Transport::open(const Interface& information) {
    close();
    interface_ = information;
    if (!information.index || information.index > 8 || !information.name[0] ||
        strnlen(information.name, 16) == 16)
        return EINVAL;
    control_ = control_socket();
    if (control_ < 0)
        return errno;
    ifreq request{};
    memcpy(request.ifr_name, information.name, sizeof(request.ifr_name));
    int error = 0;
    if (ioctl(control_, SIOCGIFFLAGS, &request) < 0)
        error = errno;
    else if (!(request.ifr_flags & IFF_UP)) {
        request.ifr_flags |= IFF_UP;
        if (ioctl(control_, SIOCSIFFLAGS, &request) < 0)
            error = errno;
    }
    if (!error) {
        packet_ = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(3));
        if (packet_ < 0)
            error = errno;
        else {
            sockaddr_ll endpoint{};
            endpoint.sll_family = AF_PACKET;
            endpoint.sll_protocol = htons(3);
            endpoint.sll_ifindex = information.index;
            int one = 1;
            if (bind(packet_, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) < 0 ||
                setsockopt(packet_, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one)) < 0)
                error = errno;
        }
    }
    if (!error) {
        int fd = udp(0);
        if (fd < 0)
            error = -fd;
        else
            broadcast_ = fd;
    }
    if (error) {
        close();
        return error;
    }
    for (unsigned index = 1; index <= 8; index++) {
        Interface local;
        if (!query_interface(index, local))
            memcpy(local_macs_[local_count_++], local.identity.mac, 6);
    }
    return 0;
}

int Transport::configured(uint32_t address) {
    if (address == address_)
        return 0;
    if (unicast_ >= 0) {
        ::close(unicast_);
        unicast_ = -1;
    }
    address_ = 0;
    if (!address)
        return 0;
    if (!unicast(address))
        return EINVAL;
    int fd = udp(address);
    if (fd < 0)
        return -fd;
    unicast_ = fd;
    address_ = address;
    return 0;
}

int Transport::transmit(const Action& action) {
    uint8_t bytes[1518];
    size_t size = 0;
    ssize_t sent = -1;
    if (action.operation == Operation::probe || action.operation == Operation::announce) {
        size = encode_arp(interface_.identity, action.lease.address,
                          action.operation == Operation::announce, bytes, sizeof(bytes));
        if (size)
            sent = send(packet_, bytes, size, MSG_DONTWAIT);
    } else if (action.operation == Operation::transmit) {
        if (memcmp(action.request.identity.mac, interface_.identity.mac, 6))
            return EINVAL;
        if (action.raw) {
            const uint8_t broadcast[]{255, 255, 255, 255, 255, 255};
            if (action.destination != 0xffffffff)
                return EOPNOTSUPP;
            size =
                encode_frame(action.request, action.destination, broadcast, bytes, sizeof(bytes));
            if (size)
                sent = send(packet_, bytes, size, MSG_DONTWAIT);
        } else {
            if (!address_ || action.request.address != address_)
                return EADDRNOTAVAIL;
            size = encode_message(action.request, bytes, sizeof(bytes));
            sockaddr_in destination{};
            destination.sin_family = AF_INET;
            destination.sin_port = htons(67);
            destination.sin_addr.s_addr = htonl(action.destination);
            if (size)
                sent = sendto(unicast_, bytes, size, MSG_DONTWAIT,
                              reinterpret_cast<sockaddr*>(&destination), sizeof(destination));
        }
    }
    if (!size)
        return EINVAL;
    return sent < 0 ? errno : size_t(sent) == size ? 0 : EIO;
}

int Transport::receive(uint32_t transaction, uint32_t candidate, bool probing, Reply& output,
                       Received& received) {
    received = Received::empty;
    const int descriptors[]{packet_, broadcast_, unicast_};
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        unsigned lane = cursor_++ % 3;
        int fd = descriptors[lane];
        if (fd < 0)
            continue;
        uint8_t bytes[1518];
        sockaddr_storage source{};
        socklen_t source_length = sizeof(source);
        ssize_t size = recvfrom(fd, bytes, sizeof(bytes), MSG_DONTWAIT | MSG_TRUNC,
                                reinterpret_cast<sockaddr*>(&source), &source_length);
        if (size < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            return errno;
        }
        received = Received::ignored;
        if (size_t(size) > sizeof(bytes))
            return 0;
        Reply reply;
        if (!lane) {
            sockaddr_ll link;
            memcpy(&link, &source, sizeof(link));
            if (source_length < 18 || link.sll_family != AF_PACKET ||
                unsigned(link.sll_ifindex) != interface_.index ||
                link.sll_pkttype == PACKET_OUTGOING || size < 14)
                return 0;
            for (size_t i = 0; i < local_count_; i++)
                if (!memcmp(bytes + 6, local_macs_[i], 6))
                    return 0;
            if (conflicting_arp(bytes, size_t(size), interface_.identity, candidate, probing))
                received = Received::conflict;
            else if (!address_ &&
                     decode_frame(bytes, size_t(size), interface_.identity, transaction, reply)) {
                received = Received::reply;
                output = reply;
            }
        } else if (address_) {
            sockaddr_in peer;
            memcpy(&peer, &source, sizeof(peer));
            if (source_length != sizeof(peer) || peer.sin_family != AF_INET ||
                peer.sin_port != htons(67) || !unicast(ntohl(peer.sin_addr.s_addr)) ||
                !decode_message(bytes, size_t(size), interface_.identity, transaction, reply) ||
                (lane == 2 && reply.type == Type::nak))
                return 0;
            // Specific binding wins unicast demultiplexing. The wildcard socket
            // supplies broadcast metadata; its duplicate ACK is harmless.
            reply.source = ntohl(peer.sin_addr.s_addr);
            reply.destination = lane == 1 ? 0xffffffff : address_;
            received = Received::reply;
            output = reply;
        }
        return 0;
    }
    return 0;
}

int Transport::carrier(bool& output) {
    ifreq request{};
    memcpy(request.ifr_name, interface_.name, sizeof(request.ifr_name));
    if (ioctl(control_, SIOCGIFFLAGS, &request) < 0)
        return errno;
    output = (request.ifr_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING);
    return 0;
}

size_t Transport::descriptors(pollfd* output, size_t capacity) const {
    size_t count = 0;
    const int descriptors[]{packet_, broadcast_, unicast_};
    for (int fd : descriptors)
        if (fd >= 0 && count < capacity)
            output[count++] = {fd, POLLIN, 0};
    return count;
}
} // namespace ax::dhcp
