// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/inet.hpp"
#include "net/inet6.hpp"
#include "net/tcp/address.hpp"

namespace ax::ip6 {
struct ErrorQuote;
}

namespace ax {
constexpr unsigned tcp_time_wait_count = 1024;
struct Handle;
bool inet_stream(InetSocket*);
uint64_t tcp_generation(const InetSocket*);
// A cancelled write consumes an old diagnostic only while there is no successor.
int tcp_cancelled_write_error(InetSocket*);
bool tcp_port_busy(uint32_t local, uint16_t port, unsigned index, bool reuse);
bool tcp_port_busy(const tcp::Binding&, uint16_t port, bool reuse);
bool tcp_ipv6(const InetSocket*);
int tcp6_import(Task&, uint64_t pointer, uint32_t length, Inet6Address&, bool connecting);
int64_t tcp6_syscall(Task&, const Frame&);
void tcp_close(InetSocket*);
void tcp_poll();
void tcp_receive(unsigned index, uint32_t source, uint32_t destination, const void*, size_t);
void tcp_icmp_error(unsigned index, const uint8_t*, size_t);
void tcp6_icmp_error(unsigned index, const ip6::ErrorQuote&);
// Refresh a trusted current path; true retires an oversized failed copied packet.
bool tcp6_path_mtu(InetSocket*, size_t failed_packet_bytes = 0);
int tcp_connect(InetSocket*, const InetAddress&);
int tcp6_connect(InetSocket*, const Inet6Address&);
void tcp_receive(unsigned index, const ip6::Address& source, const ip6::Address& destination,
                 const void*, size_t);
int64_t tcp_connect_result(InetSocket*);
int tcp_listen(InetSocket*, int backlog);
int64_t tcp_accept(Task&, Handle*, uint64_t address, uint64_t length, unsigned flags,
                   int reserved_fd);
int tcp_address(Task&, InetSocket*, bool peer, uint64_t address, uint64_t length);
int64_t tcp_read(InetSocket*, void*, size_t, bool peek = false, size_t offset = 0);
// Check stream errors and send capacity before copying user bytes; consumes a pending error.
int tcp_write_check(InetSocket*);
int64_t tcp_write(InetSocket*, const void*, size_t, bool flush = true);
bool tcp_ready(InetSocket*, bool write);
uint32_t tcp_events(InetSocket*);
int tcp_shutdown(InetSocket*, unsigned);
unsigned tcp_shutdown_state(InetSocket*);
size_t tcp_available(InetSocket*);
int tcp_error(InetSocket*, bool clear);
int tcp_so_error(InetSocket*, bool clear);
void tcp_failed(InetSocket*, int error, unsigned failed_index = 0);
void tcp_limits(InetSocket*);
bool tcp_option(InetSocket*, unsigned option, int& value, bool set, int& error);
} // namespace ax
