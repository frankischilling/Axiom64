// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/inet.hpp"

namespace ax {
struct Handle;
bool inet_stream(InetSocket*);
void tcp_close(InetSocket*);
void tcp_poll();
void tcp_receive(unsigned index, uint32_t source, uint32_t destination, const void*, size_t);
int tcp_connect(InetSocket*, const InetAddress&);
int64_t tcp_connect_result(InetSocket*);
int tcp_listen(InetSocket*, int backlog);
int64_t tcp_accept(Task&, Handle*, uint64_t address, uint64_t length, unsigned flags);
int tcp_address(Task&, InetSocket*, bool peer, uint64_t address, uint64_t length);
int64_t tcp_read(InetSocket*, void*, size_t, bool peek = false, size_t offset = 0);
int64_t tcp_write(InetSocket*, const void*, size_t);
bool tcp_ready(InetSocket*, bool write);
uint32_t tcp_events(InetSocket*);
int tcp_shutdown(InetSocket*, unsigned);
unsigned tcp_shutdown_state(InetSocket*);
size_t tcp_available(InetSocket*);
int tcp_error(InetSocket*, bool clear);
void tcp_failed(InetSocket*, int error);
void tcp_limits(InetSocket*);
bool tcp_option(InetSocket*, unsigned option, int& value, bool set, int& error);
} // namespace ax
