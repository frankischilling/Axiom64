// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/desktop/dbus-probe.c
 * @brief   Exercise the installed session bus with an activated peer.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Passes a pipe through the bus and verifies the peer writes its payload.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <dbus/dbus.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "DESKTOP_DBUS_FAIL line=%d %s %s\n", __LINE__, #expression,            \
                    error.message ? error.message : "");                                           \
            dbus_error_free(&error);                                                               \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static const char service[] = "org.axiom64.TestPipe";
static const char object[] = "/org/axiom64/TestPipe";
static const char payload[] = "activated peer\n";

static int serve(DBusConnection* connection) {
    DBusError error = DBUS_ERROR_INIT;
    CHECK(dbus_bus_request_name(connection, service, DBUS_NAME_FLAG_DO_NOT_QUEUE, &error) ==
          DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
    DBusMessage* request = NULL;
    for (int tries = 0; tries < 16; tries++) {
        if (!dbus_connection_read_write(connection, 500))
            break;
        request = dbus_connection_pop_message(connection);
        if (!request)
            continue;
        if (dbus_message_is_method_call(request, service, "Write") &&
            dbus_message_has_path(request, object))
            break;
        dbus_message_unref(request);
        request = NULL;
    }
    CHECK(request);
    int pipe;
    struct stat status;
    CHECK(dbus_message_get_args(request, &error, DBUS_TYPE_UNIX_FD, &pipe, DBUS_TYPE_INVALID));
    CHECK(fstat(pipe, &status) == 0 && S_ISFIFO(status.st_mode));
    CHECK(write(pipe, payload, sizeof(payload)) == sizeof(payload) && close(pipe) == 0);
    DBusMessage* reply = dbus_message_new_method_return(request);
    CHECK(reply && dbus_connection_send(connection, reply, NULL));
    dbus_connection_flush(connection);
    dbus_message_unref(reply);
    dbus_message_unref(request);
    return 0;
}

static int call(DBusConnection* connection) {
    DBusError error = DBUS_ERROR_INIT;
    const char* address = getenv("DBUS_SESSION_BUS_ADDRESS");
    CHECK(address && !strncmp(address, "unix:abstract=axiom64-session-", 30));
    CHECK(dbus_connection_can_send_type(connection, DBUS_TYPE_UNIX_FD));
    int pipe[2];
    CHECK(pipe2(pipe, O_NONBLOCK | O_CLOEXEC) == 0);
    DBusMessage* request = dbus_message_new_method_call(service, object, service, "Write");
    CHECK(request &&
          dbus_message_append_args(request, DBUS_TYPE_UNIX_FD, &pipe[1], DBUS_TYPE_INVALID));
    CHECK(close(pipe[1]) == 0);
    DBusMessage* reply =
        dbus_connection_send_with_reply_and_block(connection, request, 7000, &error);
    CHECK(reply);
    dbus_message_unref(reply);
    dbus_message_unref(request);
    char data[sizeof(payload)];
    CHECK(read(pipe[0], data, sizeof(data)) == sizeof(data) &&
          !memcmp(data, payload, sizeof(data)));
    CHECK(close(pipe[0]) == 0);
    printf("DESKTOP_DBUS_PASS uid=%u fd=pipe activation=1 address=%s\n", (unsigned)getuid(),
           address);
    return 0;
}

static int denied(const char* address, int foreign) {
    DBusError error = DBUS_ERROR_INIT;
    if (foreign)
        CHECK(setgroups(0, NULL) == 0 && setresgid(1001, 1001, 1001) == 0 &&
              setresuid(1001, 1001, 1001) == 0);
    DBusConnection* connection = dbus_connection_open_private(address, &error);
    if (foreign) {
        CHECK(connection && !dbus_bus_register(connection, &error));
        dbus_connection_close(connection);
        dbus_connection_unref(connection);
    } else {
        CHECK(!connection && dbus_error_has_name(&error, DBUS_ERROR_NO_SERVER));
    }
    dbus_error_free(&error);
    puts(foreign ? "DESKTOP_DBUS_FOREIGN_DENIED" : "DESKTOP_DBUS_RETIRED_PASS");
    return 0;
}

static int system_bus(void) {
    DBusError error = DBUS_ERROR_INIT;
    CHECK(getuid() == 1000 && geteuid() == 1000);
    const char* socket = "/run/dbus/system_bus_socket";
    DBusConnection* connection = NULL;
    struct stat status;
    for (int attempt = 0; attempt < 70; attempt++) {
        dbus_error_free(&error);
        connection = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        if (connection)
            break;
        usleep(100000);
    }
    CHECK(connection);
    CHECK(lstat(socket, &status) == 0 && S_ISSOCK(status.st_mode) && !status.st_uid);
    dbus_connection_set_exit_on_disconnect(connection, FALSE);
    CHECK(dbus_bus_get_unix_user(connection, DBUS_SERVICE_DBUS, &error) == 81);
    const char* name = dbus_bus_get_unique_name(connection);
    CHECK(name && dbus_bus_get_unix_user(connection, name, &error) == 1000);
    CHECK(dbus_bus_request_name(connection, service, DBUS_NAME_FLAG_DO_NOT_QUEUE, &error) == -1 &&
          dbus_error_has_name(&error, DBUS_ERROR_ACCESS_DENIED));
    dbus_error_free(&error);
    char* id = dbus_bus_get_id(connection, &error);
    CHECK(id && strlen(id) == 32);
    const char* daemon = DBUS_SERVICE_DBUS;
    DBusMessage* request = dbus_message_new_method_call(daemon, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS,
                                                        "GetConnectionUnixProcessID");
    CHECK(request &&
          dbus_message_append_args(request, DBUS_TYPE_STRING, &daemon, DBUS_TYPE_INVALID));
    DBusMessage* reply =
        dbus_connection_send_with_reply_and_block(connection, request, 3000, &error);
    dbus_uint32_t pid;
    CHECK(reply &&
          dbus_message_get_args(reply, &error, DBUS_TYPE_UINT32, &pid, DBUS_TYPE_INVALID) &&
          pid > 1);
    dbus_message_unref(reply);
    dbus_message_unref(request);
    char* machine = dbus_get_local_machine_id();
    CHECK(machine && strlen(machine) == 32);
    printf("DESKTOP_SYSTEM_DBUS_PASS client_uid=1000 daemon_uid=81 policy=denied id=%s pid=%u "
           "machine=%s\n",
           id, pid, machine);
    dbus_free(machine);
    dbus_free(id);
    dbus_connection_close(connection);
    dbus_connection_unref(connection);
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 3 && (!strcmp(argv[1], "foreign") || !strcmp(argv[1], "retired")))
        return denied(argv[2], !strcmp(argv[1], "foreign"));
    if (argc == 2 && !strcmp(argv[1], "system"))
        return system_bus();
    DBusError error = DBUS_ERROR_INIT;
    CHECK(getuid() == 1000 && geteuid() == 1000 && getenv("DBUS_SESSION_BUS_ADDRESS"));
    DBusConnection* connection = dbus_bus_get_private(DBUS_BUS_SESSION, &error);
    CHECK(connection);
    dbus_connection_set_exit_on_disconnect(connection, FALSE);
    int result = argc == 2 && !strcmp(argv[1], "serve") ? serve(connection) : call(connection);
    dbus_connection_close(connection);
    dbus_connection_unref(connection);
    return result;
}
