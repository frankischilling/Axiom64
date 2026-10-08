// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/config/profile.hpp"
#include "net/config/saved.hpp"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ax::net {
namespace {
constexpr size_t maximum_text = 4096;

bool unicast(uint32_t address, bool loopback = false) {
    unsigned first = address >> 24;
    return first && (loopback || first != 127) && first < 224;
}

bool mask_valid(uint32_t mask) {
    uint32_t bits = ~mask;
    return !(bits & (bits + 1));
}

bool names(const char* text, size_t capacity, bool list) {
    size_t length = strnlen(text, capacity);
    if (length == capacity)
        return false;
    if (!length)
        return true;
    size_t start = 0;
    unsigned count = 0;
    while (start < length) {
        if (++count > (list ? 6u : 1u))
            return false;
        size_t end = start;
        while (end < length && text[end] != ' ')
            end++;
        if (end == start || end - start > 253)
            return false;
        if (end - start != 1 || text[start] != '.') {
            size_t label = 0;
            for (size_t i = start; i < end; i++) {
                unsigned char value = text[i];
                if (value == '.') {
                    if (!label)
                        return false;
                    label = 0;
                } else if (!((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
                             (value >= '0' && value <= '9') || value == '-') ||
                           ++label > 63)
                    return false;
            }
        }
        if (end < length && (!list || end + 1 == length || text[end + 1] == ' '))
            return false;
        start = end + 1;
    }
    return true;
}

bool number(const char* text, unsigned maximum, unsigned& value) {
    if (!*text)
        return false;
    unsigned result = 0;
    for (; *text; text++) {
        if (*text < '0' || *text > '9' || result > maximum / 10)
            return false;
        result = result * 10 + unsigned(*text - '0');
        if (result > maximum)
            return false;
    }
    value = result;
    return true;
}

bool address(const char* text, uint32_t& output) {
    in_addr value;
    if (inet_pton(AF_INET, text, &value) != 1)
        return false;
    output = ntohl(value.s_addr);
    return true;
}

char* trim(char* text) {
    while (*text == ' ' || *text == '\t')
        text++;
    size_t length = strlen(text);
    while (length &&
           (text[length - 1] == ' ' || text[length - 1] == '\t' || text[length - 1] == '\r'))
        text[--length] = 0;
    return text;
}

bool text_copy(const char* input, char* output, size_t capacity, bool list = false) {
    size_t length = strlen(input);
    if (length >= capacity || !names(input, capacity, list))
        return false;
    memcpy(output, input, length + 1);
    return true;
}

struct Writer {
    char* bytes;
    size_t capacity, used = 0;
    bool good = true;

    void put(const char* format, ...) {
        if (!good)
            return;
        va_list arguments;
        va_start(arguments, format);
        int count = vsnprintf(bytes + used, capacity - used, format, arguments);
        va_end(arguments);
        if (count < 0 || size_t(count) >= capacity - used)
            good = false;
        else
            used += count;
    }

    void ip(uint32_t value) {
        put("%u.%u.%u.%u", value >> 24, value >> 16 & 255, value >> 8 & 255, value & 255);
    }
};

int sync_directory(const char* path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return errno;
    int error = fsync(fd) < 0 ? errno : 0;
    if (close(fd) < 0 && !error)
        error = errno;
    return error;
}

int ensure_directory(const char* path, unsigned mode) {
    char current[256];
    size_t length = strnlen(path, sizeof(current));
    if (!length || length >= sizeof(current) || path[0] != '/')
        return EINVAL;
    memcpy(current, path, length + 1);
    for (size_t i = 1; i <= length; i++) {
        if (current[i] && current[i] != '/')
            continue;
        char saved = current[i];
        current[i] = 0;
        bool created = mkdir(current, mode) == 0;
        if (!created && errno != EEXIST)
            return errno;
        struct stat information;
        if (lstat(current, &information) < 0)
            return errno;
        if (!S_ISDIR(information.st_mode))
            return ENOTDIR;
        if (created) {
            if (mode != 0700 && chmod(current, mode) < 0)
                return errno;
            char* slash = strrchr(current, '/');
            *slash = 0;
            int error = sync_directory(slash == current ? "/" : current);
            *slash = '/';
            if (error)
                return error;
        }
        current[i] = saved;
    }
    if (mode == 0755) {
        struct stat information;
        if (lstat(path, &information) < 0)
            return errno;
        if ((information.st_mode & 0005) != 0005 || (information.st_mode & 0022) ||
            information.st_uid != geteuid())
            return EACCES;
    }
    return 0;
}

int hex(unsigned char value) {
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -1;
}

bool hardware(const char* text, uint8_t output[6]) {
    if (strlen(text) != 17)
        return false;
    for (unsigned i = 0; i < 6; i++) {
        int high = hex(text[3 * i]), low = hex(text[3 * i + 1]);
        if (high < 0 || low < 0 || (i != 5 && text[3 * i + 2] != ':'))
            return false;
        output[i] = uint8_t(high * 16 + low);
    }
    const uint8_t zero[6]{};
    return !(output[0] & 1) && memcmp(output, zero, 6);
}
} // namespace

bool valid_profile(const Profile& profile) {
    const auto& parameters = profile.parameters;
    if (uint8_t(profile.method) > uint8_t(Method::disabled) ||
        (profile.metric && (profile.metric < 2 || profile.metric > 32767)) ||
        !names(profile.hostname, sizeof(profile.hostname), false) ||
        !names(parameters.domain, sizeof(parameters.domain), false) ||
        !names(parameters.search, sizeof(parameters.search), true) ||
        parameters.dns_count > dhcp::max_dns || parameters.route_count > dhcp::max_routes ||
        parameters.has_lease || parameters.has_renewal || parameters.has_rebinding ||
        parameters.classless)
        return false;
    bool settings = profile.address || parameters.has_mask || parameters.router ||
                    parameters.dns_count || parameters.route_count || parameters.domain[0] ||
                    parameters.search[0];
    if (profile.method != Method::fixed)
        return !settings;
    uint32_t bits = ~parameters.mask;
    if (!unicast(profile.address) || !parameters.has_mask || !mask_valid(parameters.mask) ||
        (bits >= 2 && (!(profile.address & bits) || (profile.address & bits) == bits)))
        return false;
    auto gateway_valid = [&](uint32_t gateway) {
        return !gateway || (unicast(gateway) && gateway != profile.address &&
                            (gateway & parameters.mask) == (profile.address & parameters.mask) &&
                            (bits < 2 || ((gateway & bits) && (gateway & bits) != bits)));
    };
    if (!gateway_valid(parameters.router))
        return false;
    for (size_t i = 0; i < parameters.dns_count; i++)
        if (!unicast(parameters.dns[i], true))
            return false;
    for (size_t i = 0; i < parameters.route_count; i++) {
        const auto& route = parameters.routes[i];
        if (!mask_valid(route.mask) || (route.destination & route.mask) != route.destination ||
            !gateway_valid(route.gateway))
            return false;
        for (size_t j = 0; j < i; j++)
            if (parameters.routes[j].destination == route.destination &&
                parameters.routes[j].mask == route.mask)
                return false;
    }
    return !parameters.has_lease && !parameters.has_renewal && !parameters.has_rebinding &&
           !parameters.classless;
}

bool parse_profile(const void* input, size_t size, Profile& output) {
    if (!size || size >= maximum_text || memchr(input, 0, size))
        return false;
    char bytes[maximum_text];
    memcpy(bytes, input, size);
    bytes[size] = 0;
    Profile profile;
    unsigned seen = 0;
    char* position = bytes;
    while (position && *position) {
        char* next = strchr(position, '\n');
        if (next)
            *next++ = 0;
        char* line = trim(position);
        position = next;
        if (!*line || *line == '#')
            continue;
        char* equals = strchr(line, '=');
        if (!equals)
            return false;
        *equals++ = 0;
        char* key = trim(line);
        char* value = trim(equals);
        const char* keys[]{"axiom64-network", "mode",   "address", "netmask",  "gateway", "dns",
                           "domain",          "search", "metric",  "hostname", "route"};
        unsigned index = 0;
        while (index < 11 && strcmp(key, keys[index]))
            index++;
        if (index == 11 || (index != 10 && (seen & (1u << index))))
            return false;
        seen |= 1u << index;
        switch (index) {
        case 0:
            if (strcmp(value, "1"))
                return false;
            break;
        case 1:
            if (!strcmp(value, "dhcp"))
                profile.method = Method::dhcp;
            else if (!strcmp(value, "static"))
                profile.method = Method::fixed;
            else if (!strcmp(value, "disabled"))
                profile.method = Method::disabled;
            else
                return false;
            break;
        case 2:
            if (!address(value, profile.address))
                return false;
            break;
        case 3:
            if (!address(value, profile.parameters.mask))
                return false;
            profile.parameters.has_mask = true;
            break;
        case 4:
            if (!address(value, profile.parameters.router))
                return false;
            break;
        case 5: {
            char* resolver = value;
            while (*resolver) {
                if (profile.parameters.dns_count == dhcp::max_dns)
                    return false;
                char* space = strchr(resolver, ' ');
                if (space)
                    *space++ = 0;
                if (!address(resolver, profile.parameters.dns[profile.parameters.dns_count++]))
                    return false;
                if (!space)
                    break;
                resolver = space;
            }
            break;
        }
        case 6:
            if (!text_copy(value, profile.parameters.domain, sizeof(profile.parameters.domain)))
                return false;
            break;
        case 7:
            if (!text_copy(value, profile.parameters.search, sizeof(profile.parameters.search),
                           true))
                return false;
            break;
        case 8:
            if (!number(value, 32767, profile.metric))
                return false;
            break;
        case 9:
            if (!text_copy(value, profile.hostname, sizeof(profile.hostname)))
                return false;
            break;
        case 10: {
            if (profile.parameters.route_count == dhcp::max_routes)
                return false;
            char* slash = strchr(value, '/');
            char* space = strchr(value, ' ');
            unsigned prefix;
            if (!slash || !space || slash >= space)
                return false;
            *slash++ = *space++ = 0;
            auto& route = profile.parameters.routes[profile.parameters.route_count++];
            if (!address(value, route.destination) || !number(slash, 32, prefix) ||
                !address(space, route.gateway))
                return false;
            route.mask = prefix ? UINT32_MAX << (32 - prefix) : 0;
            break;
        }
        }
    }
    if ((seen & 3) != 3 || !valid_profile(profile))
        return false;
    output = profile;
    return true;
}

size_t format_profile(const Profile& profile, void* output, size_t capacity) {
    if (!capacity || !valid_profile(profile))
        return 0;
    Writer writer{static_cast<char*>(output), capacity};
    writer.put("axiom64-network=1\nmode=%s\nhostname=%s\nmetric=%u\n",
               profile.method == Method::dhcp    ? "dhcp"
               : profile.method == Method::fixed ? "static"
                                                 : "disabled",
               profile.hostname, profile.metric);
    const auto& parameters = profile.parameters;
    if (profile.method == Method::fixed) {
        writer.put("address=");
        writer.ip(profile.address);
        writer.put("\nnetmask=");
        writer.ip(parameters.mask);
        writer.put("\ngateway=");
        writer.ip(parameters.router);
        writer.put("\ndns=");
        for (size_t i = 0; i < parameters.dns_count; i++) {
            if (i)
                writer.put(" ");
            writer.ip(parameters.dns[i]);
        }
        writer.put("\ndomain=%s\nsearch=%s\n", parameters.domain, parameters.search);
        for (size_t i = 0; i < parameters.route_count; i++) {
            const auto& route = parameters.routes[i];
            unsigned prefix = __builtin_popcount(route.mask);
            writer.put("route=");
            writer.ip(route.destination);
            writer.put("/%u ", prefix);
            writer.ip(route.gateway);
            writer.put("\n");
        }
    }
    return writer.good ? writer.used : 0;
}

Store::Store(const char* directory) {
    size_t length = strnlen(directory, sizeof(directory_));
    if (length && length < sizeof(directory_) && directory[0] == '/') {
        memcpy(directory_, directory, length + 1);
        while (length > 1 && directory_[length - 1] == '/')
            directory_[--length] = 0;
    }
}

int Store::path(const char* interface, const char* suffix, char* output, size_t capacity) const {
    size_t length = strnlen(interface, 16);
    if (!directory_[0] || !length || length == 16)
        return EINVAL;
    for (size_t i = 0; i < length; i++) {
        unsigned char value = interface[i];
        if (!((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9') || value == '-' || value == '_'))
            return EINVAL;
    }
    int count = snprintf(output, capacity, "%s/%s%s", directory_, interface, suffix);
    return count < 0 || size_t(count) >= capacity ? ENAMETOOLONG : 0;
}

int Store::read(const char* interface, const char* suffix, char* output, size_t capacity,
                size_t& size, bool saved) const {
    char name[300];
    int error = path(interface, suffix, name, sizeof(name));
    if (error)
        return error;
    if (saved)
        return saved::read(directory_, strrchr(name, '/') + 1, output, capacity, size);
    int fd = open(name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return errno;
    struct stat information;
    if (fstat(fd, &information) < 0)
        error = errno;
    else if (!S_ISREG(information.st_mode))
        error = EINVAL;
    else if (information.st_size < 0 || uint64_t(information.st_size) >= capacity)
        error = EFBIG;
    size_t used = 0;
    while (!error && used < capacity) {
        ssize_t count = ::read(fd, output + used, capacity - used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
            error = errno;
        else if (!count)
            break;
        else
            used += size_t(count);
    }
    if (!error && used == capacity)
        error = EFBIG;
    if (close(fd) < 0 && !error)
        error = errno;
    if (!error)
        size = used;
    return error;
}

int Store::write(const char* interface, const char* suffix, const void* input, size_t size,
                 unsigned mode, unsigned directory_mode, bool saved) const {
    char name[300], temporary[340];
    int error = path(interface, suffix, name, sizeof(name));
    if (error || !size || size >= maximum_text)
        return error ? error : EINVAL;
    if (saved)
        return saved::write(directory_, strrchr(name, '/') + 1, input, size);
    error = ensure_directory(directory_, directory_mode);
    if (error)
        return error;
    static unsigned serial = 0;
    int fd = -1;
    for (unsigned attempt = 0; attempt < 8; attempt++) {
        int count =
            snprintf(temporary, sizeof(temporary), "%s.tmp.%ld.%u", name, long(getpid()), ++serial);
        if (count < 0 || size_t(count) >= sizeof(temporary))
            return ENAMETOOLONG;
        fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
        if (fd >= 0)
            break;
        if (errno != EEXIST)
            return errno;
    }
    if (fd < 0)
        return EEXIST;
    if (mode != 0600 && fchmod(fd, mode) < 0)
        error = errno;
    size_t written = 0;
    auto bytes = static_cast<const uint8_t*>(input);
    while (!error && written < size) {
        ssize_t count = ::write(fd, bytes + written, size - written);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            error = count < 0 ? errno : EIO;
            break;
        }
        written += size_t(count);
    }
    if (!error && fsync(fd) < 0)
        error = errno;
    if (close(fd) < 0 && !error)
        error = errno;
    if (!error && rename(temporary, name) < 0)
        error = errno;
    if (error)
        unlink(temporary);
    else
        error = sync_directory(directory_);
    return error;
}

int Store::read_profile(const char* interface, Profile& output) const {
    char bytes[maximum_text];
    size_t size = 0;
    int error = read(interface, ".conf", bytes, sizeof(bytes), size, true);
    return error ? error : parse_profile(bytes, size, output) ? 0 : EINVAL;
}

int Store::write_profile(const char* interface, const Profile& profile) const {
    char bytes[maximum_text];
    size_t size = format_profile(profile, bytes, sizeof(bytes));
    return size ? write(interface, ".conf", bytes, size, 0600, 0700, true) : EINVAL;
}

int Store::read_hint(const char* interface, const dhcp::Identity& identity,
                     uint32_t& output) const {
    char bytes[maximum_text];
    size_t size = 0;
    int error = read(interface, ".lease", bytes, sizeof(bytes), size, true);
    if (error)
        return error;
    if (!size || size >= sizeof(bytes) || memchr(bytes, 0, size))
        return EINVAL;
    bytes[size] = 0;
    unsigned seen = 0;
    uint8_t mac[6]{};
    uint32_t value = 0;
    char* position = bytes;
    while (position && *position) {
        char* next = strchr(position, '\n');
        if (next)
            *next++ = 0;
        char* line = trim(position);
        position = next;
        char* equals = strchr(line, '=');
        if (!equals)
            return EINVAL;
        *equals++ = 0;
        unsigned field = !strcmp(line, "axiom64-lease") ? 1
                         : !strcmp(line, "mac")         ? 2
                         : !strcmp(line, "address")     ? 4
                                                        : 0;
        if (!field || (seen & field))
            return EINVAL;
        seen |= field;
        if ((field == 1 && strcmp(equals, "1")) || (field == 2 && !hardware(equals, mac)) ||
            (field == 4 && (!address(equals, value) || !unicast(value))))
            return EINVAL;
    }
    if (seen != 7)
        return EINVAL;
    if (memcmp(mac, identity.mac, 6))
        return ESTALE;
    output = value;
    return 0;
}

int Store::write_hint(const char* interface, const dhcp::Identity& identity, uint32_t value) const {
    const uint8_t zero[6]{};
    if (!unicast(value) || (identity.mac[0] & 1) || !memcmp(identity.mac, zero, 6))
        return EINVAL;
    char bytes[128];
    Writer writer{bytes, sizeof(bytes)};
    const auto mac = identity.mac;
    writer.put("axiom64-lease=1\nmac=%02x:%02x:%02x:%02x:%02x:%02x\naddress=", mac[0], mac[1],
               mac[2], mac[3], mac[4], mac[5]);
    writer.ip(value);
    writer.put("\n");
    return writer.good ? write(interface, ".lease", bytes, writer.used, 0600, 0700, true) : EINVAL;
}

int Store::remove(const char* interface, const char* suffix, bool saved) const {
    char name[300];
    int error = path(interface, suffix, name, sizeof(name));
    if (error)
        return error;
    if (saved)
        return saved::remove(directory_, strrchr(name, '/') + 1);
    if (unlink(name) < 0)
        return errno == ENOENT ? 0 : errno;
    return sync_directory(directory_);
}

int Store::forget_hint(const char* interface) const {
    return remove(interface, ".lease", true);
}
} // namespace ax::net
