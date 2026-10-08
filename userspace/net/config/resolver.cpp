// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/config/resolver.hpp"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ax::net {
namespace {
constexpr char prefix[] = "# Axiom64 generated resolver configuration\n";
constexpr uint8_t magic[]{'A', 'X', 'R', 'S', 'L', 'V', '0', '1'};

uint32_t word(const uint8_t* bytes) {
    return uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) | (uint32_t(bytes[2]) << 16) |
           (uint32_t(bytes[3]) << 24);
}

void word(uint8_t* bytes, uint32_t value) {
    for (unsigned i = 0; i < 4; i++)
        bytes[i] = value >> (i * 8);
}

uint32_t checksum(const uint8_t* bytes, size_t count) {
    uint32_t result = 2166136261;
    for (size_t i = 0; i < count; i++)
        result = (result ^ bytes[i]) * 16777619;
    return result;
}

bool same(const char* a, size_t a_size, const char* b, size_t b_size) {
    return a_size == b_size && !memcmp(a, b, a_size);
}

bool generated(const char* bytes, size_t size) {
    if (!size)
        return true;
    if (size < sizeof(prefix) - 1 || memcmp(bytes, prefix, sizeof(prefix) - 1) ||
        bytes[size - 1] != '\n')
        return false;
    unsigned line = 0;
    for (size_t i = 0; i < size; i++) {
        unsigned char value = bytes[i];
        if (value != '\n' && (value < 32 || value > 126))
            return false;
        if (++line > 255)
            return false;
        if (value == '\n')
            line = 0;
    }
    Profile profile;
    profile.method = Method::fixed;
    profile.address = 0x0a000001;
    profile.parameters.has_mask = true;
    profile.parameters.mask = 0xffffff00;
    size_t position = sizeof(prefix) - 1;
    while (position < size) {
        const char* start = bytes + position;
        const char* end = static_cast<const char*>(memchr(start, '\n', size - position));
        size_t length = size_t(end - start);
        position += length + 1;
        if (length > 11 && !memcmp(start, "nameserver ", 11)) {
            auto& parameters = profile.parameters;
            if (parameters.search[0] || parameters.dns_count == dhcp::max_dns)
                return false;
            uint32_t address = 0;
            size_t at = 11;
            for (unsigned part = 0; part < 4; part++) {
                size_t begin = at;
                unsigned value = 0;
                while (at < length && start[at] >= '0' && start[at] <= '9') {
                    if (at - begin == 3)
                        return false;
                    value = value * 10 + unsigned(start[at++] - '0');
                }
                if (at == begin || value > 255 || (at - begin > 1 && start[begin] == '0'))
                    return false;
                address = (address << 8) | value;
                if (part != 3 && (at == length || start[at++] != '.'))
                    return false;
            }
            if (at != length)
                return false;
            for (size_t i = 0; i < parameters.dns_count; i++)
                if (parameters.dns[i] == address)
                    return false;
            parameters.dns[parameters.dns_count++] = address;
        } else if (length > 7 && !memcmp(start, "search ", 7)) {
            if (position != size || length - 7 > 247)
                return false;
            for (size_t i = 7; i < length; i++)
                if ((start[i] >= 'A' && start[i] <= 'Z') ||
                    (start[i] == ' ' && (i == 7 || start[i - 1] == ' ' || i + 1 == length)) ||
                    (start[i] == '.' && i > 7 && start[i - 1] != ' ' &&
                     (i + 1 == length || start[i + 1] == ' ')))
                    return false;
            memcpy(profile.parameters.search, start + 7, length - 7);
        } else
            return false;
    }
    if (!valid_profile(profile))
        return false;
    const char* first = profile.parameters.search;
    while (*first) {
        const char* end = strchr(first, ' ');
        if (!end)
            break;
        const char* next = end + 1;
        while (*next) {
            const char* stop = strchr(next, ' ');
            size_t length = stop ? size_t(stop - next) : strlen(next);
            if (length == size_t(end - first) && !memcmp(first, next, length))
                return false;
            next = stop ? stop + 1 : next + length;
        }
        first = end + 1;
    }
    return true;
}

int sync_parent(const char* path) {
    char directory[300];
    memcpy(directory, path, strlen(path) + 1);
    char* slash = strrchr(directory, '/');
    if (!slash)
        return EINVAL;
    slash[slash == directory ? 1 : 0] = 0;
    int fd = ::open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return errno;
    int error = fsync(fd) < 0 ? errno : 0;
    if (::close(fd) < 0 && !error)
        error = errno;
    return error;
}
} // namespace

Resolver::~Resolver() {
    close();
}

void Resolver::close() {
    store_ = nullptr;
    target_[0] = 0;
    expected_size_ = before_size_ = after_size_ = 0;
    for (auto& row : rows_)
        row = {};
    managed_ = limited_ = pending_ = false;
}

bool Resolver::managed() const {
    return managed_;
}

bool Resolver::limited() const {
    return limited_;
}

int Resolver::target_policy(bool& manual) const {
    struct stat information;
    if (lstat(target_, &information) < 0) {
        if (errno != ENOENT)
            return errno;
        manual = false;
        return 0;
    }
    if (S_ISDIR(information.st_mode))
        return EISDIR;
    manual = true;
    if (!S_ISLNK(information.st_mode))
        return 0;
    char actual[300], wanted[300];
    ssize_t length = readlink(target_, actual, sizeof(actual));
    if (length < 0)
        return errno;
    int error = store_->path("resolv", ".conf", wanted, sizeof(wanted));
    if (!error)
        manual = size_t(length) != strlen(wanted) || memcmp(actual, wanted, size_t(length));
    return error;
}

int Resolver::ensure_link() {
    bool manual = false;
    int error = target_policy(manual);
    if (error || manual) {
        if (manual)
            managed_ = false;
        return error;
    }
    struct stat information;
    if (lstat(target_, &information) == 0)
        return 0;
    if (errno != ENOENT)
        return errno;
    char destination[300];
    error = store_->path("resolv", ".conf", destination, sizeof(destination));
    if (!error && symlink(destination, target_) < 0) {
        if (errno != EEXIST)
            return errno;
        error = target_policy(manual);
        if (!error)
            managed_ = !manual;
        return error;
    }
    return error ? error : sync_parent(target_);
}

int Resolver::read_output(char* bytes, size_t& size) const {
    int error = store_->read("resolv", ".conf", bytes, output_capacity, size);
    if (error == ENOENT) {
        size = 0;
        return 0;
    }
    return error;
}

int Resolver::read_record(char* old, size_t& old_size, char* next, size_t& next_size) const {
    uint8_t bytes[4096];
    size_t size = 0;
    int error =
        store_->read("resolv", ".owned", reinterpret_cast<char*>(bytes), sizeof(bytes), size);
    if (error)
        return error;
    if (size < 24 || memcmp(bytes, magic, sizeof(magic)) || word(bytes + 8) != size ||
        word(bytes + 12) != checksum(bytes + 16, size - 16))
        return EINVAL;
    size_t a = word(bytes + 16), b = word(bytes + 20);
    if (a >= output_capacity || b >= output_capacity || a + b != size - 24 ||
        !generated(reinterpret_cast<char*>(bytes + 24), a) ||
        !generated(reinterpret_cast<char*>(bytes + 24 + a), b))
        return EINVAL;
    memcpy(old, bytes + 24, a);
    memcpy(next, bytes + 24 + a, b);
    old_size = a;
    next_size = b;
    return 0;
}

int Resolver::record(const char* old, size_t old_size, const char* next, size_t next_size) const {
    uint8_t bytes[24 + 2 * output_capacity]{};
    size_t size = 24 + old_size + next_size;
    memcpy(bytes, magic, sizeof(magic));
    word(bytes + 8, size);
    word(bytes + 16, old_size);
    word(bytes + 20, next_size);
    memcpy(bytes + 24, old, old_size);
    memcpy(bytes + 24 + old_size, next, next_size);
    word(bytes + 12, checksum(bytes + 16, size - 16));
    return store_->write("resolv", ".owned", bytes, size, 0600, 0755);
}

int Resolver::restore() {
    if (!pending_)
        return 0;
    char current[output_capacity];
    size_t size = 0;
    int error = read_output(current, size);
    if (error)
        return error;
    if (!same(current, size, before_, before_size_) && !same(current, size, after_, after_size_)) {
        managed_ = false;
        pending_ = false;
        return 0;
    }
    if (!same(current, size, before_, before_size_))
        error = before_size_ ? store_->write("resolv", ".conf", before_, before_size_, 0644, 0755)
                             : store_->remove("resolv", ".conf");
    if (!error)
        error = before_size_ ? record("", 0, before_, before_size_)
                             : store_->remove("resolv", ".owned");
    if (!error) {
        memcpy(expected_, before_, before_size_);
        expected_size_ = before_size_;
        pending_ = false;
    }
    return error;
}

int Resolver::publish(const char* bytes, size_t size) {
    int error = restore();
    if (error || !managed_)
        return error;
    bool manual = false;
    error = target_policy(manual);
    if (error)
        return error;
    char current[output_capacity];
    size_t current_size = 0;
    error = read_output(current, current_size);
    if (error)
        return error;
    if (manual || !same(current, current_size, expected_, expected_size_)) {
        managed_ = false;
        return 0;
    }
    if (expected_size_) {
        char old[output_capacity], next[output_capacity];
        size_t old_size = 0, next_size = 0;
        error = read_record(old, old_size, next, next_size);
        if (error)
            return error;
        if (!same(current, current_size, old, old_size) &&
            !same(current, current_size, next, next_size)) {
            managed_ = false;
            return 0;
        }
    }
    error = ensure_link();
    if (error || !managed_)
        return error;
    if (same(bytes, size, expected_, expected_size_))
        return ensure_link();
    memcpy(before_, expected_, expected_size_);
    before_size_ = expected_size_;
    memcpy(after_, bytes, size);
    after_size_ = size;
    pending_ = true;
    error = record(before_, before_size_, after_, after_size_);
    if (!error)
        error = store_->write("resolv", ".conf", bytes, size, 0644, 0755);
    if (!error)
        error = record("", 0, bytes, size);
    if (error) {
        int restored = restore();
        return restored ? restored : error;
    }
    memcpy(expected_, bytes, size);
    expected_size_ = size;
    pending_ = false;
    return 0;
}

int Resolver::open(const Store& runtime, const char* target) {
    if (store_)
        return EALREADY;
    size_t length = strnlen(target, sizeof(target_));
    if (length < 2 || length == sizeof(target_) || target[0] != '/' || target[length - 1] == '/')
        return EINVAL;
    store_ = &runtime;
    memcpy(target_, target, length + 1);
    bool manual = false;
    int error = target_policy(manual);
    if (!error && manual)
        return 0;
    char old[output_capacity], next[output_capacity], current[output_capacity];
    size_t old_size = 0, next_size = 0, size = 0;
    int saved = error ? error : read_record(old, old_size, next, next_size);
    if (!error && saved != ENOENT && saved)
        error = saved;
    if (!error)
        error = read_output(current, size);
    if (!error && size &&
        (saved == ENOENT ||
         (!same(current, size, old, old_size) && !same(current, size, next, next_size))))
        return 0; // An unrecorded or manually edited runtime file remains manual.
    if (!error) {
        managed_ = true;
        memcpy(expected_, current, size);
        expected_size_ = size;
        char empty[output_capacity];
        size_t empty_size = 0;
        bool ignored;
        error = render(rows_, empty, empty_size, ignored);
        if (!error)
            error = publish(empty, empty_size);
    }
    if (error)
        close();
    return error;
}

int Resolver::render(const Row* rows, char* output, size_t& size, bool& limited) {
    unsigned order[8];
    for (unsigned i = 0; i < 8; i++)
        order[i] = i;
    for (unsigned i = 1; i < 8; i++) {
        unsigned selected = order[i], at = i;
        while (at && rows[selected].metric < rows[order[at - 1]].metric) {
            order[at] = order[at - 1];
            at--;
        }
        order[at] = selected;
    }
    uint32_t servers[dhcp::max_dns]{};
    size_t count = 0, used = sizeof(prefix) - 1;
    memcpy(output, prefix, used);
    limited = false;
    char domains[6][254]{};
    unsigned domains_count = 0;
    size_t search_size = 0;
    for (unsigned index : order) {
        const auto& row = rows[index];
        if (!row.used)
            continue;
        for (size_t i = 0; i < row.dns_count; i++) {
            bool present = false;
            for (size_t j = 0; j < count; j++)
                present |= row.dns[i] == servers[j];
            if (present)
                continue;
            if (count == dhcp::max_dns) {
                limited = true;
                continue;
            }
            uint32_t value = servers[count++] = row.dns[i];
            int length =
                snprintf(output + used, output_capacity - used, "nameserver %u.%u.%u.%u\n",
                         value >> 24, (value >> 16) & 255, (value >> 8) & 255, value & 255);
            if (length < 0 || size_t(length) >= output_capacity - used)
                return EOVERFLOW;
            used += size_t(length);
        }
        const char* position = row.search;
        while (*position) {
            while (*position == ' ')
                position++;
            const char* end = strchr(position, ' ');
            size_t length = end ? size_t(end - position) : strlen(position);
            if (!length)
                break;
            if (length > 1 && position[length - 1] == '.')
                length--;
            char name[254];
            for (size_t i = 0; i < length; i++)
                name[i] = position[i] >= 'A' && position[i] <= 'Z' ? position[i] + ('a' - 'A')
                                                                   : position[i];
            name[length] = 0;
            bool present = false;
            for (unsigned i = 0; i < domains_count; i++)
                present |= !strcmp(name, domains[i]);
            if (!present) {
                size_t added = length + (domains_count ? 1 : 0);
                if (domains_count == 6 || search_size + added > 247)
                    limited = true;
                else {
                    memcpy(domains[domains_count++], name, length + 1);
                    search_size += added;
                }
            }
            position = end ? end + 1 : position + strlen(position);
        }
    }
    if (domains_count) {
        if (used + 8 + search_size >= output_capacity)
            return EOVERFLOW;
        memcpy(output + used, "search ", 7);
        used += 7;
        for (unsigned i = 0; i < domains_count; i++) {
            if (i)
                output[used++] = ' ';
            size_t length = strlen(domains[i]);
            memcpy(output + used, domains[i], length);
            used += length;
        }
        output[used++] = '\n';
    }
    output[used] = 0;
    size = used;
    return 0;
}

int Resolver::commit(const Row* desired) {
    char output[output_capacity];
    size_t size = 0;
    bool limited = false;
    int error = render(desired, output, size, limited);
    if (!error && managed_)
        error = publish(output, size);
    if (!error) {
        memcpy(rows_, desired, sizeof(rows_));
        limited_ = limited;
    }
    return error;
}

int Resolver::update(unsigned index, const dhcp::Parameters& parameters, unsigned metric) {
    if (!store_)
        return EBADF;
    if (!index || index > 8 || (metric && (metric < 2 || metric > 32767)))
        return EINVAL;
    Profile validation;
    validation.method = Method::fixed;
    validation.address = 0x0a000001;
    validation.parameters.has_mask = true;
    validation.parameters.mask = 0xffffff00;
    validation.parameters.dns_count = parameters.dns_count;
    memcpy(validation.parameters.dns, parameters.dns, sizeof(parameters.dns));
    memcpy(validation.parameters.domain, parameters.domain, sizeof(parameters.domain));
    memcpy(validation.parameters.search, parameters.search, sizeof(parameters.search));
    if (!valid_profile(validation))
        return EINVAL;
    Row desired[8];
    memcpy(desired, rows_, sizeof(desired));
    auto& row = desired[index - 1];
    row = {};
    row.used = true;
    row.metric = metric ? metric : 100 + index;
    row.dns_count = parameters.dns_count;
    memcpy(row.dns, parameters.dns, sizeof(row.dns));
    const char* search = parameters.search[0] ? parameters.search : parameters.domain;
    memcpy(row.search, search, strlen(search) + 1);
    return commit(desired);
}

int Resolver::withdraw(unsigned index) {
    if (!store_)
        return EBADF;
    if (!index || index > 8)
        return EINVAL;
    Row desired[8];
    memcpy(desired, rows_, sizeof(desired));
    desired[index - 1] = {};
    return commit(desired);
}
} // namespace ax::net
