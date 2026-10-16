// SPDX-License-Identifier: GPL-3.0-or-later
#include "process/exec_arguments.hpp"

namespace ax {
ExecArguments::~ExecArguments() {
    clear();
}

void ExecArguments::clear() {
    if (text_)
        memset(text_, 0, capacity_);
    release(text_);
    release(values_);
    text_ = nullptr;
    values_ = nullptr;
    used_ = capacity_ = count_ = vector_capacity_ = 0;
    argc_ = envc_ = processed_ = budget_ = 0;
    limit_ = exec_argument_limit;
    stack_limit_ = UINT64_MAX;
    ready_ = false;
    memset(path_, 0, sizeof(path_));
}

int ExecArguments::append_pointer(const char* value, bool charged) {
    if (charged && budget_ > limit_ - sizeof(uint64_t))
        return -7;
    if (count_ == vector_capacity_) {
        size_t maximum = limit_ / sizeof(uint64_t) + 2;
        if (count_ == maximum)
            return -7;
        size_t next = min(maximum, vector_capacity_ ? vector_capacity_ * 2 : size_t(64));
        auto values = static_cast<const char**>(alloc(next * sizeof(*values_)));
        if (!values)
            return -12;
        if (count_)
            memcpy(values, values_, count_ * sizeof(*values_));
        release(values_);
        values_ = values;
        vector_capacity_ = next;
    }
    values_[count_++] = value;
    if (charged)
        budget_ += sizeof(uint64_t);
    return 0;
}

int ExecArguments::append_bytes(const char* bytes, size_t size) {
    if (size > limit_ - budget_)
        return -7;
    if (size > capacity_ - used_) {
        size_t next = max(capacity_ ? capacity_ * 2 : size_t(page_size), used_ + size);
        next = min(next, limit_);
        auto text = static_cast<char*>(alloc(next));
        if (!text)
            return -12;
        if (used_)
            memcpy(text, text_, used_);
        for (size_t i = 0; i < processed_; i++)
            if (values_[i]) {
                size_t offset = uint64_t(values_[i]) - uint64_t(text_);
                values_[i] = text + offset;
            }
        if (text_)
            memset(text_, 0, capacity_);
        release(text_);
        text_ = text;
        capacity_ = next;
    }
    memcpy(text_ + used_, bytes, size);
    used_ += size;
    budget_ += size;
    return 0;
}

int ExecArguments::vector(Read read, void* context, uint64_t address, const char* const* kernel,
                          size_t& size) {
    size = 0;
    for (;;) {
        const char* value = nullptr;
        if (read && address) {
            if (address >= user_limit || sizeof(uint64_t) > user_limit - address ||
                !read(context, address, &value, sizeof(value)))
                return -14;
            address += sizeof(uint64_t);
        } else if (kernel)
            value = kernel[size];
        int error = append_pointer(value, value != nullptr);
        if (error)
            return error;
        if (!value)
            return 0;
        size++;
    }
}

int ExecArguments::string(Read read, void* context, uint64_t address, const char* kernel,
                          size_t limit) {
    char bytes[page_size];
    for (size_t copied = 0; copied < limit;) {
        // Most arguments are short. Avoid copying a whole page for each empty
        // entry in a large vector, then use full page chunks for longer text.
        size_t size = min(copied ? size_t(page_size) : size_t(64), limit - copied);
        if (read) {
            if (address >= user_limit)
                return -14;
            size = min(size, size_t(page_size - address % page_size));
            size = min(size, size_t(user_limit - address));
            if (!read(context, address, bytes, size))
                return -14;
        } else {
            size_t count = 0;
            do {
                bytes[count] = kernel[copied + count];
            } while (bytes[count++] && count < size);
            size = count;
        }
        size_t count = 0;
        while (count < size && bytes[count])
            count++;
        bool ended = count < size;
        size = ended ? count + 1 : size;
        int error = append_bytes(bytes, size);
        if (error)
            return error;
        if (ended)
            return 0;
        copied += size;
        address += size;
    }
    return -7;
}

int ExecArguments::finish(Read read, void* context, bool kernel, bool empty) {
    for (size_t i = 0; i < count_; i++) {
        if (!values_[i] && !(empty && !i)) {
            processed_ = i + 1;
            continue;
        }
        size_t offset = used_;
        int error = empty && !i ? append_bytes("", 1)
                    : kernel
                        ? string(nullptr, nullptr, 0, values_[i], exec_string_limit)
                        : string(read, context, uint64_t(values_[i]), nullptr, exec_string_limit);
        if (error)
            return error;
        values_[i] = text_ + offset;
        processed_ = i + 1;
    }
    ready_ = true;
    return 0;
}

int ExecArguments::capture(Read read, void* context, uint64_t path, uint64_t argv, uint64_t envp,
                           uint64_t stack_limit) {
    clear();
    stack_limit_ = stack_limit;
    limit_ = max(size_t(32 * page_size), min(exec_argument_limit, size_t(stack_limit / 4)));
    if (!read)
        return -22;
    size_t length = 0;
    int error = 0;
    while (length < sizeof(path_)) {
        if (path >= user_limit || !read(context, path++, path_ + length, 1)) {
            error = -14;
            break;
        }
        if (!path_[length++])
            break;
    }
    if (!error && (length == sizeof(path_) && path_[length - 1]))
        error = -36;
    budget_ = length;
    if (!error)
        error = vector(read, context, argv, nullptr, argc_);
    bool empty = !argc_;
    if (!error && empty) {
        // Linux supplies one empty argument when the caller passes argc zero.
        argc_ = 1;
        error = append_pointer(nullptr, true);
    }
    if (!error)
        error = vector(read, context, envp, nullptr, envc_);
    if (!error)
        error = finish(read, context, false, empty);
    if (error)
        clear();
    return error;
}

int ExecArguments::capture_kernel(const char* path, const char* const* argv,
                                  const char* const* envp, uint64_t stack_limit) {
    clear();
    stack_limit_ = stack_limit;
    limit_ = max(size_t(32 * page_size), min(exec_argument_limit, size_t(stack_limit / 4)));
    if (!path)
        return -14;
    size_t length = 0;
    while (length < sizeof(path_) && path[length])
        length++;
    if (length == sizeof(path_))
        return -36;
    memcpy(path_, path, length + 1);
    budget_ = length + 1;
    int error = vector(nullptr, nullptr, 0, argv, argc_);
    bool empty = !argc_;
    if (!error && empty) {
        argc_ = 1;
        error = append_pointer(nullptr, true);
    }
    if (!error)
        error = vector(nullptr, nullptr, 0, envp, envc_);
    if (!error)
        error = finish(nullptr, nullptr, true, empty);
    if (error)
        clear();
    return error;
}

int ExecArguments::layout(uint64_t top, size_t auxiliary_size, ExecStack& output) const {
    if (!ready_ || top >= user_limit || top % page_size || auxiliary_size % 16)
        return -22;
    size_t filename_size = strlen(path_) + 1;
    size_t table_size = (argc_ + envc_ + 3) * sizeof(uint64_t);
    size_t fixed = used_ + filename_size + 7 + 16 + table_size + 15;
    constexpr size_t reserve = 128 * 1024;
    if (auxiliary_size > SIZE_MAX - fixed - reserve - page_size)
        return -7;
    size_t mapping = align_up(fixed + auxiliary_size + reserve);
    if (mapping > stack_limit_)
        mapping = align_down(stack_limit_);
    if (mapping >= top || align_up(fixed + auxiliary_size) > mapping)
        return -7;
    ExecStack result{};
    result.top = top;
    result.bottom = top - mapping;
    result.mapping_size = mapping;
    result.auxiliary_size = auxiliary_size;
    result.strings = top - used_;
    result.platform = result.strings - 7;
    result.filename = result.platform - filename_size;
    result.random = result.filename - 16;
    result.pointer = (result.random - table_size - auxiliary_size) & ~UINT64_C(15);
    if (result.pointer < result.bottom)
        return -7;
    output = result;
    return 0;
}

int ExecArguments::write_stack(const ExecStack& layout, Write write, void* context,
                               const uint8_t random[16], const void* auxiliary,
                               size_t auxiliary_size) const {
    ExecStack expected{};
    int error = this->layout(layout.top, auxiliary_size, expected);
    if (error || !write || !random || !auxiliary || memcmp(&layout, &expected, sizeof(layout)))
        return error ? error : -22;
    if (!write(context, layout.strings, text_, used_) ||
        !write(context, layout.platform, "x86_64", 7) ||
        !write(context, layout.filename, path_, strlen(path_) + 1) ||
        !write(context, layout.random, random, 16))
        return -14;
    uint64_t cursor = layout.pointer, value = argc_;
    if (!write(context, cursor, &value, sizeof(value)))
        return -14;
    cursor += sizeof(value);
    for (size_t i = 0; i < count_; i++) {
        value = values_[i] ? layout.strings + (uint64_t(values_[i]) - uint64_t(text_)) : 0;
        if (!write(context, cursor, &value, sizeof(value)))
            return -14;
        cursor += sizeof(value);
    }
    return write(context, cursor, auxiliary, auxiliary_size) ? 0 : -14;
}
} // namespace ax
