// SPDX-License-Identifier: GPL-3.0-or-later
#include "process/exec_arguments.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>

namespace ax {
static size_t calls, fail_call, live;

void* alloc(size_t size) {
    if (++calls == fail_call)
        return nullptr;
    void* result = std::malloc(size);
    if (result)
        live++;
    return result;
}

void release(void* value) {
    if (value) {
        assert(live);
        live--;
        std::free(value);
    }
}
} // namespace ax

using namespace ax;

struct Memory {
    uint64_t base;
    char* bytes;
    size_t size, writes = 0, failed_write = 0;

    static bool read(void* context, uint64_t address, void* output, size_t length) {
        auto& memory = *static_cast<Memory*>(context);
        if (address < memory.base || address - memory.base > memory.size ||
            length > memory.size - (address - memory.base))
            return false;
        memcpy(output, memory.bytes + address - memory.base, length);
        return true;
    }

    static bool write(void* context, uint64_t address, const void* input, size_t length) {
        auto& memory = *static_cast<Memory*>(context);
        if (++memory.writes == memory.failed_write || address < memory.base ||
            address - memory.base > memory.size || length > memory.size - (address - memory.base))
            return false;
        memcpy(memory.bytes + address - memory.base, input, length);
        return true;
    }
};

static void captured_strings() {
    auto text = static_cast<char*>(std::malloc(exec_string_limit + 1));
    assert(text);
    for (size_t length :
         {size_t(1023), size_t(1024), size_t(1054), size_t(4096), exec_string_limit - 1}) {
        memset(text, 'a', length);
        text[length] = 0;
        const char* argv[] = {"probe", text, nullptr};
        const char* env[] = {text, nullptr};
        ExecArguments input;
        assert(!input.capture_kernel("/bin/probe", argv, env));
        assert(input.argc() == 2 && input.envc() == 1);
        assert(strlen(input.argv()[1]) == length && strlen(input.envp()[0]) == length);
        assert(!memcmp(input.argv()[1], text, length + 1));
        assert(!memcmp(input.envp()[0], text, length + 1));
    }
    memset(text, 'a', exec_string_limit);
    text[exec_string_limit] = 0;
    const char* argv[] = {text, nullptr};
    {
        ExecArguments input;
        assert(input.capture_kernel("/bin/probe", argv, nullptr) == -7);
    }
    std::free(text);
    assert(!live);
}

static void many_strings_and_budget() {
    auto values = static_cast<const char**>(std::malloc(2049 * sizeof(const char*)));
    for (size_t i = 0; i < 2048; i++)
        values[i] = "";
    values[2048] = nullptr;
    {
        ExecArguments input;
        assert(!input.capture_kernel("/bin/probe", values, values));
        assert(input.argc() == 2048 && input.envc() == 2048);
        assert(!input.argv()[2048] && !input.envp()[2048]);
    }
    auto text = static_cast<char*>(std::malloc(exec_string_limit));
    memset(text, 'b', exec_string_limit);
    text[exec_string_limit - 1] = 0;
    for (size_t i = 0; i < 48; i++)
        values[i] = text;
    values[47] = nullptr;
    {
        ExecArguments input;
        assert(!input.capture_kernel("/bin/probe", values, nullptr));
        assert(input.argc() == 47);
    }
    values[47] = text;
    values[48] = nullptr;
    {
        ExecArguments input;
        assert(input.capture_kernel("/bin/probe", values, nullptr) == -7);
    }
    std::free(text);
    std::free(values);
    assert(!live);
}

static void stack_budgets() {
    char text[32768];
    memset(text, 's', sizeof(text) - 1);
    text[sizeof(text) - 1] = 0;
    const char* values[194];
    for (uint64_t stack : {UINT64_C(65536), UINT64_C(524288), UINT64_C(8388608), UINT64_MAX}) {
        size_t budget = max(size_t(131072), min(exec_argument_limit, size_t(stack / 4)));
        size_t count = (budget - 11) / (sizeof(text) + sizeof(uint64_t));
        assert(count + 2 <= sizeof(values) / sizeof(values[0]));
        for (size_t i = 0; i < count + 1; i++)
            values[i] = text;
        values[count] = nullptr;
        {
            ExecArguments input;
            assert(!input.capture_kernel("/bin/probe", values, nullptr, stack));
            ExecStack layout{};
            int result = input.layout(UINT64_C(0x700000000000), 16, layout);
            assert(result == (stack == 65536 ? -7 : 0));
            if (!result)
                assert(layout.mapping_size <= stack);
        }
        values[count] = text;
        values[count + 1] = nullptr;
        {
            ExecArguments input;
            assert(input.capture_kernel("/bin/probe", values, nullptr, stack) == -7);
        }
    }
    {
        const char* small[] = {"probe", nullptr};
        ExecArguments input;
        assert(!input.capture_kernel("/bin/probe", small, nullptr, 65536));
        ExecStack layout{};
        assert(!input.layout(UINT64_C(0x700000000000), 16, layout));
        assert(layout.mapping_size == 65536);
    }
    assert(!live);
}

static void user_faults_and_empty() {
    char bytes[4 * page_size]{};
    Memory memory{0x10000, bytes, sizeof(bytes)};
    memcpy(bytes, "/bin/probe", 11);
    uint64_t vector[] = {memory.base + page_size, 0};
    memcpy(bytes + 128, vector, sizeof(vector));
    memcpy(bytes + page_size, "argument", 9);
    {
        ExecArguments input;
        assert(!input.capture(Memory::read, &memory, memory.base, memory.base + 128, 0));
        assert(input.argc() == 1 && !strcmp(input.argv()[0], "argument"));
        assert(!input.envc());
    }
    for (uint64_t bad : {UINT64_MAX - 4, user_limit - 4, memory.base + sizeof(bytes)}) {
        ExecArguments input;
        assert(input.capture(Memory::read, &memory, memory.base, bad, 0) == -14);
        assert(input.capture(Memory::read, &memory, memory.base, 0, bad) == -14);
        assert(input.capture(Memory::read, &memory, bad, 0, 0) == -14);
    }
    vector[0] = memory.base + sizeof(bytes) - 1;
    memcpy(bytes + 128, vector, sizeof(vector));
    {
        ExecArguments input;
        assert(!input.capture(Memory::read, &memory, memory.base, memory.base + 128, 0));
        assert(!*input.argv()[0]);
    }
    bytes[sizeof(bytes) - 1] = 'a';
    {
        ExecArguments input;
        assert(input.capture(Memory::read, &memory, memory.base, memory.base + 128, 0) == -14);
        assert(!input.argc());
    }
    {
        ExecArguments input;
        assert(!input.capture(Memory::read, &memory, memory.base, 0, 0));
        assert(input.argc() == 1 && !*input.argv()[0] && !input.envc());
    }
    memset(bytes + page_size, 'a', exec_path_limit);
    {
        ExecArguments input;
        assert(input.capture(Memory::read, &memory, memory.base + page_size, 0, 0) == -36);
    }
    assert(!live);
}

static void stack_and_allocation_faults() {
    const char* argv[] = {"probe", "argument", nullptr};
    const char* env[] = {"X=value", nullptr};
    ExecArguments input;
    assert(!input.capture_kernel("/bin/probe", argv, env));
    ExecStack layout{};
    constexpr uint64_t top = UINT64_C(0x700000000000);
    assert(!input.layout(top, 16, layout));
    assert(!(layout.pointer % 16) && layout.pointer >= layout.bottom && layout.top == top);
    assert(input.layout(top, SIZE_MAX, layout) == -22);
    assert(input.layout(top, SIZE_MAX - 15, layout) == -7);
    assert(!input.layout(top, 16, layout));
    auto bytes = static_cast<char*>(std::malloc(layout.mapping_size));
    Memory memory{layout.bottom, bytes, layout.mapping_size};
    uint8_t random[16];
    memset(random, 0xab, sizeof(random));
    const uint64_t auxiliary[] = {0, 0};
    assert(
        !input.write_stack(layout, Memory::write, &memory, random, auxiliary, sizeof(auxiliary)));
    const auto table = reinterpret_cast<uint64_t*>(bytes + layout.pointer - layout.bottom);
    assert(table[0] == 2 && !table[3] && !table[5] && !table[6] && !table[7]);
    assert(!strcmp(bytes + table[1] - layout.bottom, "probe"));
    assert(!strcmp(bytes + table[2] - layout.bottom, "argument"));
    assert(!strcmp(bytes + table[4] - layout.bottom, "X=value"));
    assert(!memcmp(bytes + layout.random - layout.bottom, random, sizeof(random)));
    assert(!strcmp(bytes + layout.platform - layout.bottom, "x86_64"));
    assert(!strcmp(bytes + layout.filename - layout.bottom, "/bin/probe"));
    size_t writes = memory.writes;
    for (size_t failure = 1; failure <= writes; failure++) {
        memory.writes = 0;
        memory.failed_write = failure;
        assert(input.write_stack(layout, Memory::write, &memory, random, auxiliary,
                                 sizeof(auxiliary)) == -14);
    }
    std::free(bytes);
    const char* growing[2049];
    char long_value[1001];
    memset(long_value, 'g', sizeof(long_value) - 1);
    long_value[sizeof(long_value) - 1] = 0;
    for (size_t i = 0; i < 2048; i++)
        growing[i] = long_value;
    growing[2048] = nullptr;
    calls = 0;
    {
        ExecArguments measured;
        assert(!measured.capture_kernel("/bin/probe", growing, nullptr));
    }
    size_t allocation_calls = calls, baseline = live;
    for (size_t failure = 1; failure <= allocation_calls; failure++) {
        calls = 0;
        fail_call = failure;
        {
            ExecArguments failing;
            assert(failing.capture_kernel("/bin/probe", growing, nullptr) == -12);
        }
        assert(live == baseline);
    }
    fail_call = 0;
}

int main() {
    captured_strings();
    many_strings_and_budget();
    stack_budgets();
    user_faults_and_empty();
    stack_and_allocation_faults();
    assert(!live);
    puts("EXEC_ARGUMENTS_HOST_PASS long_strings string_limit vectors aggregate_budget faults "
         "empty_argv checked_stack allocation_failures lifetime");
}
