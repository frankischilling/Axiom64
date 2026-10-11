// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax {
constexpr size_t xattr_value_max = 65536, xattr_list_max = 65536;

struct XattrName {
    unsigned index;
    const char* suffix;
};

struct Xattr {
    Xattr* next = nullptr;
    uint8_t* value = nullptr;
    size_t size = 0;
    unsigned index = 0;
    char name[256]{};
};

int xattr_name(const char*, XattrName&);
const char* xattr_prefix(unsigned);
int64_t xattr_store_get(const Xattr*, const XattrName&, void*, size_t);
int64_t xattr_store_list(const Xattr*, void*, size_t, bool trusted);
int xattr_store_set(Xattr*&, const XattrName&, const void*, size_t, unsigned flags);
int xattr_store_remove(Xattr*&, const XattrName&);
void xattr_store_destroy(Xattr*&);

struct Node;
int64_t node_getxattr(Node*, const char*, void*, size_t);
int64_t node_listxattr(Node*, void*, size_t);
int node_setxattr(Node*, const char*, const void*, size_t, unsigned);
int node_removexattr(Node*, const char*);
int node_drop_file_capabilities(Node*);
void node_retire_xattrs(Node*);
} // namespace ax
