# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/tests/threads/clone.S
# @brief   Raw x86-64 clone test wrapper.
# @author  frankischilling
# @date    2026-11-18
#
# Prepares the child stack for the supplied callback and exits the child with
# the callback result.
#
# Copyright (C) 2026 frankischilling
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://gnu.org/licenses/>.
.text
.global test_clone
.type test_clone, @function
/* fn, stack, flags, arg, parent_tid, child_tid; returns the raw syscall result. */
test_clone:
    and $-16, %rsi
    sub $16, %rsi
    mov %rdi, (%rsi)
    mov %rcx, 8(%rsi)
    mov %rdx, %rdi
    mov %r8, %rdx
    mov %r9, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    jz .Lchild
    ret
.Lchild:
    mov 8(%rsp), %rdi
    call *(%rsp)
    mov %eax, %edi
    mov $60, %eax
    syscall
    ud2
.size test_clone, .-test_clone
.section .note.GNU-stack,"",@progbits
