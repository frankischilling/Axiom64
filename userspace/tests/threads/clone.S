/* SPDX-License-Identifier: GPL-3.0-or-later */
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
