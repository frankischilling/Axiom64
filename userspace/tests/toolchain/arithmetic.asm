; SPDX-License-Identifier: GPL-3.0-or-later
; @file userspace/tests/toolchain/arithmetic.asm
; @brief Check the native assembler, ELF linker, and x86-64 C calling convention.
; @author frankischilling
; @date 2026-11-19

bits 64
section .text
global native_asm_add:function

native_asm_add:
    lea eax, [rdi + rsi]
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
