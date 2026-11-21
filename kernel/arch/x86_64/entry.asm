; SPDX-License-Identifier: GPL-3.0-or-later
; @file    kernel/arch/x86_64/entry.asm
; @brief   x86-64 kernel entry and return.
; @author  frankischilling
; @date    2026-11-18
;
; Saves syscall and exception frames, dispatches them on kernel stacks, and
; restores the selected task with IRETQ.
;
; Copyright (C) 2026 frankischilling
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program. If not, see <https://gnu.org/licenses/>.
bits 64
default rel
section .text
extern handle_syscall, handle_trap, kernel_stack_top

%macro SAVE 0
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro

global syscall_entry
syscall_entry:
    mov [saved_user_rsp], rsp
    mov rsp, [kernel_stack_top]
    push qword 0x1b
    push qword [saved_user_rsp]
    push r11
    push qword 0x23
    push rcx
    push qword 0
    push qword 256
    SAVE
    cld
    mov rdi,rsp
    and rsp,-16
    call handle_syscall
    mov rsp,rax
    jmp restore_frame

global enter_user
enter_user:
    mov rsp,rdi
restore_frame:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp,16
    iretq

%assign i 0
%rep 256
interrupt_%+i:
%if i != 8 && i != 10 && i != 11 && i != 12 && i != 13 && i != 14 && i != 17 && i != 21 && i != 29 && i != 30
    push qword 0
%endif
    push qword i
    jmp interrupt_common
%assign i i+1
%endrep
interrupt_common:
    SAVE
    cld
    mov rdi,rsp
    and rsp,-16
    call handle_trap
    mov rsp,rax
    jmp restore_frame

global load_gdt
load_gdt:
    lgdt [rdi]
    push qword 8
    lea rax,[.reload]
    push rax
    retfq
.reload:
    mov ax,16
    mov ds,ax
    mov es,ax
    mov ss,ax
    xor eax,eax
    mov fs,ax
    mov gs,ax
    mov ax,0x28
    ltr ax
    ret

section .rodata
global interrupt_table
interrupt_table:
%assign i 0
%rep 256
    dq interrupt_%+i
%assign i i+1
%endrep
section .bss
saved_user_rsp: resq 1
section .note.GNU-stack noalloc noexec nowrite progbits
