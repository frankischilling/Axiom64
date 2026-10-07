; SPDX-License-Identifier: GPL-3.0-or-later
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
%rep 48
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
%rep 48
    dq interrupt_%+i
%assign i i+1
%endrep
section .bss
saved_user_rsp: resq 1
section .note.GNU-stack noalloc noexec nowrite progbits
