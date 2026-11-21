; SPDX-License-Identifier: GPL-3.0-or-later
; @file    kernel/arch/x86_64/multiboot.asm
; @brief   Enter the native kernel from a 32-bit Multiboot loader.
; @author  frankischilling
; @date    2026-11-21
;
; Supplies Multiboot headers and establishes temporary identity and
; higher-half mappings before it enters the 64-bit boot code.
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

bits 32
section .multiboot progbits alloc noexec nowrite align=8
    dd 0x1badb002, 3, -(0x1badb002 + 3) ; Page-aligned modules and memory information.
align 8, db 0
mb2_header:
    dd 0xe85250d6, 0, mb2_end - mb2_header, -(0xe85250d6 + (mb2_end - mb2_header))
    dw 1, 0 ; Required memory map.
    dd 12, 6
align 8, db 0
    dw 5, 1 ; Optional linear framebuffer, prefer the desktop mode.
    dd 20, 1024, 768, 32
align 8, db 0
    dw 0, 0
    dd 8
mb2_end:

section .text
global multiboot_start
extern multiboot_end, multiboot_bootstrap_end
extern high_pt, direct_tables
extern kernel_flags, kernel_directory_count, kernel_page_count, kernel_entry_low
multiboot_start:
    cli
    cld
    mov esi, eax
    mov edi, ebx
    lgdt [gdt_pointer]
    jmp 8:.flat
.flat:
    mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax

    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .unsupported
    mov eax, 0x80000001
    cpuid
    and edx, (1 << 29) | (1 << 20)
    cmp edx, (1 << 29) | (1 << 20)
    jne .unsupported

    mov dword [pml4], low_pdpt + 3
    mov dword [pml4 + 511 * 8], high_pdpt + 3
    %assign table 0
    %rep 4
    mov dword [low_pdpt + table * 8], low_pd + table * 4096 + 3
    %assign table table + 1
    %endrep
    mov dword [high_pdpt + 510 * 8], high_pd + 3
    xor ecx, ecx
    mov eax, 0x83
.identity:
    mov [low_pd + ecx * 8], eax
    add eax, 0x200000
    inc ecx
    cmp ecx, 2048
    jne .identity

    xor ecx, ecx
    mov eax, high_pt + 3
.directories:
    mov [high_pd + ecx * 8], eax
    add eax, 4096
    inc ecx
    cmp ecx, kernel_directory_count
    jne .directories
    xor ecx, ecx
    mov eax, 0x200000
.kernel_pages:
    movzx edx, byte [kernel_flags + ecx]
    mov ebx, edx
    and ebx, 3
    or ebx, eax
    mov [high_pt + ecx * 8], ebx
    and edx, 4
    shl edx, 29 ; Flag bit 2 supplies the NX bit.
    mov [high_pt + ecx * 8 + 4], edx
    add eax, 4096
    inc ecx
    cmp ecx, kernel_page_count
    jne .kernel_pages

    mov eax, 1 << 5 ; PAE, with four-level paging.
    mov cr4, eax
    mov eax, pml4
    mov cr3, eax
    mov ecx, 0xc0000080
    rdmsr
    or eax, (1 << 8) | (1 << 11) ; EFER.LME and EFER.NXE.
    wrmsr
    mov eax, cr0
    or eax, (1 << 31) | (1 << 16) ; Paging and supervisor write protection.
    mov cr0, eax
    jmp 24:entry64
.unsupported:
    ; Multiboot has no return address. Keep the CPU halted.
    hlt
    jmp .unsupported

bits 64
entry64:
    mov ebx, edi
    mov edi, esi
    mov esi, ebx
    mov edx, multiboot_end
    mov ecx, direct_tables
    mov r8d, multiboot_bootstrap_end
    mov eax, kernel_entry_low
    cdqe ; The kernel is linked in the upper signed 32-bit address window.
    jmp rax

section .rodata
align 8
gdt:
    dq 0, 0x00cf9b000000ffff, 0x00cf93000000ffff, 0x00af9b000000ffff
gdt_pointer:
    dw $ - gdt - 1
    dd gdt
section .bss align=4096
pml4: resb 4096
low_pdpt: resb 4096
low_pd: resb 4096 * 4
high_pdpt: resb 4096
high_pd: resb 4096
