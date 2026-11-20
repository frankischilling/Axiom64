/* SPDX-License-Identifier: GPL-3.0-or-later */
/**
 * @file    kernel/arch/x86_64/linker.ld
 * @brief   x86-64 kernel memory layout.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Maps the kernel into the higher half and assigns the boot requests, code,
 * read-only data, and writable data to ELF load segments.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kernel_main)
PHDRS { requests PT_LOAD; text PT_LOAD; rodata PT_LOAD; data PT_LOAD; }
SECTIONS {
    . = 0xffffffff80000000;
    .limine_requests : { KEEP(*(.limine_requests_start)) KEEP(*(.limine_requests)) KEEP(*(.limine_requests_end)) } :requests
    . = ALIGN(4096);
    .text : { *(.text .text.*) } :text
    . = ALIGN(4096);
    .rodata : { *(.rodata .rodata.*) } :rodata
    . = ALIGN(4096);
    .data : { *(.data .data.*) } :data
    .bss : { *(COMMON) *(.bss .bss.*) } :data
    /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment*) }
}
