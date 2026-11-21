/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * @file    kernel/arch/x86_64/multiboot.ld
 * @brief   Place the Multiboot wrapper and native kernel payload.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Puts both protocol headers within the loader's search window and reserves
 * space for the native kernel's zero-filled memory and bootstrap tables.
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
ENTRY(multiboot_start)
PHDRS { bootstrap PT_LOAD FLAGS(5); image PT_LOAD FLAGS(6); }
SECTIONS {
    . = 0x100000;
    .multiboot : { KEEP(*(.multiboot)) } :bootstrap
    .text : { *(.text) } :bootstrap
    .rodata : {
        *(.rodata)
        kernel_flags = .;
        *kernel-flags.bin(.data)
    } :bootstrap
    multiboot_bootstrap_end = ALIGN(4096);
    ASSERT(multiboot_bootstrap_end <= 0x200000, "Multiboot bootstrap overlaps the kernel")
    . = 0x200000;
    .kernel : { *kernel-payload.bin(.data) } :image
    PROVIDE(kernel_image_size = SIZEOF(.kernel));
    PROVIDE(kernel_directory_count = 0);
    .kernel_zero (NOLOAD) : { . += kernel_image_size - SIZEOF(.kernel); } :image
    . = ALIGN(4096);
    .bss (NOLOAD) : {
        *(.bss)
        high_pt = .;
        . += kernel_directory_count * 4096;
        /* One ACPI root page and a 4 GiB direct map with 4 KiB leaves. */
        direct_tables = .;
        . += 4096 * (1 + 1 + 4 + 2048);
    } :image
    multiboot_end = .;
    ASSERT(multiboot_end <= 0xffffffff, "Multiboot image exceeds the 32-bit load address space")
}
