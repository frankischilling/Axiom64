// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/boot/boot.hpp
 * @brief   Bootloader request declarations.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Exposes the bootloader requests and response helpers used during kernel
 * startup.
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
#pragma once
#include "core/base.hpp"
#include "limine.h"

namespace ax {
extern volatile limine_hhdm_request hhdm_request;
extern volatile limine_memmap_request memmap_request;
extern volatile limine_module_request module_request;
extern volatile limine_framebuffer_request framebuffer_request;
extern volatile limine_executable_cmdline_request cmdline_request;
} // namespace ax
