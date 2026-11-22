// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/intel_lpss.hpp
 * @brief   Declares the Intel LPSS I²C boot probe.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Checks PCI power and the memory aperture before I²C controller discovery.
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

namespace ax {
namespace Acpi {
struct DefinitionBlocks;
}

void intel_lpss_i2c_probe(const Acpi::DefinitionBlocks&);
} // namespace ax
