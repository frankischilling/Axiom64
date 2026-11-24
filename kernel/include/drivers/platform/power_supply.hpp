// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/power_supply.hpp
 * @brief   Publishes ACPI batteries and adapters through the Linux power-supply class.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once

namespace ax::Acpi {
struct DefinitionBlocks;
}

namespace ax::DeviceInventory {
void power_supply_prepare(const Acpi::DefinitionBlocks&);
void power_supply_init();
void power_supply_refresh();
} // namespace ax::DeviceInventory
