// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_rsn.hpp
 * @brief   Validate the security suites used for AX201 association.
 * @author  frankischilling
 * @date    2026-11-24
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "core/base.hpp"

namespace ax::IntelWifi {
enum class RsnAkm : uint8_t { open = 0, enterprise = 1, personal = 2 };
inline constexpr uint32_t ccmp_suite = 0x000fac04;
inline constexpr uint32_t enterprise_suite = 0x000fac01, personal_suite = 0x000fac02;
inline constexpr uint8_t rsn_element = 48;

bool supports_rsn(const uint8_t* body, size_t length, RsnAkm, bool station_request);
bool station_rsn_matches(const uint8_t* elements, size_t length, RsnAkm);
} // namespace ax::IntelWifi
