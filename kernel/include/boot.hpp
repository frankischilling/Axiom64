// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "base.hpp"
#include "limine.h"
namespace ax {
extern volatile limine_hhdm_request hhdm_request;
extern volatile limine_memmap_request memmap_request;
extern volatile limine_module_request module_request;
extern volatile limine_framebuffer_request framebuffer_request;
extern volatile limine_executable_cmdline_request cmdline_request;
}
