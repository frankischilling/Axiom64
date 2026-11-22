// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/fb_console.cpp
 * @brief   Draw console text on the firmware framebuffer.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Keeps text cells while the virtual terminal is in graphics mode.
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

#include "drivers/platform/fb_console.hpp"
#include "boot/boot.hpp"
#include "font8x8/font8x8_basic.hpp"

namespace ax {
namespace {
constexpr unsigned max_columns = 164, max_rows = 80;
constexpr unsigned glyph_width = 8, glyph_height = 8;
enum class Escape { plain, first, csi };

struct Console {
    const BootFramebuffer* framebuffer;
    unsigned columns, rows, col, row, horizontal_scale, vertical_scale;
    uint32_t ink, background;
    bool graphics;
    Escape escape;
    unsigned char text[max_rows][max_columns];
};

Console console;

void draw_cell(unsigned column, unsigned row) {
    const auto& fb = *console.framebuffer;
    const auto character = console.text[row][column];
    const auto* glyph = font8x8_basic[character];
    const unsigned scale_x = console.horizontal_scale, scale_y = console.vertical_scale;
    auto* framebuffer = static_cast<volatile uint8_t*>(fb.address);
    for (unsigned y = 0; y < glyph_height * scale_y; ++y) {
        auto* line = reinterpret_cast<volatile uint32_t*>(
            framebuffer + (row * glyph_height * scale_y + y) * fb.pitch);
        line += column * glyph_width * scale_x;
        for (unsigned x = 0; x < glyph_width * scale_x; ++x)
            line[x] = glyph[y / scale_y] & (1u << (x / scale_x)) ? console.ink : console.background;
    }
}

void redraw() {
    if (console.graphics)
        return;
    const auto& fb = *console.framebuffer;
    auto* base = static_cast<volatile uint8_t*>(fb.address);
    for (unsigned y = 0; y < fb.height; ++y) {
        auto* pixels = reinterpret_cast<volatile uint32_t*>(base + y * fb.pitch);
        for (unsigned x = 0; x < fb.width; ++x)
            pixels[x] = console.background;
    }
    for (unsigned row = 0; row < console.rows; ++row)
        for (unsigned col = 0; col < console.columns; ++col)
            if (console.text[row][col] != ' ')
                draw_cell(col, row);
}

void newline() {
    console.col = 0;
    if (console.row + 1 < console.rows) {
        ++console.row;
        return;
    }
    memmove(console.text, console.text + 1, (console.rows - 1) * max_columns);
    memset(console.text[console.rows - 1], ' ', max_columns);
    redraw();
}

void print(unsigned char character) {
    if (console.col == console.columns)
        newline();
    console.text[console.row][console.col] = character;
    if (!console.graphics)
        draw_cell(console.col, console.row);
    ++console.col;
}
} // namespace

bool fb_console_init(const BootFramebuffer& fb) {
    if (!fb.address || uint64_t(fb.address) % 4 || fb.bpp != 32 || fb.width < 320 ||
        fb.height < 200 || fb.width > 8192 || fb.height > 8192 || fb.pitch % 4 ||
        fb.pitch < fb.width * 4 || fb.pitch > 32768 || fb.red_mask_size != 8 ||
        fb.green_mask_size != 8 || fb.blue_mask_size != 8 || fb.red_mask_shift > 24 ||
        fb.green_mask_shift > 24 || fb.blue_mask_shift > 24)
        return false;
    const uint32_t red = 255u << fb.red_mask_shift, green = 255u << fb.green_mask_shift,
                   blue = 255u << fb.blue_mask_shift;
    if ((red & green) || (red & blue) || (green & blue))
        return false;
    console.framebuffer = &fb;
    console.horizontal_scale = fb.width >= 1600 ? 2 : 1;
    console.vertical_scale = fb.height >= 600 ? 2 : 1;
    console.columns =
        min(max_columns, unsigned(fb.width / (glyph_width * console.horizontal_scale)));
    console.rows = min(max_rows, unsigned(fb.height / (glyph_height * console.vertical_scale)));
    console.ink = red | green | blue;
    console.background =
        16u << fb.red_mask_shift | 20u << fb.green_mask_shift | 27u << fb.blue_mask_shift;
    memset(console.text, ' ', sizeof(console.text));
    redraw();
    return true;
}

void fb_console_put(unsigned char character) {
    if (!console.framebuffer)
        return;
    if (console.escape == Escape::first) {
        console.escape = character == '[' ? Escape::csi : Escape::plain;
        return;
    }
    if (console.escape == Escape::csi) {
        if (character < 0x20 || character >= 0x40)
            console.escape = Escape::plain;
        return;
    }
    switch (character) {
    case '\033':
        console.escape = Escape::first;
        break;
    case '\r':
        console.col = 0;
        break;
    case '\n':
        newline();
        break;
    case '\b':
        if (console.col)
            --console.col;
        break;
    case '\t': {
        const unsigned spaces = 8 - console.col % 8;
        for (unsigned i = 0; i < spaces; ++i)
            print(' ');
        break;
    }
    default:
        if (character >= 0x20 && character < 0x7f)
            print(character);
        break;
    }
}

void fb_console_graphics(bool graphics) {
    if (!console.framebuffer || console.graphics == graphics)
        return;
    console.graphics = graphics;
    redraw();
}
} // namespace ax
