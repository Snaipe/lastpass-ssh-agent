/* lastpass-ssh-agent
 * 
 * Copyright (C) 2018  Franklin "Snaipe" Mathieu <me@snai.pe>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <errno.h>

#include "base64.h"

static const char unb64_table[] = {
    ['A'] =  1, ['B'] =  2, ['C'] =  3, ['D'] =  4, ['E'] =  5,
    ['F'] =  6, ['G'] =  7, ['H'] =  8, ['I'] =  9, ['J'] = 10,
    ['K'] = 11, ['L'] = 12, ['M'] = 13, ['N'] = 14, ['O'] = 15,
    ['P'] = 16, ['Q'] = 17, ['R'] = 18, ['S'] = 19, ['T'] = 20,
    ['U'] = 21, ['V'] = 22, ['W'] = 23, ['X'] = 24, ['Y'] = 25,
    ['Z'] = 26, ['a'] = 27, ['b'] = 28, ['c'] = 29, ['d'] = 30,
    ['e'] = 31, ['f'] = 32, ['g'] = 33, ['h'] = 34, ['i'] = 35,
    ['j'] = 36, ['k'] = 37, ['l'] = 38, ['m'] = 39, ['n'] = 40,
    ['o'] = 41, ['p'] = 42, ['q'] = 43, ['r'] = 44, ['s'] = 45,
    ['t'] = 46, ['u'] = 47, ['v'] = 48, ['w'] = 49, ['x'] = 50,
    ['y'] = 51, ['z'] = 52, ['0'] = 53, ['1'] = 54, ['2'] = 55,
    ['3'] = 56, ['4'] = 57, ['5'] = 58, ['6'] = 59, ['7'] = 60,
    ['8'] = 61, ['9'] = 62, ['+'] = 63, ['/'] = 64, ['='] =  1,
};

int base64_decode_inplace(char *src, size_t *size)
{
    /* validate */
    size_t len = 0;
    for (char *c = src; *c; ++c, ++len) {
        if (*c == '=')
            continue;
        if (!unb64_table[(size_t)*c]) {
            errno = EINVAL;
            return -1;
        }
    }

    if (len & 3) {
        errno = EINVAL;
        return -1;
    }

    *size = len / 4 * 3;

    /* decode in-place */
    char *dst = src;
    for (; len; len -= 4, src += 4, dst += 3) {
        for (int i = 0; i < 4; ++i) {
            src[i] = unb64_table[(size_t)src[i]] - 1;
        }
        dst[0] = (src[0] << 2) + ((src[1] & 0x30) >> 4);
        dst[1] = ((src[1] & 0xf) << 4) + ((src[2] & 0x3c) >> 2);
        dst[2] = ((src[2] & 0x3) << 6) + src[3];
    }

    /* remove padding from size */
    for (; !src[3]; --src, --*size);
    return 0;
}
