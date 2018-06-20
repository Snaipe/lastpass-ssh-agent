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
#include "config.h"

#include <err.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "sensitive.h"
#include "utils.h"

#define align2_up(Val, Pow) ((((Val) - 1) & ~((Pow) - 1)) + (Pow))

int sbuf_realloc(struct sbuf *buf, size_t newsize)
{
    newsize = align2_up(newsize, pagesize());

    void *map = mmap(NULL, newsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (map == MAP_FAILED) {
        return -1;
    }

    /* plaintext private keys should never go to swap */
    if (mlock(map, newsize) == -1) {
        munmap(map, newsize);
        return -1;
    }

    if (buf->data) {
        size_t minsize = newsize > buf->size ? buf->size : newsize;
        memcpy(map, buf->data, minsize);
        sbuf_free(buf);
    }

    buf->data = map;
    buf->size = newsize;

    return 0;
}

void sbuf_wipe(struct sbuf *buf)
{
    explicit_bzero(buf->data, buf->size);
}

int sbuf_free(struct sbuf *buf)
{
    if (!buf->data)
        return 0;
    sbuf_wipe(buf);
    return munmap(buf->data, buf->size);
}
