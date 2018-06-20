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
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "msg.h"

int msg_init(int code, struct msg *m)
{
    m->size = 0;
    m->length = 0;
    m->buf = NULL;

    uint32_t size = 0;
    if (msg_append(m, &size, sizeof (size)) == -1) {
        return -1;
    }

    uint8_t b = code;
    if (msg_append(m, &b, sizeof (b)) == -1) {
        return -1;
    }

    return 0;
}

int msg_append(struct msg *m, const void *bytes, size_t size)
{
    if (m->length > SIZE_MAX - size) {
        errno = EOVERFLOW;
        return -1;
    }

    if (m->size < m->length + size) {
        while (m->size < m->length + size) {
            if (m->size > SIZE_MAX / 3 * 2 - 1) {
                m->size = m->length + size;
            } else {
                m->size = (m->size + 1) * 3 / 2;
            }
        }
        void *nbuf = realloc(m->buf, m->size);
        if (!nbuf) {
            return -1;
        }
        m->buf = nbuf;
    }

    memcpy((char *)m->buf + m->length, bytes, size);
    m->length += size;
    return 0;
}

int msg_appendf(struct msg *m, const char *fmt, ...)
{
    va_list vl;
    va_start(vl, fmt);

    union {
        uint8_t u8;
        uint32_t u32;
    } buf;

    for (const char *c = fmt; *c; c++) {
        switch (*c) {
            void *data;
            size_t size;
        case 'b':
            buf.u8 = va_arg(vl, unsigned);
            data = &buf.u8;
            size = sizeof (buf.u8);
            goto end;
        case 'i':
            buf.u32 = htonl(va_arg(vl, uint32_t));
            data = &buf.u32;
            size = sizeof (buf.u32);
            goto end;
        case 'p':
            data = va_arg(vl, void *);
            size = va_arg(vl, size_t);
            goto prepend_size;
        case 's':
            data = va_arg(vl, char *);
            size = strlen((char *)data);
            goto prepend_size;

        prepend_size:
            buf.u32 = htonl(size);
            if (msg_append(m, &buf.u32, sizeof (buf.u32)) == -1) {
                return -1;
            }
        end:
            if (msg_append(m, data, size) == -1) {
                return -1;
            }
        default:
            break;
        }
    }

    va_end(vl);

    return 0;
}

int msg_send(struct msg *m, int sock)
{
    uint32_t *size = m->buf;

    if (m->length < sizeof (*size)) {
        errno = EOVERFLOW;
        return -1;
    }

    *size = htonl(m->length - sizeof (*size));

    int rc = write(sock, m->buf, m->length);
    msg_free(m);
    return rc;
}

void msg_free(struct msg *m)
{
    free(m->buf);
}
