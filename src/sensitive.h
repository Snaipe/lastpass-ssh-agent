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
#ifndef SENSITIVE_H_
#define SENSITIVE_H_

/* Content-sentitive buffer allocation & file API.
   The main use-case is to store temporarily unencrypted private keys,
   and as such, we need to be extra careful. */

struct sbuf {
    void *data;
    size_t size;
};

int sbuf_realloc(struct sbuf *buf, size_t newsize);
void sbuf_wipe(struct sbuf *buf);
int sbuf_free(struct sbuf *buf);

#endif /* !SENSITIVE_H_ */
