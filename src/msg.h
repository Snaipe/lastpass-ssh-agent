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
#ifndef MSG_H_
#define MSG_H_

#include <stddef.h>

struct msg {
    size_t size;
    size_t length;
    void *buf;
};

int msg_init(int code, struct msg *m);
int msg_append(struct msg *m, const void *bytes, size_t size);
int msg_appendf(struct msg *m, const char *fmt, ...);
int msg_send(struct msg *m, int sock);
void msg_free(struct msg *m);

#endif /* !MSG_H_ */
