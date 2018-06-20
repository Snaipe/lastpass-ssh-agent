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
#ifndef PROTO_H_
#define PROTO_H_

#include "ssh.h"

typedef int proto_fn(int, char *, size_t);

void send_failure(int conn);
void send_success(int conn);

extern proto_fn *protocol[SSH_CODE_NUM];

#endif /* !PROTO_H_ */
