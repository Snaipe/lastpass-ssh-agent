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
#ifndef MONAD_H_
#define MONAD_H_

#include <errno.h>

#define minit() int _try_ok = 1; int _try_err; const char *_try_where; (void) _try_where; (void) _try_err
#define mtry(expr) do { \
    if (_try_ok && !(_try_ok = (expr) != -1)) { \
        _try_where = #expr; \
        _try_err = errno; \
    } \
} while (0)
#define mfailed() (!_try_ok && (errno = _try_err))
#define mwhere() (_try_where)
#define merr() (_try_err)

#endif /* !MONAD_H_ */
