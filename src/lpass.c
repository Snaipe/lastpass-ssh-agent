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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "sensitive.h"
#include "utils.h"

/* This is *really* insecure. We call `lpass` to retrieve our private keys,
   which is terrible on a security standpoint, because we leak unencrypted
   private keys to RAM and/or swap. This is just done right now out of
   convenience and needs to be replaced before release. */
static int popen_lines(const char *exe, int (*fn)(char *, void *), void *cookie)
{
    int rc = 0;

    FILE *out = popen(exe, "r");
    if (!out) {
        return -1;
    }

    char *line = NULL;
    size_t size = 0;

    errno = 0;
    while ((rc = getline(&line, &size, out)) != -1) {
        rc = fn(line, cookie);
        if (rc != 0) {
            break;
        }

        errno = 0;
    }

    if (rc == -1 && errno) {
        perror("getline");
    } else {
        rc = 0;
    }

    struct sbuf rest = { .data = NULL };
    if (sbuf_realloc(&rest, 4096) == -1) {
        perror("sbuf_realloc");
        abort();
    }
    while (!feof(out)) {
        fread(rest.data, 1, 4096, out);
    }
    sbuf_free(&rest);

    free(line);
    if (pclose(out) != EXIT_SUCCESS) {
        errno = ENOTSUP;
        return -1;
    }
    return rc == -1 ? -1 : 0;
}

struct cut_pubkey_ctx {
    int (*fn)(char *, char *, char *, char *, void *);
    void *cookie;
};

static int cut_pubkey(char *line, void *cookie)
{
    struct cut_pubkey_ctx *ctx = cookie;

    char *id = strtok(line, ":");
    char *type = strtok(NULL, " ");
    char *pubkey = strtok(NULL, " ");
    char *comment = strtok(NULL, "\n");

    if (strlen(id) == 0 || strlen(type) == 0 || strlen(pubkey) == 0) {
        warnx("invalid pubkey %s:%s\n", id, pubkey);
        return 0;
    }

    return ctx->fn(id, type, pubkey, comment, ctx->cookie);
}

int lpass_pubkeys(int (*fn)(char *, char *, char *, char *, void *), void *cookie)
{
    struct cut_pubkey_ctx ctx = {
        .fn = fn,
        .cookie = cookie,
    };
    return popen_lines(LIBEXECDIR "/lastpass-ssh-agent/pubkeys", cut_pubkey, &ctx);
}

struct find_privkey_ctx {
    void *pubkey;
    size_t keylen;
    struct sbuf *privkey;
    size_t *pkeylen;
    int match;
};

static char *cut_field(char *what, char **save)
{
    if (what)
        *save = what;

    char *cur = *save;

    if (!cur)
        return cur;

    char *nl = cur - 1;

    while ((nl = strchr(nl + 1, '\n'))) {

        int field = 0;
        for (char *s = nl + 1; !field && *s && *s != '\n'; ++s) {
            field = *s == ':' && s[1] != ' ';
        }

        if (field) {
            *nl = 0;
            *save = nl + 1;
            break;
        }
    }
    if (!nl) {
        *save = NULL;
    }

    return cur;
}

static int match_key(char *payload, void *cookie)
{
    struct find_privkey_ctx *ctx = cookie;

    char *payload_end = payload + strlen(payload);

    char *dst = payload;
    for (char *s = payload; *s; ++s, ++dst) {
        if (s[0] == '\\' && s[1] == 'n') {
            *dst = '\n';
            ++s;
            continue;
        }

        *dst = *s;
    }
    *dst = 0;

    const char pubkey_prefix[] = "Public Key:";
    const char privkey_prefix[] = "Private Key:";

    int match = 0;
    char *save;

    for (char *line = cut_field(payload, &save); line; line = cut_field(NULL, &save)) {

        if (!strncmp(line, pubkey_prefix, sizeof (pubkey_prefix) - 1)) {
            line += sizeof (pubkey_prefix) - 1;

            char *type = strtok(line, " ");
            char *base64 = strtok(NULL, " ");

            if (!type || !base64) {
                return 0;
            }

            size_t keysize;
            if (base64_decode_inplace(base64, &keysize) == -1) {
                perror("base64_decode_inplace");
                return 0;
            }

            if (ctx->keylen != keysize) {
                return 0;
            }
            match = 1;
        } else if (!strncmp(line, privkey_prefix, sizeof (privkey_prefix) - 1)) {
            line += sizeof (privkey_prefix) - 1;

            size_t len = strlen(line);

            if (sbuf_realloc(ctx->privkey, len) == -1) {
                perror("sbuf_realloc");
                return 0;
            }

            memcpy(ctx->privkey->data, line, len);
            *ctx->pkeylen = len;
        }
        if (match && *ctx->pkeylen) {
            break;
        }
    }

    memset(payload, 0, (size_t)(payload_end - payload));

    ctx->match = match;
    if (!ctx->match) {
        sbuf_free(ctx->privkey);
        *ctx->pkeylen = 0;
    }

    return ctx->match;
}

int lpass_find_privkey(void *pubkey, size_t keylen, struct sbuf *privkey, size_t *pkeylen)
{
    struct find_privkey_ctx ctx = {
        .pubkey = pubkey,
        .keylen = keylen,
        .privkey = privkey,
        .pkeylen = pkeylen,
    };
    return popen_lines(LIBEXECDIR "/lastpass-ssh-agent/privkeys", match_key, &ctx);
}
