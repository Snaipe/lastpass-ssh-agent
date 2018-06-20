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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "lpass.h"
#include "monad.h"
#include "msg.h"
#include "proto.h"
#include "sensitive.h"
#include "sign.h"
#include "ssh.h"

void send_failure(int conn)
{
    struct msg resp;
    msg_init(SSH_AGENT_FAILURE, &resp);
    msg_send(&resp, conn);
}

void send_success(int conn)
{
    struct msg resp;
    msg_init(SSH_AGENT_SUCCESS, &resp);
    msg_send(&resp, conn);
}

struct req_id_ctx {
    struct msg *resp;
    int sock;
    size_t nkeys;
};

static int concat_id(char *id, char *type, char *pubkey, char *comment, void *cookie)
{
    struct req_id_ctx *ctx = cookie;
    size_t keylen;

    minit();

    mtry(base64_decode_inplace(pubkey, &keylen));
    mtry(msg_appendf(ctx->resp, "ps", pubkey, keylen, comment));

    if (mfailed()) {
        warn("%s: %s", mwhere(), id);
    } else {
        ++ctx->nkeys;
    }
    return 0;
}

int request_identities(int sock, char *buf, size_t len)
{
    minit();

    struct msg resp;

    struct req_id_ctx ctx = {
        .resp = &resp,
        .sock = sock,
        .nkeys = 0,
    };

    mtry(msg_init(SSH_AGENT_IDENTITIES_ANSWER, &resp));

    /* we'll update later the number of keys */
    size_t nkeys_off = resp.length;
    mtry(msg_appendf(&resp, "i", 0));

    mtry(lpass_pubkeys(concat_id, &ctx));

    *(uint32_t *)((char *)resp.buf + nkeys_off) = htonl(ctx.nkeys);

    mtry(msg_send(&resp, sock));

    if (mfailed()) {
        perror(mwhere());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int u32_decode(char **buf, size_t *len, uint32_t *val)
{
    if (*len < sizeof (uint32_t)) {
        errno = EINVAL;
        return -1;
    }

    *val = ntohl(*(uint32_t *)*buf);

    *len -= sizeof (*val);
    *buf += sizeof (*val);
    return 0;
}

static int string_decode(char **buf, size_t *len, char **where, size_t *outlen)
{
    uint32_t strsize;
    if (u32_decode(buf, len, &strsize) == -1) {
        return -1;
    }

    if (strsize > *len) {
        errno = EINVAL;
        return -1;
    }

    *where = *buf;
    *outlen = strsize;

    *len -= strsize;
    *buf += strsize;

    return 0;
}

int sign_request(int sock, char *buf, size_t len)
{
    minit();

    struct msg resp;
    mtry(msg_init(SSH_AGENT_SIGN_RESPONSE, &resp));

    char *pubkey;
    size_t keylen;
    mtry(string_decode(&buf, &len, &pubkey, &keylen));

    char *tbuf = pubkey;
    size_t tlen = keylen;
    char *type;
    size_t typelen;
    mtry(string_decode(&tbuf, &tlen, &type, &typelen));

    char *data;
    size_t datasize;
    mtry(string_decode(&buf, &len, &data, &datasize));

    uint32_t flags = 0;
    mtry(u32_decode(&buf, &len, &flags));

    struct sbuf privkey = { .data = NULL };
    size_t pkeylen;
    mtry(lpass_find_privkey(pubkey, keylen, &privkey, &pkeylen));

    char *sig;
    size_t siglen;
    mtry(sign(data, datasize, type, typelen, flags, &privkey, pkeylen, &sig, &siglen));

    sbuf_free(&privkey);

    if (!mfailed() && !strncmp(type, "ssh-rsa", typelen)) {
        if (flags & SSH_AGENT_RSA_SHA2_256) {
            type = "rsa-sha2-256";
            typelen = strlen(type);
        } else if (flags & SSH_AGENT_RSA_SHA2_512) {
            type = "rsa-sha2-512";
            typelen = strlen(type);
        }
    }

    size_t totalsize = typelen + siglen + 2 * sizeof (uint32_t);

    mtry(msg_appendf(&resp, "ipp", totalsize, type, typelen, sig, siglen));

    mtry(msg_send(&resp, sock));

    if (mfailed()) {
        perror(mwhere());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

proto_fn *protocol[SSH_CODE_NUM] = {
    [SSH_AGENTC_REQUEST_IDENTITIES] = request_identities,
    [SSH_AGENTC_SIGN_REQUEST]       = sign_request,
};
