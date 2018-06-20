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

#include <arpa/inet.h>
#include <err.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "monad.h"
#include "proto.h"

#define SOCKPATH "/run/user/%d/lastpass-ssh-agent/agent.sock"

static int init(void)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        err(EXIT_FAILURE, "socket");
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    snprintf(addr.sun_path, sizeof (addr.sun_path), SOCKPATH, getuid());
    char *dir = dirname(addr.sun_path);
    while (mkdir(dir, 0700) != -1) {
        dir = dirname(dir);
    }
    if (errno != EEXIST) {
        err(EXIT_FAILURE, "mkdir");
    }
    snprintf(addr.sun_path, sizeof (addr.sun_path), SOCKPATH, getuid());
    unlink(addr.sun_path);

    if (bind(sock, (struct sockaddr *) &addr, sizeof (addr)) == -1) {
        err(EXIT_FAILURE, "bind");
    }

    if (listen(sock, 16) == -1) {
        err(EXIT_FAILURE, "listen");
    }

    return sock;
}

static int handle(int sock)
{
    {
        ssize_t rd;
        uint32_t len;
        if ((rd = read(sock, &len, sizeof (len))) == -1) {
            warn("read: length");
            goto err;
        }

        /* some clients probe the agent by sending empty messages */
        if (rd == 0) {
            return EXIT_SUCCESS;
        }

        if (rd != sizeof (len)) {
            warnx("read: not enough bytes for length");
            goto err;
        }

        len = ntohl(len);
        if (len == 0) {
            warnx("read: empty message");
            goto err;
        }

        char buffer[len];

        if (read(sock, buffer, len) < (ssize_t) len) {
            warn("read: buffer");
            goto err;
        }

        uint8_t type = buffer[0];
        if (!type || type >= SSH_CODE_NUM || !protocol[type]) {
            warnx("protocol: unknown code %hhu.", type);
            goto err;
        }

        if (protocol[type](sock, buffer + 1, len - 1) != EXIT_SUCCESS) {
            goto err;
        }
        return EXIT_SUCCESS;
    }
err:
    send_failure(sock);
    return EXIT_FAILURE;
}

static void reap(int sig)
{
    int status;
    waitpid(-1, &status, 0);

    if (WIFSIGNALED(status)) {
        fprintf(stderr, "child crashed with %s\n", sys_siglist[WTERMSIG(status)]);
    } else if (WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS) {
        fprintf(stderr, "child exited with %d\n", WEXITSTATUS(status));
    }
}

static void server_run(void)
{
    minit();

    int sock = init();

    signal(SIGCHLD, reap);

    for (;;) {
        int conn;
        mtry(conn = accept(sock, NULL, NULL));

        pid_t pid;
        mtry(pid = fork());

        if (mfailed()) {
            perror(mwhere());
            continue;
        }

        if (pid) {
            close(conn);
            continue;
        }

        signal(SIGCHLD, SIG_DFL);

        int rc = EXIT_SUCCESS;

        while (rc != EXIT_FAILURE) {
            errno = 0;
            rc = handle(conn);
        }

        close(conn);
        exit(rc);
    }
}

int main(int argc, char *argv[])
{
    server_run();
    return EXIT_SUCCESS;
}
