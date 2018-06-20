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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sign.h"
#include "ssh.h"

/* This is really dumb and not ideal, but it works. This needs to be replaced
   with proper openssl code before release. */
int sign(char *data, size_t datasize, char *type, size_t typesize,
        uint32_t flags, struct sbuf *privkey, size_t pkeylen,
        char **sig, size_t *siglen)
{
    /* data pipe */
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return -1;
    }

    /* key pipe */
    int kpipefd[2];
    if (pipe(kpipefd) == -1) {
        perror("pipe");
        return -1;
    }

    /* output pipe */
    int opipefd[2];
    if (pipe(opipefd) == -1) {
        perror("pipe");
        return -1;
    }

    char *shaopt = "";
    if (!strncmp(type, "ssh-rsa", typesize)) {
        if (flags & SSH_AGENT_RSA_SHA2_256) {
            shaopt = "-sha256";
        } else if (flags & SSH_AGENT_RSA_SHA2_512) {
            shaopt = "-sha512";
        }
    }

    char cmdline[4096];
    snprintf(cmdline, sizeof (cmdline),
            "openssl dgst -sign /proc/self/fd/%d %s -",
            kpipefd[0], shaopt);

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return -1;
    }

    close(pipefd[!pid]);
    close(kpipefd[!pid]);
    close(opipefd[!!pid]);
    if (!pid) {
        dup2(pipefd[0], STDIN_FILENO);
        dup2(opipefd[1], STDOUT_FILENO);
        execl("/bin/sh", "sh", "-c", cmdline, NULL);
        _exit(1);
    }

    if (write(kpipefd[1], privkey->data, pkeylen) == -1) {
        perror("write");
        return -1;
    }

    if (write(pipefd[1], data, datasize) == -1) {
        perror("write");
        return -1;
    }

    close(kpipefd[1]);
    close(pipefd[1]);

    *siglen = 0;

    size_t bufsize = 0;
    char *buf = NULL;
    for (;;) {
        bufsize += 4096;
        char *nbuf = realloc(buf, bufsize);
        if (!nbuf) {
            perror("realloc");
            return -1;
        }
        buf = nbuf;

        ssize_t rd = read(opipefd[0], buf + bufsize - 4096, 4096);
        if (rd == -1) {
            perror("read");
            return -1;
        }
        *siglen += rd;
        if (rd < 4096) {
            break;
        }
    }

    close(opipefd[0]);

    *sig = buf;

    int status;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }

    fprintf(stderr, "waited for %d\n", pid);

    return 0;
}
