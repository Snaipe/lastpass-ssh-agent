bin_PROGRAMS = lastpass-ssh-agent

WARNINGS = \
	-Wall -Wextra \
	-Wno-unused-parameter

lastpass_ssh_agent_CFLAGS = -std=c99 -pedantic $(WARNINGS)

lastpass_ssh_agent_SOURCES = \
	base64.c \
	base64.h \
	config.h \
	lpass.c \
	lpass.h \
	monad.h \
	msg.c \
	msg.h \
	proto.c \
	proto.h \
	sensitive.c \
	sensitive.h \
	server.c \
	sign.c \
	sign.h \
	ssh.h \
	utils.c \
	utils.h

install-exec-hook:
	setcap CAP_IPC_LOCK=eip $(DESTDIR)$(bindir)/lastpass-ssh-agent
