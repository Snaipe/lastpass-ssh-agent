AC_INIT([lastpass-ssh-agent], [0.1], [me@snai.pe])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign dist-xz -Wall -Werror])
AM_SILENT_RULES([yes])

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_GNU_SOURCE

AX_DEFINE_DIR([PREFIX], [prefix], "prefix directory")
AX_DEFINE_DIR([LIBEXECDIR], [libexecdir], "libexec directory")

AC_CONFIG_HEADERS([src/config.h])

AC_CONFIG_FILES([Makefile src/Makefile scripts/Makefile])

AC_OUTPUT
