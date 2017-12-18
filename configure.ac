#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.65)
AC_INIT([mod_authz_zakautho], [0.0.1], [azagli@libero.it])
AC_CONFIG_SRCDIR([src/mod_authz_zakautho.c])
AC_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE(-Wall)

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_SYSTEM

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AC_PATH_PROG(APXS, 'apxs', [no])
AC_PATH_PROG(APXS2, 'apxs2', [no])
if test x"$APXS" == "xno" -a x"$APXS2" == "xno" ; then
	AC_MSG_ERROR([apxs command missing please install apache development package])
fi
if test x"$APXS2" != "xno" ; then
   APXS="$APXS2"
fi

# Checks for libraries.
PKG_CHECK_MODULES(MOD_AUTHZ_ZAKAUTHO, [apr-1
                                       apr-util-1
                                       libzakautho])

AC_SUBST(MOD_AUTHZ_ZAKAUTHO_CFLAGS)
AC_SUBST(MOD_AUTHZ_ZAKAUTHO_LIBS)

# Checks for header files.
AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.

# Checks for library functions.

dnl ******************************
dnl Check for Operating System
dnl ******************************

platform_win32=no

case "$host" in
*-mingw*)
    platform_win32=yes
    ;;
esac

AM_CONDITIONAL(PLATFORM_WIN32, [test $platform_win32 = yes])

# Output files
AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
