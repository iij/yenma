# Copyright (c) 2006-2014 Internet Initiative Japan Inc. All rights reserved.
#
# The terms and conditions of the accompanying program
# shall be provided separately by Internet Initiative Japan Inc.
# Any use, reproduction or distribution of the program are permitted
# provided that you agree to be bound to such terms and conditions.
#
# $Id$

AC_INIT(yenma, 2.0.0-beta4)
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR(yenma/yenma.c)
AC_CONFIG_HEADERS(config.h)
AC_GNU_SOURCE
AM_MAINTAINER_MODE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_SED
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_LIBTOOL
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

progname=yenma

# Checks for libraries.
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(clock_gettime, rt)

# Checks for header files.
AC_CHECK_HEADERS(sys/prctl.h net/if_dl.h tcpd.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_CHECK_FUNCS([prctl])

ACX_PTHREAD([], AC_MSG_ERROR(POSIX thread not found))

AC_ARG_WITH(libmilter,
    AC_HELP_STRING(--with-libmilter=DIR, [specify libmilter base directory]),
    [CPPFLAGS="$CPPFLAGS -I$withval/include" LDFLAGS="$LDFLAGS -L$withval/lib"],
    [CPPFLAGS="$CPPFLAGS -I/usr/local/include" LDFLAGS="$LDFLAGS -L/usr/local/lib"])

AC_ARG_WITH(libbind,
    AC_HELP_STRING(--with-libbind=DIR, [specify libbind base directory]),
    [CPPFLAGS="$CPPFLAGS -I$withval/include/bind" LDFLAGS="$LDFLAGS -L$withval/lib"])

AC_ARG_WITH(ldns,
    AC_HELP_STRING(--with-ldns=DIR, [specify ldns base directory]),
    [CPPFLAGS="$CPPFLAGS -I$withval/include" LDFLAGS="$LDFLAGS -L$withval/lib"])

AC_ARG_WITH(ssl,
    AC_HELP_STRING(--with-ssl=DIR, [specify OpenSSL base directory]),
    [CPPFLAGS="$CPPFLAGS -I$withval/include" LDFLAGS="$LDFLAGS -L$withval/lib"],
    [CPPFLAGS="$CPPFLAGS -I/usr/local/include" LDFLAGS="$LDFLAGS -L/usr/local/lib"])

AC_CHECK_LIB(crypto, EVP_DigestInit, [], [AC_MSG_ERROR(libcrypto not found)])

AC_CHECK_MEMBER([struct smfiDesc.xxfi_negotiate],
    [AC_DEFINE([HAVE_MILTER_XXFI_NEGOTIATE], [1], [defined if smfiDesc struct has xxfi_negotiate member])], [],
    [#include <libmilter/mfapi.h>])

dnl libbind built on Solaris 8 or later depends libmd5
AC_SEARCH_LIBS(MD5Init, md5)

AC_CHECK_LIB(ldns, ldns_resolver_new,
    [AC_DEFINE(HAVE_LIBLDNS, [1], [Define to 1 if you have the `ldns' library (-lldns).])
     LIBS="-lldns ${LIBS}"
     RESOLVER_OBJ="ldnsresolver.lo ${RESOLVER_OBJ}"], [],
    [-lcrypto])

AC_CHECK_LIB(bind, __res_ndestroy,
    [AC_DEFINE(HAVE_LIBBIND, [1], [Define to 1 if you have the `bind' library (-lbind).])
     LIBS="-lbind ${LIBS}"
     RESOLVER_OBJ="bindresolver.lo ${RESOLVER_OBJ}" MILTER_LIBS="-lbind"])

AC_ARG_WITH(libresolv,
    AC_HELP_STRING(--with-libresolv, [use libresolv as resolver instead of libbind (NOT RECOMMENDED)]),
        [AC_DEFINE(USE_LIBRESOLV, [1], [Define to 1 if you have the `resolv' library (-lresolv).])
         LIBS="-lresolv ${LIBS}"
         RESOLVER_OBJ="bindresolver.lo ${RESOLVER_OBJ}" MILTER_LIBS="-lresolv"])

if test "x${RESOLVER_OBJ}" = x; then
    AC_MSG_ERROR(no resolver library found)
fi

AC_CHECK_LIB(milter, smfi_main, [], [AC_MSG_ERROR(libmilter not found or not available)], [${MILTER_LIBS}])

AC_ARG_WITH(libwrap,
    AC_HELP_STRING(--with-libwrap, [use tcpwrapper for control socket]),
    AC_CHECK_LIB(wrap, hosts_access, [], [AC_MSG_ERROR(libwrap not found)])
)

expanded_sysconfdir=`eval echo "${sysconfdir}"`
dnl autoconf 2.70 or later will support ${runstatedir}
expanded_runstatedir=`eval echo "${localstatedir}/run"`

AC_SUBST(expanded_sysconfdir)
AC_SUBST(expanded_runstatedir)
AC_SUBST(RESOLVER_OBJ)
AC_SUBST(LIBTOOL_DEPS)
AC_SUBST(progname)

AC_CONFIG_FILES([Makefile common/Makefile yenma/Makefile tools/Makefile])
AC_CONFIG_FILES([libsauth/Makefile libsauth/base/Makefile libsauth/resolver/Makefile])
AC_CONFIG_FILES([libsauth/spf/Makefile libsauth/dkim/Makefile libsauth/dmarc/Makefile])
AC_CONFIG_FILES([etc/Makefile etc/yenma.conf])
AC_CONFIG_FILES([etc/rc.yenma], [chmod +x etc/rc.yenma])

AC_OUTPUT
