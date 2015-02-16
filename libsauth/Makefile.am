# $Id$

SUBDIRS = base resolver spf dkim dmarc
noinst_HEADERS = include

include $(top_srcdir)/Makefile.decl

LIBSAUTH_VERSIONINFO = 0:0:0

lib_LTLIBRARIES = libsauth.la
libsauth_la_SOURCES =
libsauth_la_LIBADD = base/libsauth_base.la resolver/libsauth_resolver.la spf/libsauth_spf.la \
	dkim/libsauth_dkim.la dmarc/libsauth_dmarc.la
libsauth_la_LDFLAGS = $(PTHREAD_LIBS) -version-info $(LIBSAUTH_VERSIONINFO)
