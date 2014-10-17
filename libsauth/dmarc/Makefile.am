# $Id$

include $(top_srcdir)/Makefile.decl
CPPFLAGS += -I$(top_srcdir)/libsauth/include -I$(top_srcdir)/libsauth/base -I$(top_srcdir)/libsauth/dkim

noinst_LTLIBRARIES = libsauth_dmarc.la

libsauth_dmarc_la_SOURCES = dmarcaligner.c dmarcenum.c dmarcrecord.c publicsuffix.c radtree.c \
	dmarcenum.h dmarcrecord.h dmarcspec.h radtree.h

