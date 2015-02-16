# $Id$

include $(top_srcdir)/Makefile.decl
AM_CPPFLAGS += -I../include -I../base -I../dkim

noinst_LTLIBRARIES = libsauth_dmarc.la

libsauth_dmarc_la_SOURCES = dmarcaligner.c dmarcenum.c dmarcrecord.c publicsuffix.c radtree.c \
	dmarcenum.h dmarcrecord.h dmarcspec.h radtree.h

