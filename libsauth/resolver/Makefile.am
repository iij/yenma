# $Id$

include $(top_srcdir)/Makefile.decl
AM_CPPFLAGS += -I$(top_srcdir)/libsauth/include

noinst_LTLIBRARIES = libsauth_resolver.la

libsauth_resolver_la_SOURCES = dnsresolv.c dnsresolv_internal.h 
EXTRA_libsauth_resolver_la_SOURCES = bindresolver.c ldnsresolver.c \
	bindresolver.h ldnsresolver.h
libsauth_resolver_la_LIBADD = $(RESOLVER_OBJ)
libsauth_resolver_la_DEPENDENCIES = $(RESOLVER_OBJ)
