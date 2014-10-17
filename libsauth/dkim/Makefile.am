# $Id$

include $(top_srcdir)/Makefile.decl
CPPFLAGS += -I$(top_srcdir)/libsauth/include -I$(top_srcdir)/libsauth/base

noinst_LTLIBRARIES = libsauth_dkim.la

libsauth_dkim_la_SOURCES = dkimadsp.c dkimatps.c dkimcanonicalizer.c dkimconverter.c dkimdigester.c \
	dkimenum.c dkimpublickey.c dkimsignature.c dkimsigner.c dkimsignpolicy.c \
	dkimtaglistobject.c dkimverificationpolicy.c dkimverifier.c dkimwildcard.c \
	dkimadsp.h dkimatps.h dkimcanonicalizer.h dkimconverter.h dkimdigester.h dkimenum.h \
	dkimlogger.h dkimpublickey.h dkimsignature.h dkimsignpolicy.h dkimspec.h \
	dkimtaglistobject.h dkimverificationpolicy.h dkimwildcard.h

dstat.map: $(top_srcdir)/libsauth/include/dkim.h
	rm -f $@
	grep DSTAT_ $< | grep -v define | $(SED) -e 's/\(DSTAT_[A-Z0-9_]*\).*/CODE2STRMAP(\1),/' > $@

dkimenum.c: dstat.map

clean-local:
	-rm -f dstat.map
