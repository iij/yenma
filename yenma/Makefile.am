# $Id$

include $(top_srcdir)/Makefile.decl

libexec_PROGRAMS = yenma

yenma_SOURCES =yenma.c yenmamfi.c yenmasession.c yenmaconfig.c yenmacontext.c yenmactrl.c \
	authstats.c authresult.c validatedresult.c ipaddrblocktree.c rbtree.c resolverpool.c \
	authresult.h authstats.h yenma.h yenmaconfig.h yenmacontext.h yenmactrl.h yenmasession.h \
	ipaddrblocktree.h rbtree.h resolverpool.h validatedresult.h

yenma_LDADD = ../common/libyenma_common.a ../libsauth/libsauth.la
yenma_LDFLAGS = -lmilter -lcrypto $(PTHREAD_LIBS)
