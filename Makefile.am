# $Id$

ACLOCAL_AMFLAGS = -I m4
SUBDIRS = libsauth common yenma tools etc
EXTRA_DIST = README.ja INSTALL.ja LICENSE LICENSE.ja TODO.ja example
LIBTOOL_DEPS = @LIBTOOL_DEPS@

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
