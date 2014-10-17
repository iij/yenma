/*
 * Copyright (c) 2006-2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __XPARSE_H__
#define __XPARSE_H__

#include "xbuffer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*xparse_funcp) (const char *, const char *, const char **, XBuffer *);

extern int XParse_char(const char *head, const char *tail, char c, const char **nextp,
                       XBuffer *xbuf);

// RFC 2822
extern int XParse_dotAtomText(const char *head, const char *tail, const char **nextp,
                              XBuffer *xbuf);
extern int XParse_2822LocalPart(const char *head, const char *tail, const char **nextp,
                                XBuffer *xbuf);
extern int XParse_2822Domain(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);

// RFC 2821
extern int XParse_2821LocalPart(const char *head, const char *tail, const char **nextp,
                                XBuffer *xbuf);
extern int XParse_5321LocalPart(const char *head, const char *tail, const char **nextp,
                                XBuffer *xbuf);
extern int XParse_smtpLocalPart(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);
extern int XParse_2821Domain(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);
extern int XParse_dotString(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);
extern int XParse_cfws(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);

// RFC 6376
extern int XParse_selector(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);
extern int XParse_domainName(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);
extern int XParse_dkimQuotedPrintable(const char *head, const char *tail, const char **nextp,
                                      XBuffer *xbuf);

// RFC 3461
extern int XParse_realDomain(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);

// RFC 2554
extern int XParse_xtext(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);

#ifdef __cplusplus
}
#endif

#endif /* __XPARSE_H__ */
