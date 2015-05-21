/*
 * Copyright (c) 2006-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __DKIM_CONVERTER_H__
#define __DKIM_CONVERTER_H__

#include "xbuffer.h"
#include "dkim.h"
#include "dkimenum.h"

#ifdef __cplusplus
extern "C" {
#endif

extern XBuffer *DkimConverter_decodeBase64(const char *head,
                                           const char *tail, const char **nextp, DkimStatus *dstat);
extern XBuffer *DkimConverter_encodeBase64(const void *s, size_t size, DkimStatus *dstat);
extern DkimStatus DkimConverter_encodeBaseX16(const void *s, size_t size, XBuffer *xbuf);
extern DkimStatus DkimConverter_encodeBaseX32(const void *s, size_t size, XBuffer *xbuf);
extern DkimStatus DkimConverter_encodeBaseX32Hex(const void *s, size_t size, XBuffer *xbuf);
extern DkimStatus DkimConverter_encodeBaseX64(const void *s, size_t size, XBuffer *xbuf);
extern XBuffer *DkimConverter_encodeLocalpartToDkimQuotedPrintable(const void *s, size_t size,
                                                                   DkimStatus *dstat);
extern long long DkimConverter_longlong(const char *head, const char *tail, unsigned int digits,
                                        const char **nextp);

#ifdef __cplusplus
}
#endif

#endif /* __DKIM_CONVERTER_H__ */
