/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __XBUFFER_H__
#define __XBUFFER_H__

#include <sys/types.h>
#include <stdarg.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct XBuffer XBuffer;
typedef size_t xbuffer_savepoint_t;

extern int XBuffer_appendByte(XBuffer *self, unsigned char b);
extern int XBuffer_appendBytes(XBuffer *self, const void *b, size_t size);
extern int XBuffer_appendXBuffer(XBuffer *self, const XBuffer *xbuf);
extern int XBuffer_appendChar(XBuffer *self, char c);
extern int XBuffer_appendFormatString(XBuffer *self, const char *format, ...)
    __attribute__ ((format(printf, 2, 3)));
extern int XBuffer_appendVFormatString(XBuffer *self, const char *format, va_list ap);
extern int XBuffer_appendVFormatStringN(XBuffer *self, size_t len, const char *format, va_list ap);
extern int XBuffer_appendString(XBuffer *self, const char *s);
extern int XBuffer_appendStringN(XBuffer *self, const char *s, size_t len);
extern void XBuffer_chomp(XBuffer *self);
extern bool XBuffer_compareToBytes(const XBuffer *self, const void *b, size_t size);
extern bool XBuffer_compareToString(const XBuffer *self, const char *s);
extern bool XBuffer_compareToStringIgnoreCase(const XBuffer *self, const char *s);
extern bool XBuffer_compareToStringN(const XBuffer *self, const char *s, size_t len);
extern bool XBuffer_compareToStringNIgnoreCase(const XBuffer *self, const char *s, size_t len);
extern void *XBuffer_dupBytes(const XBuffer *self);
extern char *XBuffer_dupString(const XBuffer *self);
extern void XBuffer_free(XBuffer *self);
extern const void *XBuffer_getBytes(const XBuffer *self);
extern const char *XBuffer_getString(const XBuffer *self);
extern size_t XBuffer_getSize(const XBuffer *self);
extern XBuffer *XBuffer_new(size_t size);
extern int XBuffer_reserve(XBuffer *self, size_t size);
extern void XBuffer_reset(XBuffer *self);
extern void XBuffer_rollback(XBuffer *self, xbuffer_savepoint_t savepoint);
extern xbuffer_savepoint_t XBuffer_savepoint(const XBuffer *self);
extern void XBuffer_setGrowth(XBuffer *self, size_t growth);
extern int XBuffer_status(const XBuffer *self);

#ifdef __cplusplus
}
#endif

#endif /* __XBUFFER_H__ */
