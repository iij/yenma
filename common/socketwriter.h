/*
 * Copyright (c) 2008-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef _SOCKET_WRITER_H_
#define _SOCKET_WRITER_H_

#include <sys/types.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _wsock_stat {
    WSOCKSTAT_OK = 0,
    WSOCKSTAT_TIMEOUT,
    WSOCKSTAT_WRITEERR,
    WSOCKSTAT_NORESOURCE,
} wsockstat_t;

struct SocketWriter;
typedef struct SocketWriter SocketWriter;

extern bool SocketWriter_ignoreSigPipe(void);
extern SocketWriter *SocketWriter_new(int fd);
extern void SocketWriter_free(SocketWriter *self);
extern void SocketWriter_setTimeout(SocketWriter *self, time_t timeout);
extern void SocketWriter_setAbsoluteTimeout(SocketWriter *self, time_t timeout);
extern void SocketWriter_setAutoFlush(SocketWriter *self, bool autoflush);
extern void SocketWriter_setWaterMark(SocketWriter *self, size_t watermark);
extern void SocketWriter_reset(SocketWriter *self);
extern void SocketWriter_clearError(SocketWriter *self);
extern wsockstat_t SocketWriter_checkError(const SocketWriter *self);
extern wsockstat_t SocketWriter_flush(SocketWriter *self);
extern wsockstat_t SocketWriter_writeString(SocketWriter *self, const char *s);
extern wsockstat_t SocketWriter_writeByte(SocketWriter *self, unsigned char c);
extern wsockstat_t SocketWriter_writeBytes(SocketWriter *self, const void *p, size_t size);
extern wsockstat_t SocketWriter_writeFormatString(SocketWriter *self, const char *format, ...)
    __attribute__ ((format(printf, 2, 3)));
extern wsockstat_t SocketWriter_writeVFormatString(SocketWriter *self, const char *format,
                                                   va_list ap);

#ifdef __cplusplus
}
#endif

#endif /* _SOCKET_WRITER_H_ */
