/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef _SOCKET_READER_H_
#define _SOCKET_READER_H_

#include <sys/types.h>
#include <stdbool.h>
#include "xbuffer.h"

typedef enum _rsock_stat {
    RSOCKSTAT_OK = 0,
    RSOCKSTAT_TIMEOUT,
    RSOCKSTAT_EOF,
    RSOCKSTAT_READERR,
    RSOCKSTAT_NORESOURCE,
} rsockstat_t;

struct SocketReader;
typedef struct SocketReader SocketReader;

extern SocketReader *SocketReader_new(int fd);
extern void SocketReader_free(SocketReader *self);
extern void SocketReader_setTimeout(SocketReader *self, time_t timeout);
extern void SocketReader_setAbsoluteTimeout(SocketReader *self, time_t timeout);
extern rsockstat_t SocketReader_isAlive(SocketReader *self);
extern rsockstat_t SocketReader_read(SocketReader *self, void *buf, size_t buflen, size_t *readlen);
extern rsockstat_t SocketReader_readLine(SocketReader *self, void *buf, size_t buflen,
                                         size_t *readlen);
extern rsockstat_t SocketReader_readString(SocketReader *self, XBuffer *xbuf, size_t nbyte,
                                           size_t *readlen);
extern rsockstat_t SocketReader_readStringLine(SocketReader *self, XBuffer *xbuf, size_t limitlen,
                                               size_t *readlen);

#endif /* _SOCKET_READER_H_ */
