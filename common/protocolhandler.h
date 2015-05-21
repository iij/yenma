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

#ifndef __PROTOCOL_HANDLER_H__
#define __PROTOCOL_HANDLER_H__

#include <stdbool.h>
#include "xbuffer.h"
#include "socketreader.h"
#include "socketwriter.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CommandHandlerMap CommandHandlerMap;

typedef struct ProtocolHandler {
    SocketReader *sreader;
    SocketWriter *swriter;
    XBuffer *xbuf;
    const CommandHandlerMap *handler_table;
    const char *delimiter;
    void *context;
} ProtocolHandler;

struct CommandHandlerMap {
    const char *name;           // コマンドとして認識する文字列
    bool (*handler) (ProtocolHandler *handler, const char *param);
};

extern int ProtocolHandler_run(const CommandHandlerMap *handler_table, int fd, void *context);

#ifdef __cplusplus
}
#endif

#endif /* __PROTOCOL_HANDLER_H__ */
