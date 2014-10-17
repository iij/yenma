/*
 * Copyright (c) 2008-2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include "ptrop.h"
#include "loghandler.h"
#include "socketreader.h"
#include "socketwriter.h"
#include "xbuffer.h"
#include "protocolhandler.h"

static void
ProtocolHandler_cleanup(ProtocolHandler *self)
{
    if (NULL != self->sreader) {
        SocketReader_free(self->sreader);
        self->sreader = NULL;
    }   // end if
    if (NULL != self->swriter) {
        SocketWriter_free(self->swriter);
        self->swriter = NULL;
    }   // end if
    if (NULL != self->xbuf) {
        XBuffer_free(self->xbuf);
        self->xbuf = NULL;
    }   // end if
}   // end function: ProtocolHandler_cleanup

static int
ProtocolHandler_init(ProtocolHandler *self, int fd)
{
    memset(self, 0, sizeof(ProtocolHandler));
    self->sreader = SocketReader_new(fd);
    if (NULL == self->sreader) {
        LogNoResource();
        goto cleanup;
    }   // end if
    self->swriter = SocketWriter_new(fd);
    if (NULL == self->swriter) {
        LogNoResource();
        goto cleanup;
    }   // end if
    self->xbuf = XBuffer_new(256);
    if (NULL == self->xbuf) {
        LogNoResource();
        goto cleanup;
    }   // end if
    return 0;

  cleanup:
    ProtocolHandler_cleanup(self);
    return -1;
}   // end function: ProtocolHandler_init

/**
 * @param request コマンド行 (NULL 終端, 末尾に改行文字を含まない)
 * @return プロセスを継続する場合は 0, プロセスを終了する場合は非0.
 */
static bool
ProtocolHandler_dispatch(ProtocolHandler *self, const char *request)
{
    LogDebug("request=%s", request);
    const CommandHandlerMap *p;
    const char *cmdtail = strpbrk(request, self->delimiter);
    const char *requesttail = STRTAIL(request);
    for (p = self->handler_table; NULL != p->name; ++p) {
        // リクエスト行の先頭がコマンド名と一致するか調べる
        int cmpstat;
        if (NULL != cmdtail) {
            size_t cmd_len = cmdtail - request;
            cmpstat = strncasecmp(p->name, request, cmd_len);
        } else {
            cmpstat = strcasecmp(p->name, request);
        }   // end if
        if (0 == cmpstat) {
            if (NULL != cmdtail) {
                // コマンド名と引数とのデリミタをスキップする
                for (; cmdtail < requesttail && NULL != strchr(self->delimiter, *cmdtail);
                     ++cmdtail);
            }   // end if
            LogDebug("dispatch=%s, param=%s", p->name, NNSTR(cmdtail));
            return p->handler(self, cmdtail);
        }   // end if
    }   // end for
    return (NULL != p->handler) ? p->handler(self, request) : -1;
}   // end function: ProtocolHandler_dispatch

/**
 * @return プロセスを継続する場合は true, プロセスを終了する場合は false.
 */
int
ProtocolHandler_run(const CommandHandlerMap *handler_table, int fd, void *context)
{
    ProtocolHandler self;
    int ret = ProtocolHandler_init(&self, fd);
    if (0 != ret) {
        return ret;
    }   // end if
    self.context = context;
    self.handler_table = handler_table;
    self.delimiter = " ";
    // SocketReader_setTimeout(self.sreader, 30);
    // SocketWriter_setTimeout(self.swriter, 30);
    // SocketWriter_setWaterMark(self.swriter, BUFSIZ);
    // SocketWriter_setAutoFlush(self.swriter, true);

    while (true) {
        // リクエストの受け付け
        XBuffer_reset(self.xbuf);
        rsockstat_t rsockstat = SocketReader_readStringLine(self.sreader, self.xbuf, 0, NULL);
        switch (rsockstat) {
        case RSOCKSTAT_OK:
            break;

        case RSOCKSTAT_EOF:
            LogNotice("read socket closed unexpectedly");
            goto exitloop;

        case RSOCKSTAT_TIMEOUT:
            LogNotice("read from socket timeout");
            goto exitloop;

        case RSOCKSTAT_READERR:
        case RSOCKSTAT_NORESOURCE:
            LogNotice("read from socket failed: errno=%s", strerror(errno));
            goto exitloop;

        default:
            LogError("MUST NOT REACH HERE");
            abort();
        }   // end switch

        XBuffer_chomp(self.xbuf);
        LogDebug("[request] %s", XBuffer_getString(self.xbuf));
        bool handlerstat = ProtocolHandler_dispatch(&self, XBuffer_getString(self.xbuf));
        wsockstat_t wsockstat = SocketWriter_flush(self.swriter);
        switch (wsockstat) {
        case WSOCKSTAT_OK:
            break;

        case WSOCKSTAT_TIMEOUT:
            LogNotice("write to timeout");
            goto exitloop;

        case WSOCKSTAT_WRITEERR:
        case WSOCKSTAT_NORESOURCE:
            LogNotice("write to socket failed: errno=%s", strerror(errno));
            goto exitloop;

        default:
            LogError("MUST NOT REACH HERE");
            abort();
        }   // end switch
        if (handlerstat) {
            goto exitloop;
        }   // end if
    }   // end while

  exitloop:
    ProtocolHandler_cleanup(&self);
    return 0;
}   // end function: ProtocolHandler_run
