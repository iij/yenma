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

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include "timeop.h"
#include "stdaux.h"
#include "xbuffer.h"
#include "socketwriter.h"

#define RETURN_IF_SOCKETERROR(__self) \
  do { \
      if (WSOCKSTAT_OK != (__self)->last_error) { \
          return (__self)->last_error; \
      } \
  } while(0)

struct SocketWriter {
    int fd;
    XBuffer *buf;
    bool autoflush;
    // autoflush 時にバッファをフラッシュする閾値, 0 だと毎回フラッシュ
    size_t watermark;
    // 1回の書き出しに対するタイムアウト [sec]
    time_t op_timeout;
    // 複数の書き出しをまたぐタイムアウト
    struct timeval abs_timeout;
    // 最後に発生したエラー
    wsockstat_t last_error;
};

/**
 * SIGPIPE を無視する.
 * 初期化処理中に呼び出すことを想定している.
 */
bool
SocketWriter_ignoreSigPipe(void)
{
    struct sigaction act;

    act.sa_handler = SIG_IGN;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGPIPE);
    act.sa_flags = 0;
    return bool_cast(0 == sigaction(SIGPIPE, &act, NULL));
}   // end function: SocketWriter_ignoreSigPipe

/**
 * SocketWriter オブジェクトを構築する.
 * @param fd ラップするディスクリプタ
 * @return 初期化済みの SocketWriter オブジェクト
 */
SocketWriter *
SocketWriter_new(int fd)
{
    SocketWriter *self = (SocketWriter *) malloc(sizeof(SocketWriter));
    if (NULL == self) {
        return NULL;
    }   // end if

    self->buf = XBuffer_new(0);
    if (NULL == self->buf) {
        goto cleanup;
    }   // end if
    self->fd = fd;
    self->autoflush = false;
    self->op_timeout = 0;
    self->watermark = 0;
    timerclear(&(self->abs_timeout));
    self->last_error = WSOCKSTAT_OK;

    return self;

  cleanup:
    SocketWriter_free(self);
    return NULL;
}   // end function: SocketWriter_new

/**
 * SocketWriter オブジェクトを解放する.
 * @param self SocketWriter オブジェクト
 * @note バッファのフラッシュ, ソケットのクローズなどはおこなわない.
 */
void
SocketWriter_free(SocketWriter *self)
{
    if (NULL == self) {
        return;
    }   // end if

    XBuffer_free(self->buf);
    free(self);
}   // end function: SocketWriter_free

/**
 * タイムアウトの設定をおこなう.
 * @param timeout ディスクリプタが準備できるまで待つ秒数.
 *                0以下を指定した場合はタイムアウトしない.
 *                デフォルトは 0 (タイムアウトしない).
 */
void
SocketWriter_setTimeout(SocketWriter *self, time_t timeout)
{
    assert(NULL != self);
    self->op_timeout = timeout;
}   // end function: SocketWriter_setTimeout

void
SocketWriter_setAbsoluteTimeout(SocketWriter *self, time_t timeout)
{
    assert(NULL != self);
    if (timeout > 0) {
        gettimeofday(&(self->abs_timeout), NULL);
        self->abs_timeout.tv_sec += timeout;
    } else {
        timerclear(&(self->abs_timeout));
    }   // end if
}   // end function: SocketWriter_setAbsoluteTimeout

static bool
SocketWriter_checkWaterMark(const SocketWriter *self)
{
    return self->autoflush && self->watermark < XBuffer_getSize(self->buf);
}   // end function: SocketWriter_checkWaterMark

/*
 * autoflush が true の場合, SocketWriter_writeXXX() メソッドはバッファにデータを追加し,
 * バッファのデータが一定以上になった場合に, 蓄えていたデータをソケットに書き出す.
 *
 * autoflush が false の場合, SocketWriter_writeXXX() メソッドはバッファにデータを追加するだけで,
 * 決してソケットに書き込むことはない.
 * バッファに蓄えたデータは SocketWriter_flush() メソッドによってソケットに書き出される.
 *
 * バッファに蓄えるデータの量は SocketWriter_setWaterMark() メソッドで設定する.
 *
 * @param self SocketWriter オブジェクト
 * @param autoflush autoflush を有効にする場合は true, 無効にする場合は false.
 */
void
SocketWriter_setAutoFlush(SocketWriter *self, bool autoflush)
{
    assert(NULL != self);
    self->autoflush = autoflush;
}   // end function: SocketWriter_setAutoFlush

/*
 * バッファに蓄えるデータの量を設定する.
 * SocketWriter が蓄えるデータがこのメソッドで指定した量を超えた際に,
 * バッファに蓄えていたデータをソケットに書き出す.
 *
 * @param self SocketWriter オブジェクト
 * @param watermark バッファのフラッシュをトリガーする閾値
 * @note 初期値は 0 であり, 1バイト以上の書き込みに対して毎回ソケットをフラッシュする.
 */
void
SocketWriter_setWaterMark(SocketWriter *self, size_t watermark)
{
    assert(NULL != self);
    self->watermark = watermark;
}   // end function: SocketWriter_setWaterMark

/**
 * まだソケットに書き出していない, バッファに蓄えているデータを破棄する.
 * それまでに発生したソケット書き込みエラーも破棄する.
 * @param self SocketWriter オブジェクト
 */
void
SocketWriter_reset(SocketWriter *self)
{
    assert(NULL != self);
    self->last_error = WSOCKSTAT_OK;
    XBuffer_reset(self->buf);
}   // end function: SocketWriter_reset

/**
 * それまでに発生したソケット書き込みエラーを破棄する.
 * @param self SocketWriter オブジェクト
 */
void
SocketWriter_clearError(SocketWriter *self)
{
    assert(NULL != self);
    self->last_error = WSOCKSTAT_OK;
}   // end function: SocketWriter_clearError

/**
 * これまでに発生した書き込みエラーを取得する.
 *
 * @param self FileWriter オブジェクト.
 * @param error 取得したエラー内容の格納場所.
 * @return これまでに発生したエラーを示すステータスコード.
 */
wsockstat_t
SocketWriter_checkError(const SocketWriter *self)
{
    assert(NULL != self);
    return self->last_error;
}   // end function: SocketWriter_checkError

/**
 * バッファに蓄えているデータをソケットに書き出す.
 * ただし, それまでにソケット書き込みエラーが発生している場合は, 実際の書き出しはおこなわない.
 * @param self SocketWriter オブジェクト
 */
wsockstat_t
SocketWriter_flush(SocketWriter *self)
{
    assert(NULL != self);
    RETURN_IF_SOCKETERROR(self);

    // バッファが空の場合は何もしない
    if (0 == XBuffer_getSize(self->buf)) {
        return WSOCKSTAT_OK;
    }   // end if

    size_t writelen = 0;
    do {
        fd_set wfdset;
        int select_stat;
        struct timeval *timeoutp;
        struct timeval time_left;

        do {
            FD_ZERO(&wfdset);
            FD_SET(self->fd, &wfdset);
            // Linux では timeval 構造体が上書きされるので毎回セットする必要がある
            timeoutp = NULL;
            if (timerisset(&(self->abs_timeout))) {
                struct timeval now;
                gettimeofday(&now, NULL);
                timersub(&now, &(self->abs_timeout), &time_left);
                if (!timerispositive(&time_left)) {
                    // 既に abs_timeout を過ぎている
                    return self->last_error = WSOCKSTAT_TIMEOUT;
                }   // end if
                timeoutp = &time_left;
            }
            if (self->op_timeout > 0 && (NULL == timeoutp || self->op_timeout <= timeoutp->tv_sec)) {
                time_left.tv_sec = self->op_timeout;
                time_left.tv_usec = 0;
                timeoutp = &time_left;
            }
            // select(2) はタイムアウトした場合は 0, エラーの場合は -1 を返す
            select_stat = select(self->fd + 1, NULL, &wfdset, NULL, timeoutp);
        } while (-1 == select_stat && EINTR == errno);

        switch (select_stat) {
        case 0:
            return self->last_error = WSOCKSTAT_TIMEOUT;

        case -1:
            return self->last_error = WSOCKSTAT_WRITEERR;

        default:
            // do nothing
            break;
        }   // end switch

        if (FD_ISSET(self->fd, &wfdset)) {
            ssize_t write_stat;
            SKIP_EINTR(write_stat =
                       write(self->fd, XBuffer_getBytes(self->buf) + writelen,
                             XBuffer_getSize(self->buf) - writelen));
            if (-1 == write_stat) {
                return self->last_error = WSOCKSTAT_WRITEERR;
            }   // end if
            writelen += write_stat;
        }   // end if
    } while (writelen < XBuffer_getSize(self->buf));

    XBuffer_reset(self->buf);
    return WSOCKSTAT_OK;
}   // end function: SocketWriter_flush

static wsockstat_t
SocketWriter_autoflush(SocketWriter *self)
{
    return SocketWriter_checkWaterMark(self) ? SocketWriter_flush(self) : WSOCKSTAT_OK;
}   // end function: SocketWriter_autoflush

/**
 * 書き込みソケット用バッファに文字列を追加する.
 * ただし, autoflush が有効な場合は watermark と比較の上, バッファの内容がソケットにフラッシュされる場合がある.
 * また, それまでにソケット書き込みエラーが発生している場合は, 実際の書き出しはおこなわない.
 * @param self SocketWriter オブジェクト
 * @param s 書き出す NULL 終端文字列
 */
wsockstat_t
SocketWriter_writeString(SocketWriter *self, const char *s)
{
    assert(NULL != self);
    assert(NULL != s);
    RETURN_IF_SOCKETERROR(self);
    if (0 > XBuffer_appendString(self->buf, s)) {
        return self->last_error = WSOCKSTAT_NORESOURCE;
    }   // end if
    return SocketWriter_autoflush(self);
}   // end function: SocketWriter_writeString

/**
 * 書き込みソケット用バッファにバイトを追加する.
 * ただし, autoflush が有効な場合は watermark と比較の上, バッファの内容がソケットにフラッシュされる場合がある.
 * また, それまでにソケット書き込みエラーが発生している場合は, 実際の書き出しはおこなわない.
 * @param self SocketWriter オブジェクト
 * @param c 書き出す文字
 */
wsockstat_t
SocketWriter_writeByte(SocketWriter *self, unsigned char c)
{
    assert(NULL != self);
    RETURN_IF_SOCKETERROR(self);
    if (0 > XBuffer_appendChar(self->buf, c)) {
        return self->last_error = WSOCKSTAT_NORESOURCE;
    }   // end if
    return SocketWriter_autoflush(self);
}   // end function: SocketWriter_writeByte

/**
 * 書き込みソケット用バッファにバイト列を追加する.
 * ただし, autoflush が有効な場合は watermark と比較の上, バッファの内容がソケットにフラッシュされる場合がある.
 * また, それまでにソケット書き込みエラーが発生している場合は, 実際の書き出しはおこなわない.
 * @param self SocketWriter オブジェクト
 * @param p 書き出すバイト列
 */
wsockstat_t
SocketWriter_writeBytes(SocketWriter *self, const void *p, size_t size)
{
    assert(NULL != self);
    assert(NULL != p);
    RETURN_IF_SOCKETERROR(self);
    if (0 > XBuffer_appendBytes(self->buf, p, size)) {
        return self->last_error = WSOCKSTAT_NORESOURCE;
    }   // end if
    return SocketWriter_autoflush(self);
}   // end function: SocketWriter_writeBytes

/**
 * 書き込みソケット用バッファにフォーマット文字列を追加する.
 * ただし, autoflush が有効な場合は watermark と比較の上, バッファの内容がソケットにフラッシュされる場合がある.
 * また, それまでにソケット書き込みエラーが発生している場合は, 実際の書き出しはおこなわない.
 * @param self SocketWriter オブジェクト
 * @param format 書き出すフォーマット文字列
 */
wsockstat_t
SocketWriter_writeFormatString(SocketWriter *self, const char *format, ...)
{
    assert(NULL != self);
    assert(NULL != format);
    RETURN_IF_SOCKETERROR(self);

    va_list ap;
    va_start(ap, format);
    int ret = XBuffer_appendVFormatString(self->buf, format, ap);
    va_end(ap);
    if (0 > ret) {
        return self->last_error = WSOCKSTAT_NORESOURCE;
    }   // end if
    return SocketWriter_autoflush(self);
}   // end function: SocketWriter_writeFormatString

/**
 * 書き込みソケット用バッファにフォーマット文字列を追加する.
 * ただし, autoflush が有効な場合は watermark と比較の上, バッファの内容がソケットにフラッシュされる場合がある.
 * また, それまでにソケット書き込みエラーが発生している場合は, 実際の書き出しはおこなわない.
 * @param self SocketWriter オブジェクト
 * @param format 書き出すフォーマット文字列
 */
wsockstat_t
SocketWriter_writeVFormatString(SocketWriter *self, const char *format, va_list ap)
{
    assert(NULL != self);
    assert(NULL != format);
    RETURN_IF_SOCKETERROR(self);

    if (0 > XBuffer_appendVFormatString(self->buf, format, ap)) {
        return self->last_error = WSOCKSTAT_NORESOURCE;
    }   // end if
    return SocketWriter_autoflush(self);
}   // end function: SocketWriter_writeVFormatString
