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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "stdaux.h"
#include "timeop.h"
#include "ptrop.h"
#include "socketreader.h"

#define READBUFLEN 4096

struct SocketReader {
    // ソケットディスクリプタ
    int fd;
    // 読み込んだデータを格納するバッファ
    unsigned char readbuf[READBUFLEN];
    // readbuf の未書き出し領域の先頭を指す
    unsigned char *readptr;
    // readptr を先頭とする, readbuf の有効な残りバイト数
    size_t bufleft;
    // 1回の読み込みに対するタイムアウト [sec]
    time_t op_timeout;
    // 複数の読み込みをまたぐタイムアウト
    struct timeval abs_timeout;
};

/**
 * SocketReader オブジェクトを構築する.
 * @param fd ラップするディスクリプタ
 * @return 初期化済みの SocketReader オブジェクト
 */
SocketReader *
SocketReader_new(int fd)
{
    SocketReader *self = (SocketReader *) malloc(sizeof(SocketReader));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(SocketReader));
    self->fd = fd;
    self->bufleft = 0;
    self->readptr = self->readbuf;
    self->op_timeout = 0;
    timerclear(&(self->abs_timeout));

    return self;
}   // end function: SocketReader_new

/**
 * SocketReader オブジェクトを解放する.
 * @param self 解放する SocketReader オブジェクト
 * @attention SocketReader_new() の際に渡された fd の close() はおこなわない
 */
void
SocketReader_free(SocketReader *self)
{
    free(self);
}   // end function: SocketReader_free

/**
 * タイムアウトの設定をおこなう.
 * @param timeout ディスクリプタが準備できるまで待つ秒数.
 *                0以下を指定した場合はタイムアウトしない.
 *                デフォルトは 0 (タイムアウトしない).
 */
void
SocketReader_setTimeout(SocketReader *self, time_t timeout)
{
    assert(NULL != self);
    self->op_timeout = timeout;
}   // end function: SocketReader_setTimeout

void
SocketReader_setAbsoluteTimeout(SocketReader *self, time_t timeout)
{
    if (timeout > 0) {
        gettimeofday(&(self->abs_timeout), NULL);
        self->abs_timeout.tv_sec += timeout;
    } else {
        timerclear(&(self->abs_timeout));
    }   // end if
}   // end function: SocketReader_setAbsoluteTimeout

/**
 * 接続が生きているかどうか確認する.
 * @return 接続が生きている場合は RSOCKSTAT_OK,
 *         EOF に達している場合は RSOCKSTAT_EOF,
 *         読み込みエラーが発生している場合は RSOCKSTAT_READERR.
 */
rsockstat_t
SocketReader_isAlive(SocketReader *self)
{
    char dummy;
    int ret;
    SKIP_EINTR(ret = recv(self->fd, &dummy, 1, MSG_PEEK | MSG_DONTWAIT));

    if (0 < ret) {
        // データが到着している
        return RSOCKSTAT_OK;
    } else if (0 == ret) {
        // ソケットはクローズされている (FIN を受け取った).
        return RSOCKSTAT_EOF;
    } else {    /* (0 > ret) */
        switch (errno) {
        case EAGAIN:   // 大半の実装では EAGAIN と EWOULDBLOCK は同一の値を持つ.
            // データが到着していない.
            return RSOCKSTAT_OK;
        case ECONNRESET:
            // 接続のリモート側が接続をリセットした (RST を受け取った).
            return RSOCKSTAT_READERR;
        default:
            return RSOCKSTAT_READERR;
        }   // end switch
    }   // end if
}   // end function: SocketReader_isAlive

/**
 * バッファが空だった場合, ソケットからデータを読み込みバッファを埋める.
 * バッファが空でない場合は何もしない.
 * @param self SocketReader オブジェクト
 * @return 読み込みに成功した場合は RSOCKSTAT_OK,
 *         タイムアウトした場合は RSOCKSTAT_TIMEOUT,
 *         EOF に達した場合は RSOCKSTAT_EOF,
 *         読み込みエラーの場合は RSOCKSTAT_READERR
 */
static rsockstat_t
SocketReader_fill(SocketReader *self)
{
    if (0 < self->bufleft) {
        return RSOCKSTAT_OK;
    }   // end if

    int ret;
    fd_set rfdset;
    struct timeval *timeoutp;
    struct timeval time_left;

    while (true) {
        do {
            FD_ZERO(&rfdset);
            FD_SET(self->fd, &rfdset);
            // Linux では timeval 構造体が上書きされるので毎回セットする必要がある
            timeoutp = NULL;
            if (timerisset(&(self->abs_timeout))) {
                struct timeval now;
                gettimeofday(&now, NULL);
                timersub(&now, &(self->abs_timeout), &time_left);
                if (!timerispositive(&time_left)) {
                    // 既に abs_timeout を過ぎている
                    return RSOCKSTAT_TIMEOUT;
                }   // end if
                timeoutp = &time_left;
            }   // end if
            if (self->op_timeout > 0 && (NULL == timeoutp || self->op_timeout <= timeoutp->tv_sec)) {
                time_left.tv_sec = self->op_timeout;
                time_left.tv_usec = 0;
                timeoutp = &time_left;
            }   // end if
            // select(2) はタイムアウトした場合は 0, エラーの場合は -1 を返す
            ret = select(self->fd + 1, &rfdset, NULL, NULL, timeoutp);
        } while (-1 == ret && EINTR == errno);

        switch (ret) {
        case 0:
            return RSOCKSTAT_TIMEOUT;

        case -1:
            return RSOCKSTAT_READERR;

        default:
            // do nothing
            break;
        }   // end switch

        if (FD_ISSET(self->fd, &rfdset)) {
            do {
                // recv() は EOF の場合は 0, エラーの場合は -1 を返す
                ret = recv(self->fd, self->readbuf, READBUFLEN, MSG_DONTWAIT);
            } while (-1 == ret && EINTR == errno);

            switch (ret) {
            case 0:
                return RSOCKSTAT_EOF;

            case -1:
                if (EAGAIN == errno) {  // EWOULDBLOCK は EAGAIN に等しい
                    // Linux では select/poll によってソケットの準備ができたと報告されても,
                    // チェックサム異常によってパケットが破棄された場合などに
                    // 後続の読み出しがブロックする可能性がある.
                    // ノンブロッキングを指定 (MSG_DONTWAIT) して recv() をよび出すと,
                    // そのような場合ブロックせずに EAGAIN/EWOULDBLOCK を戻す.
                    break;  // select からやり直し
                } else {
                    return RSOCKSTAT_READERR;
                }   // end if

            default:
                self->bufleft = (size_t) ret;
                self->readptr = self->readbuf;
                return RSOCKSTAT_OK;
            }   // end switch
        }   // end if
    }   // end while
}   // end function: SocketReader_fill

/**
 * ソケットから指定した長さのバイト列を読み込む.
 * @param self SocketReader オブジェクト
 * @param buf 読み込んだデータを受け取るバッファへのポインタ
 * @param nbyte 読み込みを要求するバイト数, buf で指定するバッファのサイズ以下でなければならない.
 * @param readlen 実際に読み込んだデータの長さを受け取る変数へのポインタ
 * @param error エラー情報の受け渡しをおこなう GError オブジェクトを受け取るためのポインタ.
 *              要求されたバイト数を読み込めた場合はエラーはセットされない (NULL のまま).
 * @return 読み込みに成功した場合は RSOCKSTAT_OK,
 *         タイムアウトした場合は RSOCKSTAT_TIMEOUT,
 *         EOF に達した場合は RSOCKSTAT_EOF,
 *         読み込みエラーの場合は RSOCKSTAT_READERR
 * @attention EOF やタイムアウトが発生した場合, 読み込むバイト数は nbyte 以下になる場合がある.
 *            また, 返値が FALSE でもエラーが発生するまでに読み込まれたデータが buf に格納される場合がある.
 */
extern rsockstat_t
SocketReader_read(SocketReader *self, void *buf, size_t nbyte, size_t *readlen)
{
    assert(NULL != self);
    assert(NULL != buf);
    assert(0 < nbyte);

    unsigned char *p = (unsigned char *) buf;
    size_t destspace = nbyte;

    while (destspace > 0) {
        rsockstat_t readstat = SocketReader_fill(self);
        if (RSOCKSTAT_OK != readstat) {
            // 読み込みエラー
            SETDEREF(readlen, nbyte - destspace);
            return readstat;
        }   // end if

        // バッファから buf にコピー
        size_t writelen = MIN(self->bufleft, destspace);
        memcpy(p, self->readptr, writelen);

        // カウンタを調整
        self->bufleft -= writelen;
        self->readptr += writelen;
        destspace -= writelen;
        p += writelen;
    }   // end while

    SETDEREF(readlen, nbyte - destspace);
    return RSOCKSTAT_OK;
}   // end function: SocketReader_read

/**
 * ソケットから指定した長さのバイト列を読み込み, GString に格納する.
 * @param self SocketReader オブジェクト
 * @param string 読み込んだデータを受け取る GString オブジェクト
 * @param nbyte 読み込みを要求するバイト数
 * @param readlen 実際に読み込んだデータの長さを受け取る変数へのポインタ
 * @param error エラー情報の受け渡しをおこなう GError オブジェクトを受け取るためのポインタ.
 *              要求されたバイト数を読み込めた場合はエラーはセットされない (NULL のまま).
 * @return 読み込みに成功した場合は RSOCKSTAT_OK,
 *         タイムアウトした場合は RSOCKSTAT_TIMEOUT,
 *         EOF に達した場合は RSOCKSTAT_EOF,
 *         読み込みエラーの場合は RSOCKSTAT_READERR
 * @attention EOF やタイムアウトが発生した場合, 読み込むバイト数は nbyte 以下になる場合がある.
 *            また, 返値が FALSE でもエラーが発生するまでに読み込まれたデータが string に格納される場合がある.
 */
extern rsockstat_t
SocketReader_readString(SocketReader *self, XBuffer *xbuf, size_t nbyte, size_t *readlen)
{
    assert(NULL != self);
    assert(NULL != xbuf);
    assert(0 < nbyte);

    size_t destspace = nbyte;

    while (destspace > 0) {
        rsockstat_t readstat = SocketReader_fill(self);
        if (RSOCKSTAT_OK != readstat) {
            // 読み込みエラー
            SETDEREF(readlen, nbyte - destspace);
            return readstat;
        }   // end if

        // バッファから xbuf にコピー
        size_t writelen = MIN(self->bufleft, destspace);
        if (0 > XBuffer_appendBytes(xbuf, self->readptr, writelen)) {
            return RSOCKSTAT_NORESOURCE;
        }   // end if

        // カウンタを調整
        self->bufleft -= writelen;
        self->readptr += writelen;
        destspace -= writelen;
    }   // end while

    SETDEREF(readlen, nbyte - destspace);
    return RSOCKSTAT_OK;
}   // end function: SocketReader_readString

/**
 * ソケットから指定した長さの行を読み込み, 行末に NULL 文字を付加する.
 * 入力列に対して, LF を行の区切りとする.
 * LF が現れる, バッファが一杯になる ((buflen - 1) バイト) EOF, タイムアウト, 読み込みエラーのいずれかの条件発生するまで読み込む.
 * @param self SocketReader オブジェクト
 * @param buf 読み込んだデータを受け取るバッファへのポインタ
 * @param buflen buf のサイズ
 * @param readlen 実際に読み込んだデータの長さを受け取る変数へのポインタ
 * @param error エラー情報の受け渡しをおこなう GError オブジェクトを受け取るためのポインタ.
 *              行として読み込めた (LF に遭遇した) 場合はエラーはセットされない (NULL のまま).
 * @return 読み込みに成功した場合は RSOCKSTAT_OK,
 *         タイムアウトした場合は RSOCKSTAT_TIMEOUT,
 *         EOF に達した場合は RSOCKSTAT_EOF,
 *         読み込みエラーの場合は RSOCKSTAT_READERR
 *         メモリ確保に失敗した場合は RSOCKSTAT_NORESOURCE
 * @attention EOF やタイムアウトが発生した場合, 読み込んだデータは LF で終端しない場合がある.
 *            また, 返値が FALSE でもエラーが発生するまでに読み込まれたデータが buf に格納される場合がある.
 * @attention 読み込んだデータの末尾に NULL 文字を付加するので, buf の長さ (buflen) は必ず 1 以上でなければならない.
 */
extern rsockstat_t
SocketReader_readLine(SocketReader *self, void *buf, size_t buflen, size_t *readlen)
{
    assert(NULL != self);
    assert(NULL != buf);
    assert(0 < buflen);

    unsigned char *p = buf;
    size_t destspace = buflen - 1;  // 1 は NULL の分

    while (destspace > 0) {
        rsockstat_t readstat = SocketReader_fill(self);
        if (RSOCKSTAT_OK != readstat) {
            // 読み込みエラー
            *p = '\0';
            SETDEREF(readlen, buflen - destspace - 1);  // 1 は NULL の分
            return readstat;
        }   // end if

        // バッファから buf にコピー
        size_t writelen = MIN(self->bufleft, destspace);
        // LF が存在する場合は LF までをコピー対象とする
        unsigned char *lfptr = (unsigned char *) memchr(self->readptr, '\n', writelen);
        if (NULL != lfptr) {    // LF が存在する場合
            writelen = lfptr - self->readptr + 1;
        }   // end if
        memcpy(p, self->readptr, writelen);

        // カウンタを調整
        self->bufleft -= writelen;
        self->readptr += writelen;
        destspace -= writelen;
        p += writelen;

        if (NULL != lfptr) {    // LF が存在する場合
            break;
        }   // end if
    }   // end while

    *p = '\0';
    SETDEREF(readlen, buflen - destspace - 1);  // 1 は NULL の分
    return RSOCKSTAT_OK;
}   // end function: SocketReader_readLine

/**
 * ソケットから指定した長さの行を読み込み, 行末に NULL 文字を付加する.
 * 入力列に対して, LF を行の区切りとする.
 * LF が現れる, 指定したバイト数を読み込む, EOF, タイムアウト, 読み込みエラーのいずれかの条件発生するまで読み込む.
 * @param self SocketReader オブジェクト
 * @param string 読み込んだデータを受け取る GString オブジェクト
 * @param limitlen 読み込むバイト数の上限, 0 だと無制限.
 * @param readlen 実際に読み込んだデータの長さを受け取る変数へのポインタ
 * @param error エラー情報の受け渡しをおこなう GError オブジェクトを受け取るためのポインタ.
 *              行として読み込めた (LF に遭遇した) 場合はエラーはセットされない (NULL のまま).
 * @return 読み込みに成功した場合は RSOCKSTAT_OK,
 *         タイムアウトした場合は RSOCKSTAT_TIMEOUT,
 *         EOF に達した場合は RSOCKSTAT_EOF,
 *         読み込みエラーの場合は RSOCKSTAT_READERR
 *         メモリ確保に失敗した場合は RSOCKSTAT_NORESOURCE
 * @attention EOF やタイムアウトが発生した場合, 読み込んだデータは LF で終端しない場合がある.
 *            また, 返値が FALSE でもエラーが発生するまでに読み込まれたデータが string に格納される場合がある.
 * @attention 読み込んだデータの末尾に NULL 文字を付加するので, buf の長さ (buflen) は必ず 1 以上でなければならない.
 */
extern rsockstat_t
SocketReader_readStringLine(SocketReader *self, XBuffer *xbuf, size_t limitlen, size_t *readlen)
{
    assert(NULL != self);
    assert(NULL != xbuf);

    size_t destspace = limitlen;
    size_t curreadlen = 0;

    while (destspace > 0 || 0 == limitlen) {
        rsockstat_t readstat = SocketReader_fill(self);
        if (RSOCKSTAT_OK != readstat) {
            // 読み込みエラー
            SETDEREF(readlen, curreadlen);
            return readstat;
        }   // end if

        // バッファから buf にコピー
        size_t writelen;
        if (0 == limitlen) {    // 行末まで無制限に読む場合
            writelen = self->bufleft;
        } else {
            writelen = MIN(self->bufleft, destspace);
        }   // end if
        // LF が存在する場合は LF までをコピー対象とする
        unsigned char *lfptr = (unsigned char *) memchr(self->readptr, '\n', writelen);
        if (NULL != lfptr) {    // LF が存在する場合
            writelen = lfptr - self->readptr + 1;
        }   // end if
        if (0 > XBuffer_appendBytes(xbuf, self->readptr, writelen)) {
            return RSOCKSTAT_NORESOURCE;
        }   // end if

        // カウンタを調整
        self->bufleft -= writelen;
        self->readptr += writelen;
        curreadlen += writelen;
        if (0 != limitlen) {
            destspace -= writelen;
        }   // end if

        if (NULL != lfptr) {    // LF が存在する場合
            break;
        }   // end if
    }   // end while

    SETDEREF(readlen, curreadlen);
    return RSOCKSTAT_OK;
}   // end function: SocketReader_readStringLine
