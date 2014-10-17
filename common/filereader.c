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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>

#include "ptrop.h"
#include "stdaux.h"
#include "xbuffer.h"
#include "filereader.h"

#define READBUFLEN 4096

struct FileReader {
    // ファイルディスクリプタ
    int fd;
    // 読み込んだデータを格納するバッファ
    unsigned char readbuf[READBUFLEN];
    // readbuf の未書き出し領域の先頭を指す
    unsigned char *readptr;
    // readptr を先頭とする, readbuf の有効な残りバイト数
    size_t bufleft;
};


/**
 * FileReader オブジェクトを構築する.
 * @param fd ラップするディスクリプタ
 * @return 初期化済みの FileReader オブジェクト
 */
FileReader *
FileReader_new(int fd)
{
    FileReader *self = (FileReader *) malloc(sizeof(FileReader));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(FileReader));
    self->fd = fd;
    self->bufleft = 0;
    self->readptr = self->readbuf;

    return self;
}   // end function: FileReader_new

/**
 * FileReader オブジェクトを解放する.
 * @param self 解放する FileReader オブジェクト
 * @attention FileReader_new() の際に渡された fd の close() はおこなわない
 */
void
FileReader_free(FileReader *self)
{
    free(self);
}   // end function: FileReader_free

/**
 * バッファが空だった場合, ファイルからデータを読み込みバッファを埋める.
 * バッファが空でない場合は何もしない.
 * @param self FileReader オブジェクト
 * @return 読み込みに成功した場合は TRUE,
 *         EOF, 読み込みエラーの場合は FALSE.
 */
static rfilestat_t
FileReader_fill(FileReader *self)
{
    if (0 < self->bufleft) {
        return RFILESTAT_OK;
    }

    ssize_t ret;
    SKIP_EINTR(ret = read(self->fd, self->readbuf, READBUFLEN));

    switch (ret) {
    case 0:
        return RFILESTAT_EOF;

    case -1:
        return RFILESTAT_READERR;

    default:
        self->bufleft = (size_t) ret;
        self->readptr = self->readbuf;
        return RFILESTAT_OK;
    }   // end switch
}   // end function: FileReader_fill

/**
 * ファイルから指定した長さのバイト列を読み込む.
 * @param self FileReader オブジェクト
 * @param buf 読み込んだデータを受け取るバッファへのポインタ
 * @param nbyte 読み込みを要求するバイト数, buf で指定するバッファのサイズ以下でなければならない.
 * @param readlen 実際に読み込んだデータの長さを受け取る変数へのポインタ
 * @return エラーなく要求されたバイト数を読み込めた場合は TRUE, エラーが発生した場合は FALSE.
 * @attention EOF に遭遇した場合, 読み込むバイト数は nbyte 以下になる場合がある.
 *            また, 返値が FALSE でもエラーが発生するまでに読み込まれたデータが buf に格納される場合がある.
 */
rfilestat_t
FileReader_read(FileReader *self, void *buf, size_t nbyte, size_t *readlen)
{
    assert(NULL != self);
    assert(NULL != buf);
    assert(0 < nbyte);

    unsigned char *p = (unsigned char *) buf;
    size_t destspace = nbyte;

    while (destspace > 0) {
        rfilestat_t readstat = FileReader_fill(self);
        if (RFILESTAT_OK != readstat) {
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
    return RFILESTAT_OK;
}   // end function: FileReader_read

/**
 * ファイルから指定した長さのバイト列を読み込み, GString に格納する.
 * @param self FileReader オブジェクト
 * @param string 読み込んだデータを受け取る GString オブジェクト
 * @param nbyte 読み込みを要求するバイト数
 * @param readlen 実際に読み込んだデータの長さを受け取る変数へのポインタ
 * @return エラーなく要求されたバイト数を読み込めた場合は TRUE, エラーが発生した場合は FALSE.
 * @attention EOF に遭遇した場合, 読み込むバイト数は nbyte 以下になる場合がある.
 *            また, 返値が FALSE でもエラーが発生するまでに読み込まれたデータが string に格納される場合がある.
 */
rfilestat_t
FileReader_readString(FileReader *self, XBuffer *xbuf, size_t nbyte, size_t *readlen)
{
    assert(NULL != self);
    assert(NULL != xbuf);
    assert(0 < nbyte);

    size_t destspace = nbyte;

    while (destspace > 0) {
        rfilestat_t readstat = FileReader_fill(self);
        if (RFILESTAT_OK != readstat) {
            // 読み込みエラー
            SETDEREF(readlen, nbyte - destspace);
            return readstat;
        }   // end if

        // バッファから xbuf にコピー
        size_t writelen = MIN(self->bufleft, destspace);
        if (0 > XBuffer_appendBytes(xbuf, self->readptr, writelen)) {
            return RFILESTAT_NORESOURCE;
        }   // end if

        // カウンタを調整
        self->bufleft -= writelen;
        self->readptr += writelen;
        destspace -= writelen;
    }   // end while

    SETDEREF(readlen, nbyte - destspace);
    return RFILESTAT_OK;
}   // end function: FileReader_readString

/**
 * ファイルから指定した長さの行を読み込み, 行末に NULL 文字を付加する.
 * 入力列に対して, LF を行の区切りとする.
 * LF が現れる, バッファが一杯になる ((buflen - 1) バイト) EOF, タイムアウト, 読み込みエラーのいずれかの条件発生するまで読み込む.
 * @param self FileReader オブジェクト
 * @param buf 読み込んだデータを受け取るバッファへのポインタ
 * @param buflen buf のサイズ
 * @param readlen 実際に読み込んだデータの長さを受け取る変数へのポインタ
 * @return エラーなく行を読み込めた場合は TRUE, エラーが発生した場合は FALSE.
 * @attention EOF に遭遇した場合, 読み込んだデータは LF で終端しない場合がある.
 *            また, 返値が FALSE でもエラーが発生するまでに読み込まれたデータが buf に格納される場合がある.
 * @attention 読み込んだデータの末尾に NULL 文字を付加するので, buf の長さ (buflen) は必ず 1 以上でなければならない.
 */
rfilestat_t
FileReader_readLine(FileReader *self, void *buf, size_t buflen, size_t *readlen)
{
    assert(NULL != self);
    assert(NULL != buf);
    assert(0 < buflen);

    unsigned char *p = (unsigned char *) buf;
    size_t destspace = buflen - 1;  // 1 は NULL の分

    while (destspace > 0) {
        rfilestat_t readstat = FileReader_fill(self);
        if (RFILESTAT_OK != readstat) {
            // 読み込みエラー
            *p = '\0';
            SETDEREF(readlen, buflen - destspace - 1);  // 1 は NULL の分
            return readstat;
        }   // end if

        // バッファから buf にコピー
        size_t writelen = MIN(self->bufleft, destspace);
        // LF が存在する場合は LF までをコピー対象とする
        unsigned char *lfptr = (unsigned char *) memchr(self->readptr, '\n', writelen);
        if (NULL != lfptr) {
            // LF が存在する場合
            writelen = lfptr - self->readptr + 1;
        }
        memcpy(p, self->readptr, writelen);

        // カウンタを調整
        self->bufleft -= writelen;
        self->readptr += writelen;
        destspace -= writelen;
        p += writelen;

        if (NULL != lfptr) {
            // LF が存在する場合
            break;
        }
    }   // end while

    *p = '\0';
    SETDEREF(readlen, buflen - destspace - 1);  // 1 は NULL の分
    return RFILESTAT_OK;
}   // end function: FileReader_readLine

/**
 * ファイルから指定した長さの行を読み込み, 行末に NULL 文字を付加する.
 * 入力列に対して, LF を行の区切りとする.
 * LF が現れる, 指定したバイト数を読み込む, EOF, タイムアウト, 読み込みエラーのいずれかの条件発生するまで読み込む.
 * @param self FileReader オブジェクト
 * @param string 読み込んだデータを受け取る GString オブジェクト
 * @param limitlen 読み込むバイト数の上限, 0 だと無制限.
 * @param readlen 実際に読み込んだデータの長さを受け取る変数へのポインタ
 * @return エラーなく要求されたバイト数を読み込めた場合は TRUE, エラーが発生した場合は FALSE.
 * @attention EOF に遭遇した場合, 読み込んだデータは LF で終端しない場合がある.
 *            また, 返値が FALSE でもエラーが発生するまでに読み込まれたデータが string に格納される場合がある.
 * @attention 読み込んだデータの末尾に NULL 文字を付加するので, buf の長さ (buflen) は必ず 1 以上でなければならない.
 */
rfilestat_t
FileReader_readStringLine(FileReader *self, XBuffer *xbuf, size_t limitlen, size_t *readlen)
{
    assert(NULL != self);
    assert(NULL != xbuf);

    size_t destspace = limitlen;
    size_t curreadlen = 0;

    while (destspace > 0 || 0 == limitlen) {
        rfilestat_t readstat = FileReader_fill(self);
        if (RFILESTAT_OK != readstat) {
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
        if (NULL != lfptr) {
            // LF が存在する場合
            writelen = lfptr - self->readptr + 1;
        }
        if (0 > XBuffer_appendBytes(xbuf, self->readptr, writelen)) {
            return RFILESTAT_NORESOURCE;
        }   // end if

        // カウンタを調整
        self->bufleft -= writelen;
        self->readptr += writelen;
        curreadlen += writelen;
        if (0 != limitlen) {
            destspace -= writelen;
        }

        if (NULL != lfptr) {    // LF が存在する場合
            break;
        }
    }   // end while

    SETDEREF(readlen, curreadlen);
    return RFILESTAT_OK;
}   // end function: FileReader_readStringLine

/**
 * ファイルの読み書きオフセットの位置を変える. lseek のラップ関数.
 * 読み込みバッファに溜まっているデータは破棄する.
 * @param self FileReader オブジェクト
 * @param offset whence で指定した位置からの移動バイト数.
 * @param whence  SEEK_SET, SEEK_CUR, SEEK_END のいずれか.
 * @return 読み込みに成功した場合は TRUE, エラーが発生した場合は FALSE.
 */
rfilestat_t
FileReader_seek(FileReader *self, off_t offset, int whence)
{
    if (-1 == lseek(self->fd, offset, whence)) {
        return RFILESTAT_READERR;
    }
    // バッファの内容を破棄
    self->bufleft = 0;
    self->readptr = self->readbuf;
    return RFILESTAT_OK;
}   // end function: FileReader_seek
