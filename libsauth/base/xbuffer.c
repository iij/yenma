/*
 * Copyright (c) 2006-2012 Internet Initiative Japan Inc. All rights reserved.
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
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdbool.h>

#include "stdaux.h"
#include "xbuffer.h"

#define ROUNDUP(c, base) ((((int) (((c) - 1) / (base))) + 1) * (base))

#define GROWTH_DEFAULT  256

struct XBuffer {
    // realloc() が NULL を返した場合以外,
    // すなわちメモリ確保に失敗した場合以外には NULL にならない
    unsigned char *buf;

    // 有効なデータのサイズ, 末尾の NULL 文字を *含まない*
    size_t size;

    // 確保済みメモリのサイズ
    // これが 0 の場合はエラー状態を示す
    size_t capacity;

    // メモリを拡張する単位
    size_t growth;

    // 最後に発生したエラー, エラーが発生していない場合は 0
    int status;
};

/*
 * 実際に確保するメモリ領域のサイズを変更する.
 * @param size 必要とするメモリ領域のサイズ
 * @return 成功した場合は, 実際に確保した領域のサイズ, 失敗した場合は -1
 * @attention 実際に確保するメモリ領域のサイズは, 引数で指定したサイズより大きい可能性がある
 */
int
XBuffer_reserve(XBuffer *self, size_t size)
{
    assert(NULL != self);

    ++size; // NULL 文字を格納するスペースを常に確保しておく. 同時にサイズ 0 のメモリブロックを要求することも防ぐ.
    if (self->capacity < size) {    // 要再確保
        unsigned char *newbuf;

        self->capacity = ROUNDUP(size, self->growth);
        newbuf = (unsigned char *) realloc(self->buf, self->capacity);
        if (NULL == newbuf) {
            self->status = errno;
            return -1;
        }   // end if
        self->buf = newbuf;
    }   // end if

    return self->capacity;
}   // end function: XBuffer_reserve

/**
 * create XBuffer object
 * @return initialized XBuffer object, or NULL if memory allocation failed.
 */
XBuffer *
XBuffer_new(size_t size)
{
    XBuffer *self = (XBuffer *) malloc(sizeof(XBuffer));
    if (NULL == self) {
        return NULL;
    }   // end if

    memset(self, 0, sizeof(XBuffer));
    self->growth = GROWTH_DEFAULT;

    if (0 > XBuffer_reserve(self, size)) {
        free(self);
        return NULL;
    }   // end if

    return self;
}   // end function: XBuffer_new

/**
 * release XBuffer object
 * @param self XBuffer object to release
 */
void
XBuffer_free(XBuffer *self)
{
    if (NULL == self) {
        return;
    }   // end if

    if (self->buf) {
        free(self->buf);
    }   // end if
    free(self);
}   // end function: XBuffer_free

/*
 * @attention それまでに取得した savepoint は全て無効になる
 */
void
XBuffer_reset(XBuffer *self)
{
    assert(NULL != self);
    self->size = 0;
    self->status = 0;
}   // end function: XBuffer_reset

/*
 * @return それまでにエラーが発生している場合はエラーコード, エラーが発生していない場合は 0
 */
int
XBuffer_status(const XBuffer *self)
{
    assert(NULL != self);
    return self->status;
}   // end function: XBuffer_status

void
XBuffer_setGrowth(XBuffer *self, size_t growth)
{
    assert(NULL != self);
    self->growth = growth;
}   // end function: XBuffer_setGrowth

const void *
XBuffer_getBytes(const XBuffer *self)
{
    return (const void *) self->buf;
}   // end function: XBuffer_getBytes

const char *
XBuffer_getString(const XBuffer *self)
{
    self->buf[self->size] = '\0';   // semantically constant
    return (char *) self->buf;
}   // end function: XBuffer_getString

size_t
XBuffer_getSize(const XBuffer *self)
{
    return self->size;
}   // end function: XBuffer_getSize

int
XBuffer_appendChar(XBuffer *self, char c)
{
    assert(NULL != self);

    if (0 > XBuffer_reserve(self, self->size + 1)) {
        return -1;
    }   // end if

    self->buf[self->size++] = *((unsigned char *) &c);
    return 0;
}   // end function: XBuffer_appendChar

int
XBuffer_appendByte(XBuffer *self, unsigned char b)
{
    assert(NULL != self);

    if (0 > XBuffer_reserve(self, self->size + 1)) {
        return -1;
    }   // end if

    self->buf[self->size++] = b;
    return 0;
}   // end function: XBuffer_appendByte

int
XBuffer_appendStringN(XBuffer *self, const char *s, size_t len)
{
    assert(NULL != self);
    assert(NULL != s);

    if (0 > XBuffer_reserve(self, self->size + len)) {
        return -1;
    }   // end if

    memcpy(self->buf + self->size, s, len);
    self->size += len;

    return 0;
}   // end function: XBuffer_appendStringN

int
XBuffer_appendString(XBuffer *self, const char *s)
{
    assert(NULL != self);
    assert(NULL != s);
    return XBuffer_appendStringN(self, s, strlen(s));
}   // end function: XBuffer_appendString

int
XBuffer_appendFormatString(XBuffer *self, const char *format, ...)
{
    assert(NULL != self);
    assert(NULL != format);

    va_list ap;
    size_t len;
    char dummy;

    va_start(ap, format);
    // Solaris 9 では vsnprintf の第2引数に 0 を渡せない
    len = vsnprintf(&dummy, 1, format, ap);
    va_end(ap);

    if (0 > XBuffer_reserve(self, self->size + len)) {
        return -1;
    }   // end if

    va_start(ap, format);
    len = vsnprintf((char *) self->buf + self->size, self->capacity - self->size, format, ap);
    va_end(ap);

    self->size += len;

    return 0;
}   // end function: XBuffer_appendFormatString

int
XBuffer_appendVFormatString(XBuffer *self, const char *format, va_list ap)
{
    assert(NULL != self);
    assert(NULL != format);

    va_list aphead;
    size_t len;
    char dummy;

    va_copy(aphead, ap);
    // Solaris 9 では vsnprintf の第2引数に 0 を渡せない
    len = vsnprintf(&dummy, 1, format, aphead);
    va_end(aphead);

    if (0 > XBuffer_reserve(self, self->size + len)) {
        return -1;
    }   // end if

    len = vsnprintf((char *) self->buf + self->size, self->capacity - self->size, format, ap);
    self->size += len;

    return 0;
}   // end function: XBuffer_appendVFormatString

int
XBuffer_appendVFormatStringN(XBuffer *self, size_t len, const char *format, va_list ap)
{
    assert(NULL != self);
    assert(NULL != format);

    if (0 > XBuffer_reserve(self, self->size + len)) {
        return -1;
    }   // end if

    vsnprintf((char *) self->buf + self->size, self->capacity - self->size, format, ap);
    self->size += len;

    return 0;
}   // end function: XBuffer_appendVFormatStringN

int
XBuffer_appendBytes(XBuffer *self, const void *b, size_t size)
{
    assert(NULL != self);
    assert(NULL != b);

    if (0 > XBuffer_reserve(self, self->size + size)) {
        return -1;
    }   // end if

    memcpy(self->buf + self->size, b, size);
    self->size += size;

    return 0;
}   // end function: XBuffer_appendBytes

int
XBuffer_appendXBuffer(XBuffer *self, const XBuffer *xbuf)
{
    assert(NULL != self);
    assert(NULL != xbuf);
    return XBuffer_appendBytes(self, xbuf->buf, xbuf->size);
}   // end function: XBuffer_appendXBuffer

bool
XBuffer_compareToString(const XBuffer *self, const char *s)
{
    assert(NULL != self);
    assert(NULL != s);
    self->buf[self->size] = '\0';   // semantically constant
    return bool_cast(0 == strcmp((char *) self->buf, s));
}   // end function: XBuffer_compareToString

bool
XBuffer_compareToStringIgnoreCase(const XBuffer *self, const char *s)
{
    assert(NULL != self);
    assert(NULL != s);
    self->buf[self->size] = '\0';   // semantically constant
    return bool_cast(0 == strcasecmp((char *) self->buf, s));
}   // end function: XBuffer_compareToStringIgnoreCase

bool
XBuffer_compareToStringN(const XBuffer *self, const char *s, size_t len)
{
    assert(NULL != self);
    assert(NULL != s);
    return bool_cast(0 == strncmp((char *) self->buf, s, len));
}   // end function: XBuffer_compareToStringN

bool
XBuffer_compareToStringNIgnoreCase(const XBuffer *self, const char *s, size_t len)
{
    assert(NULL != self);
    assert(NULL != s);
    return bool_cast(0 == strncasecmp((char *) self->buf, s, len));
}   // end function: XBuffer_compareToStringNIgnoreCase

/**
 * XBuffer オブジェクトが保持するバイト列と, 引数として指定したバイト列とを比較し,
 * 長さおよび内容が一致しているか確認する
 */
bool
XBuffer_compareToBytes(const XBuffer *self, const void *b, size_t size)
{
    assert(NULL != self);
    assert(NULL != b);
    return bool_cast(self->size == size && 0 == memcmp(self->buf, b, size));
}   // end function: XBuffer_compareToBytes

/*
 * XBuffer オブジェクトが1バイトも保持していない場合は空の NULL 終端文字列が返る.
 */
char *
XBuffer_dupString(const XBuffer *self)
{
    assert(NULL != self);

    char *p = (char *) malloc(self->size + 1);
    if (NULL != p) {
        if (0 < self->size) {
            memcpy(p, self->buf, self->size);
        }   // end if
        p[self->size] = '\0';
    }   // end if
    return p;
}   // end function: XBuffer_dupString

/*
 * XBuffer オブジェクトが1バイトも保持していない場合は NULL が返る.
 */
void *
XBuffer_dupBytes(const XBuffer *self)
{
    assert(NULL != self);

    if (0 == self->size) {
        return NULL;
    }   // end if

    void *p = malloc(self->size);
    if (NULL != p) {
        memcpy(p, self->buf, self->size);
    }   // end if
    return p;
}   // end function: XBuffer_dupBytes

/*
 * XBuffer オブジェクトが保持するバイト列を文字列と見なした場合に,
 * 末尾の改行文字 (CRLF または LF) を削る.
 * 末尾が改行文字でない場合は何もしない.
 */
void
XBuffer_chomp(XBuffer *self)
{
    // 末尾が LF なら削る
    if (1 <= self->size && '\n' == self->buf[self->size - 1]) {
        --(self->size);
        // さらにその直前が CR ならそれも削る
        if (1 <= self->size && '\r' == self->buf[self->size - 1]) {
            --(self->size);
        }   // end if
    }   // end if
    return;
}   // end function: XBuffer_chomp

/*
 * セーブポイントを取得する
 * XBuffer_reset() をよぶと取得したセーブポイントは無効になる
 */
xbuffer_savepoint_t
XBuffer_savepoint(const XBuffer *self)
{
    return (xbuffer_savepoint_t) self->size;
}   // end function: XBuffer_savepoint

/*
 * savepoint が不正な場合の動作は未定義
 */
void
XBuffer_rollback(XBuffer *self, xbuffer_savepoint_t savepoint)
{
    self->size = (size_t) savepoint;
}   // end function: XBuffer_rollback
