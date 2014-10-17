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
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/types.h>

#include "ptrop.h"
#include "stdaux.h"
#include "xbuffer.h"
#include "foldstring.h"

#define LINE_LENGTH_LIMITS  78

struct FoldString {
    XBuffer *xbuf;
    size_t linepos;             // 現在の行の長さ
    size_t linelimits;          // 1行の最大長 (改行文字を *含まない*), この値は死守されるものではなく意図すれば突破可能
    bool folding_cr;            // folding の際に LF の前に CR を含めるか
};

/**
 * create FoldString object
 * @return initialized FoldString object, or NULL if memory allocation failed.
 */
FoldString *
FoldString_new(size_t size)
{
    FoldString *self = (FoldString *) malloc(sizeof(FoldString));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(FoldString));

    self->linelimits = LINE_LENGTH_LIMITS;
    self->folding_cr = false;   // デフォルトでは LF の前に CR は挿入しない

    self->xbuf = XBuffer_new(size);
    if (NULL == self->xbuf) {
        free(self);
        return NULL;
    }   // end if

    return self;
}   // end function: FoldString_new

/**
 * release FoldString object
 * @param self FoldString object to release
 */
void
FoldString_free(FoldString *self)
{
    if (NULL == self) {
        return;
    }   // end if

    XBuffer_free(self->xbuf);
    free(self);
}   // end function: FoldString_free

void
FoldString_reset(FoldString *self)
{
    assert(NULL != self);
    if (NULL != self->xbuf) {
        XBuffer_reset(self->xbuf);
    }   // end if
    self->linepos = 0;
}   // end function: FoldString_reset

/*
 * @return それまでにエラーが発生している場合はエラーコード, エラーが発生していない場合は 0
 */
int
FoldString_status(const FoldString *self)
{
    assert(NULL != self);
    return XBuffer_status(self->xbuf);
}   // end function: FoldString_status

/**
 * メモリを拡張する際の単位を指定する
 */
void
FoldString_setGrowth(FoldString *self, size_t growth)
{
    assert(NULL != self);
    XBuffer_setGrowth(self->xbuf, growth);
}   // end function: FoldString_setGrowth

/*
 * 実際に確保するメモリ領域のサイズを変更する.
 * @param size 必要とするメモリ領域のサイズ
 * @return 成功した場合は, 実際に確保した領域のサイズ, 失敗した場合は -1
 * @attention 実際に確保するメモリ領域のサイズは, 引数で指定したサイズより大きい可能性がある
 */
int
FoldString_reserve(FoldString *self, size_t size)
{
    assert(NULL != self);
    return XBuffer_reserve(self->xbuf, size);
}   // end function: FoldString_reserve

/**
 * folding 処理をおこなう
 * @return 成功した場合は 0, 失敗した場合は -1
 */
int
FoldString_folding(FoldString *self)
{
    assert(NULL != self);

    int ret;
    if (self->folding_cr) {
        ret = XBuffer_appendStringN(self->xbuf, "\r\n\t", 3);
    } else {
        ret = XBuffer_appendStringN(self->xbuf, "\n\t", 2);
    }   // end if

    if (0 > ret) {
        return -1;
    }   // end if

    self->linepos = 1;  // tab 文字の分
    return 0;
}   // end function: FoldString_folding

/**
 * 現在の行に size で指定した文字数を格納できない場合にのみ folding をおこなう.
 * @return 成功した場合は, folding をおこなわなかった場合は 0,
 *         失敗した場合は -1
 */
int
FoldString_precede(FoldString *self, size_t size)
{
    if (0 != self->linepos && self->linelimits < self->linepos + size) {
        return FoldString_folding(self);
    }   // end if
    return 0;
}   // end function: FoldString_precede

/**
 * 文字を連結する
 * 必要ならば folding 処理をおこなう
 * @return 成功した場合は 0, 失敗した場合は -1
 */
int
FoldString_appendChar(FoldString *self, bool prefolding, char c)
{
    assert(NULL != self);

    if (prefolding && 0 > FoldString_precede(self, 1)) {
        return -1;
    }   // end if
    if (0 > XBuffer_appendChar(self->xbuf, c)) {
        return -1;
    }   // end if
    ++(self->linepos);
    return 0;
}   // end function: FoldString_appendChar

/**
 * 途中で folding してはいけない固まりを append する
 * @return 成功した場合は 0, 失敗した場合は -1
 */
int
FoldString_appendBlock(FoldString *self, bool prefolding, const char *s)
{
    assert(NULL != self);
    size_t len = strlen(s);
    if (prefolding && 0 > FoldString_precede(self, len)) {
        return -1;
    }   // end if
    if (0 > XBuffer_appendStringN(self->xbuf, s, len)) {
        return -1;
    }   // end if
    self->linepos += len;
    return 0;
}   // end function: FoldString_appendBlock

/*
 * 途中で folding してよい固まりを append する
 * @return 成功した場合は 0, 失敗した場合は -1
 */
int
FoldString_appendNonBlock(FoldString *self, bool prefolding, const char *s)
{
    assert(NULL != self);
    assert(NULL != s);

    const char *p = s;
    ssize_t srcrest = strlen(s);

    // 現在の行に書き込む文字数を計算する
    ssize_t linespace = self->linelimits - self->linepos;   // 現在の行の残り文字数
    if (linespace <= 0) {
        if (prefolding) {
            // 残り文字数が負の数になっている場合は 0 に
            linespace = 0;
        } else {
            // スペースがなくても 1 文字は無理矢理書き込む
            linespace = 1;
        }   // end if
    }   // end if

    for (;;) {
        if (linespace > 0) {
            size_t writelen = MIN(linespace, srcrest);
            if (0 > XBuffer_appendStringN(self->xbuf, p, writelen)) {
                return -1;
            }   // end if
            p += writelen;
            srcrest -= writelen;
            self->linepos += writelen;
        }   // end if
        if (srcrest <= 0) {
            break;
        }   // end if
        if (0 > FoldString_folding(self)) {
            return -1;
        }   // end if
        linespace = self->linelimits - self->linepos;
    }   // end for

    return 0;
}   // end function: FoldString_appendNonBlock

/**
 * 途中で folding してはいけない固まりを append する
 * @return 成功した場合は 0, 失敗した場合は -1
 */
int
FoldString_appendFormatBlock(FoldString *self, bool prefolding, const char *format, ...)
{
    assert(NULL != self);

    va_list ap, aphead;
    char dummy;
    va_start(ap, format);
    va_copy(aphead, ap);
    // Solaris 9 では vsnprintf の第2引数に 0 を渡せない
    size_t len = vsnprintf(&dummy, 1, format, aphead);
    va_end(aphead);

    int ret;
    if (prefolding && 0 > FoldString_precede(self, len)) {
        ret = -1;
        goto cleanup;
    }   // end if

    if (0 > XBuffer_appendVFormatStringN(self->xbuf, len, format, ap)) {
        ret = -1;
        goto cleanup;
    }   // end if
    self->linepos += len;

    ret = 0;

  cleanup:
    va_end(ap);
    return ret;
}   // end function: FoldString_appendFormatBlock

/**
 * 1行に収める文字数を指定する
 * @param limits 1行に収める文字数
 * @attention この文字数は厳守されるものではなく,
 * 可能な限りこの文字数を越えないよう努力する, というもの
 */
void
FoldString_setLineLengthLimits(FoldString *self, size_t limits)
{
    assert(self);
    self->linelimits = limits;
}   // end function: FoldString_setLineLengthLimits

/**
 * 現在の行の残り文字数を size 文字減らす
 * folding の位置を調整するのに使用する
 */
void
FoldString_consumeLineSpace(FoldString *self, size_t size)
{
    assert(NULL != self);
    self->linepos += size;
}   // end function: FoldString_consumeLineSpace

/**
 * folding をおこなう際に CR を含めるかどうかを指定する
 * @param cr folding に CR を含める場合は true, LF のみにする場合は false
 */
void
FoldString_setFoldingCR(FoldString *self, bool cr)
{
    assert(NULL != self);
    self->folding_cr = cr;
}   // end function: FoldString_setFoldingCR

/**
 * 保持している文字列を返す
 */
const char *
FoldString_getString(const FoldString *self)
{
    assert(NULL != self);
    return XBuffer_getString(self->xbuf);
}   // end function: FoldString_getString

size_t
FoldString_getSize(const FoldString *self)
{
    assert(NULL != self);
    return XBuffer_getSize(self->xbuf);
}   // end function: FoldString_getSize
