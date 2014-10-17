/*
 * Copyright (c) 2006-2013 Internet Initiative Japan Inc. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include "ptrop.h"
#include "pstring.h"

/**
 * head から始まり tail の直前までの領域を複製する．
 * 複製した文字列の終端には NULL を付加する．
 * @param head コピーする領域の開始点を示すポインタ
 * @param tail コピーする領域の終了点の次を示すポインタ
 * @return 成功した場合は複製した文字列へのポインタ，失敗した場合は NULL
 * @attention The returned string should be released with free() when no longer needed.
 */
char *
strpdup(const char *head, const char *tail)
{
    assert(head <= tail);

    size_t len = tail - head + 1;
    char *buf = (char *) malloc(len);
    if (NULL == buf) {
        return NULL;
    }   // end if

    const char *p;
    char *q;
    for (p = head, q = buf; p < tail; ++p, ++q) {
        *q = *p;
    }   // end if
    *q = '\0';
    return buf;
}   // end function: strpdup

/**
 * head から始まり tail の直前までの領域から文字 c を探索する
 * @param head 探索する領域の開始点を示すポインタ
 * @param tail 探索する領域の終了点の次を示すポインタ
 * @return 文字 c が見つかった場合はその文字へのポインタ，見つからなかった場合は NULL
 */
const char *
strpchr(const char *head, const char *tail, char c)
{
    for (const char *p = head; p < tail; ++p) {
        if (*p == c) {
            return p;
        }   // end if
    }   // end for
    return NULL;
}   // end function: strpchr

/**
 * head から始まり tail の直前までの領域から末尾に最も近い文字 c を探索する
 * @param head 探索する領域の開始点を示すポインタ
 * @param tail 探索する領域の終了点の次を示すポインタ
 * @return 文字 c が見つかった場合はその文字へのポインタ，見つからなかった場合は NULL
 */
const char *
strprchr(const char *head, const char *tail, char c)
{
    for (const char *p = tail - 1; head <= p; --p) {
        if (*p == c) {
            return p;
        }   // end if
    }   // end for
    return NULL;
}   // end function: strprchr

/*
 * 数字でない文字に遭遇する, 文字列の終端に達する, オーバーフローする直前, のいずれかの条件を満たすまで,
 * 文字列を数字だとみなしてパースする.
 * @return 解釈した数値. 数字が1文字も含まれていない場合は 0.
 */
unsigned long long
strptoull(const char *head, const char *tail, const char **endptr)
{
    const char *p;
    static const unsigned long long multmax = ULLONG_MAX / 10ULL;
    unsigned long long v = 0ULL, retv = 0ULL;

    for (p = head; p < tail && isdigit(*p); ++p) {
        // 10 倍しても安全か確認
        if (v > multmax) {
            // 10倍したらオーバーフローする
            break;
        }   // end if
        v *= 10ULL;
        unsigned long long dec = (unsigned long long) (*p - '0');
        // 1の位を足しても安全か確認
        if (ULLONG_MAX - v < dec) {
            // 1の位を足したらオーバーフローする
            break;
        }   // end if
        retv = v += dec;
    }   // end for
    SETDEREF(endptr, p);
    return retv;
}   // end function: strptoull

/*
 * 数字でない文字に遭遇する, 文字列の終端に達する, オーバーフローする直前, のいずれかの条件を満たすまで,
 * 文字列を数字だとみなしてパースする.
 * @return 解釈した数値. 数字が1文字も含まれていない場合は 0.
 */
unsigned long
strptoul(const char *head, const char *tail, const char **endptr)
{
    const char *p;
    static const unsigned long multmax = ULONG_MAX / 10UL;
    unsigned long v = 0UL, retv = 0UL;

    for (p = head; p < tail && isdigit(*p); ++p) {
        // 10 倍しても安全か確認
        if (v > multmax) {
            // 10倍したらオーバーフローする
            break;
        }   // end if
        v *= 10UL;
        unsigned long dec = (unsigned long) (*p - '0');
        // 1の位を足しても安全か確認
        if (ULONG_MAX - v < dec) {
            // 1の位を足したらオーバーフローする
            break;
        }   // end if
        retv = v += dec;
    }   // end for
    SETDEREF(endptr, p);
    return retv;
}   // end function: strptoul
