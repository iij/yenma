/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
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
#include "ptrarray.h"
#include "strarray.h"

/**
 * create StrArray object
 * @return initialized StrArray object, or NULL if memory allocation failed.
 */
StrArray *
StrArray_new(size_t size)
{
    return PtrArray_new(size, free);
}   // end function: StrArray_new

/**
 * StrArray オブジェクトに格納している文字列への参照を取得する
 * @param self StrArray オブジェクト
 * @param pos 要素の番号
 * @return 文字列への参照
 */
const char *
StrArray_get(const StrArray *self, size_t pos)
{
    return (const char *) PtrArray_get(self, pos);
}   // end function: StrArray_get

/**
 * StrArray オブジェクトに文字列を格納する
 * @param self StrArray オブジェクト
 * @param pos 要素の番号
 * @param val 格納する文字列
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
StrArray_set(StrArray *self, size_t pos, const char *val)
{
    char *buf = strdup(val);
    if (NULL == buf) {
        return -1;
    }   // end if
    int ret = PtrArray_set(self, pos, buf);
    if (0 > ret) {
        free(buf);
    }   // end if
    return ret;
}   // end function: StrArray_set

/**
 * StrArray オブジェクトに文字列を格納する
 * @param self StrArray オブジェクト
 * @param pos 要素の番号
 * @param val 格納する文字列
 * @param len 格納する文字列のサイズ
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
StrArray_setWithLength(StrArray *self, size_t pos, const char *val, size_t len)
{
    char *buf = (char *) malloc(len + 1);
    if (NULL == buf) {
        return -1;
    }   // end if
    strncpy(buf, val, len);
    buf[len] = '\0';
    int ret = PtrArray_set(self, pos, buf);
    if (0 > ret) {
        free(buf);
    }   // end if
    return ret;
}   // end function: StrArray_setWithLength

/**
 * StrArray オブジェクトの末尾に文字列を格納する
 * @param self StrArray オブジェクト
 * @param val 格納する文字列
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
StrArray_append(StrArray *self, const char *val)
{
    return StrArray_set(self, StrArray_getCount(self), val);
}   // end function: StrArray_append


/**
 * StrArray オブジェクトの末尾に文字列を格納する
 * @param self StrArray オブジェクト
 * @param val 格納する文字列
 * @param len 格納する文字列のサイズ
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
StrArray_appendWithLength(StrArray *self, const char *val, size_t len)
{
    return StrArray_setWithLength(self, StrArray_getCount(self), val, len);
}   // end function: StrArray_appendWithLength

static int
StrArray_compareElement(const void *p1, const void *p2)
{
    return strcmp(*((const char **) p1), *((const char **) p2));
}   // end function: StrArray_compareElement

static int
StrArray_compareElementIgnoreCase(const void *p1, const void *p2)
{
    return strcasecmp(*((const char **) p1), *((const char **) p2));
}   // end function: StrPairArray_compareElementIgnoreCase

static int
StrArray_compareKey(const void *keyObj, const void *arrayElement)
{
    return strcmp((const char *) keyObj, *((const char **) arrayElement));
}   // end function: StrArray_compareKey

static int
StrArray_compareKeyIgnoreCase(const void *keyObj, const void *arrayElement)
{
    return strcasecmp((const char *) keyObj, *((const char **) arrayElement));
}   // end function: StrArray_compareKeyIgnoreCase

void
StrArray_sort(StrArray *self)
{
    assert(NULL != self);
    PtrArray_sort(self, StrArray_compareElement);
}   // end function: StrArray_sort

void
StrArray_sortIgnoreCase(StrArray *self)
{
    assert(NULL != self);
    PtrArray_sort(self, StrArray_compareElementIgnoreCase);
}   // end function: StrArray_sortIgnoreCase

int
StrArray_binarySearch(StrArray *self, const char *key)
{
    assert(NULL != self);
    return PtrArray_binarySearch(self, key, StrArray_compareKey, StrArray_compareElement);
}   // end function: StrArray_binarySearch

int
StrArray_binarySearchIgnoreCase(StrArray *self, const char *key)
{
    assert(NULL != self);
    return PtrArray_binarySearch(self, key, StrArray_compareKeyIgnoreCase,
                                 StrArray_compareElementIgnoreCase);
}   // end function: StrArray_binarySearchIgnoreCase

int
StrArray_linearSearch(StrArray *self, const char *key)
{
    assert(NULL != self);
    return PtrArray_linearSearch(self, key, StrArray_compareKey);
}   // end function: StrArray_linearSearch

int
StrArray_linearSearchIgnoreCase(StrArray *self, const char *key)
{
    assert(NULL != self);
    return PtrArray_linearSearch(self, key, StrArray_compareKeyIgnoreCase);
}   // end function: StrArray_linearSearchIgnoreCase

/**
 * 文字列を delim で区切った内容を要素として保持する StrArray オブジェクトを構築する.
 * @param input NULL-terminated string
 * @param delim delimiter
 * @param block_delimiter interpret continuous delimiters as single delimiters like strtok().
 * @return StrArray Object or NULL if an error occurred
 */
StrArray *
StrArray_split(const char *input, const char *delim, bool block_delimiter)
{
    StrArray *self = StrArray_new(0);
    if (NULL == self) {
        return NULL;
    }   // end if

    const char *p;
    for (p = input; '\0' != *p;) {
        const char *pdelim = strpbrk(p, delim);
        if (NULL == pdelim) {
            break;
        }   // end if
        if (0 > StrArray_appendWithLength(self, p, pdelim - p)) {
            goto cleanup;
        }   // end if
        p = pdelim + 1;
        if (block_delimiter) {
            for (; '\0' != *p && NULL != strchr(delim, *p); ++p);
        }   // end if
    }   // end for

    // append rest of string as an element
    if (0 > StrArray_append(self, p)) {
        goto cleanup;
    }   // end if
    return self;

  cleanup:
    if (NULL != self) {
        StrArray_free(self);
    }   // end if
    return NULL;
}   // end function: StrArray_split

StrArray *
StrArray_copyDeeply(const StrArray *orig)
{
    size_t num = StrArray_getCount(orig);
    StrArray *self = StrArray_new(num);
    if (NULL == self) {
        return NULL;
    }   // end if

    for (size_t i = 0; i < num; ++i) {
        const char *element = StrArray_get(orig, i);
        if (0 > StrArray_set(self, i, element)) {
            goto cleanup;
        }   // end if
    }   // end for
    return self;

  cleanup:
    StrArray_free(self);
    return NULL;
}   // end function: StrArray_copyDeeply
