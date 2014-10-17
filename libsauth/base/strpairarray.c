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
#include "ptrop.h"
#include "strpairarray.h"

typedef struct StringPairElement {
    char *key;
    char *val;
    char buf[];
} StringPairElement;

static void
StrPairArray_freeElement(void *ptr)
{
    free(ptr);
}   // end function: StrPairArray_freeElement

/**
 * create StrPairArray object
 * @return initialized StrPairArray object, or NULL if memory allocation failed.
 */
StrPairArray *
StrPairArray_new(size_t size)
{
    return PtrArray_new(size, StrPairArray_freeElement);
}   // end function: StrPairArray_new

/**
 * StrPairArray オブジェクトに格納している文字列への参照を取得する
 * @param self StrPairArray オブジェクト
 * @param pos 要素の番号
 * @param pkey 当該の要素が保持する key への参照, NULL の場合は値を返さない
 * @param pval 当該の要素が保持する value への参照, NULL の場合は値を返さない
 */
void
StrPairArray_get(const StrPairArray *self, size_t pos, const char **pkey, const char **pval)
{
    assert(NULL != self);
    StringPairElement *pent = (StringPairElement *) PtrArray_get(self, pos);
    if (NULL != pent) {
        SETDEREF(pkey, pent->key);
        SETDEREF(pval, pent->val);
    } else {
        SETDEREF(pkey, NULL);
        SETDEREF(pval, NULL);
    }   // end if
    return;
}   // end function: StrPairArray_get

/**
 * StrPairArray オブジェクトに格納している文字列への参照を取得する
 * @param self StrPairArray オブジェクト
 * @param pos 要素の番号
 * @return 当該の要素が保持する key への参照
 */
const char *
StrPairArray_getKey(const StrPairArray *self, size_t pos)
{
    assert(NULL != self);
    StringPairElement *pent = (StringPairElement *) PtrArray_get(self, pos);
    return pent ? pent->key : NULL;
}   // end function: StrPairArray_getKey

/**
 * StrPairArray オブジェクトに格納している文字列への参照を取得する
 * @param self StrPairArray オブジェクト
 * @param pos 要素の番号
 * @return 当該の要素が保持する value への参照
 */
const char *
StrPairArray_getValue(const StrPairArray *self, size_t pos)
{
    assert(NULL != self);
    StringPairElement *pent = (StringPairElement *) PtrArray_get(self, pos);
    return pent ? pent->val : NULL;
}   // end function: StrPairArray_getValue

int
StrPairArray_setWithLength(StrPairArray *self, size_t pos, const char *key, size_t keylen,
                           const char *val, size_t vallen)
{
    assert(NULL != self);

    int ret;
    if (NULL != key) {
        StringPairElement *pent = (StringPairElement *) malloc(sizeof(StringPairElement) + keylen + vallen + 2);    // 2 は NULL 文字2個分
        if (NULL == pent) {
            return -1;
        }   // end if

        // val は key の直後につなげる
        memcpy(pent->buf, key, keylen);
        pent->buf[keylen] = '\0';
        memcpy(pent->buf + keylen + 1, val, vallen);
        pent->buf[keylen + 1 + vallen] = '\0';
        pent->key = pent->buf;
        pent->val = pent->buf + keylen + 1;

        ret = PtrArray_set(self, pos, pent);
        if (ret < 0) {
            free(pent);
        }   // end if
    } else {
        ret = PtrArray_set(self, pos, NULL);
    }   // end if
    return ret;
}   // end function: StrPairArray_setWithLength

/**
 * StrPairArray オブジェクトに文字列を格納する
 * @param self StrPairArray オブジェクト
 * @param pos 要素の番号
 * @param key 格納する key
 * @param val 格納する value
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
StrPairArray_set(StrPairArray *self, size_t pos, const char *key, const char *val)
{
    assert(NULL != self);
    size_t keylen = key ? strlen(key) : 0;
    size_t vallen = val ? strlen(val) : 0;
    return StrPairArray_setWithLength(self, pos, key, keylen, val, vallen);
}   // end function: StrPairArray_set

int
StrPairArray_appendWithLength(StrPairArray *self, const char *key, size_t keylen, const char *val,
                              size_t vallen)
{
    assert(NULL != self);
    return StrPairArray_setWithLength(self, StrPairArray_getCount(self), key, keylen, val, vallen);
}   // end function: StrPairArray_appendWithLength

/**
 * StrPairArray オブジェクトの末尾に文字列を格納する
 * @param self StrPairArray オブジェクト
 * @param key 格納する key
 * @param val 格納する value
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
StrPairArray_append(StrPairArray *self, const char *key, const char *val)
{
    assert(NULL != self);
    return StrPairArray_set(self, StrPairArray_getCount(self), key, val);
}   // end function: StrPairArray_append

static int
StrPairArray_compareElement(const void *p1, const void *p2)
{
    return strcmp((*((StringPairElement **) p1))->key, (*((StringPairElement **) p2))->key);
}   // end function: StrPairArray_compareElement

static int
StrPairArray_compareElementIgnoreCase(const void *p1, const void *p2)
{
    return strcasecmp((*((StringPairElement **) p1))->key, (*((StringPairElement **) p2))->key);
}   // end function: StrPairArray_compareElementIgnoreCase

static int
StrPairArray_compareKey(const void *keyObj, const void *arrayElement)
{
    return strcmp((const char *) keyObj, (*((StringPairElement **) arrayElement))->key);
}   // end function: StrPairArray_compareKey

static int
StrPairArray_compareKeyIgnoreCase(const void *keyObj, const void *arrayElement)
{
    return strcasecmp((const char *) keyObj, (*((StringPairElement **) arrayElement))->key);
}   // end function: StrPairArray_compareKeyIgnoreCase

void
StrPairArray_sortByKey(StrPairArray *self)
{
    assert(NULL != self);
    PtrArray_sort(self, StrPairArray_compareElement);
}   // end function: StrPairArray_sortByKey

void
StrPairArray_sortByKeyIgnoreCase(StrPairArray *self)
{
    assert(NULL != self);
    PtrArray_sort(self, StrPairArray_compareElementIgnoreCase);
}   // end function: StrPairArray_sortByKeyIgnoreCase

const char *
StrPairArray_binarySearchByKey(StrPairArray *self, const char *key)
{
    assert(NULL != self);
    int idx = PtrArray_binarySearch(self, key, StrPairArray_compareKey,
                                    StrPairArray_compareElement);
    return 0 <= idx ? StrPairArray_getValue(self, idx) : NULL;
}   // end function: StrPairArray_binarySearchByKey

const char *
StrPairArray_binarySearchByKeyIgnoreCase(StrPairArray *self, const char *key)
{
    assert(NULL != self);
    int idx = PtrArray_binarySearch(self, key, StrPairArray_compareKeyIgnoreCase,
                                    StrPairArray_compareElementIgnoreCase);
    return 0 <= idx ? StrPairArray_getValue(self, idx) : NULL;
}   // end function: StrPairArray_binarySearchByKeyIgnoreCase

const char *
StrPairArray_linearSearchByKey(StrPairArray *self, const char *key)
{
    assert(NULL != self);
    int idx = PtrArray_linearSearch(self, key, StrPairArray_compareKey);
    return 0 <= idx ? StrPairArray_getValue(self, idx) : NULL;
}   // end function: StrPairArray_linearSearchByKey

const char *
StrPairArray_linearSearchByKeyIgnoreCase(StrPairArray *self, const char *key)
{
    assert(NULL != self);
    int idx = PtrArray_linearSearch(self, key, StrPairArray_compareKeyIgnoreCase);
    return 0 <= idx ? StrPairArray_getValue(self, idx) : NULL;
}   // end function: StrPairArray_linearSearchByKeyIgnoreCase
