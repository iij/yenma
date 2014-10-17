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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <search.h>
#include <stdbool.h>
#include "intarray.h"

#define ROUNDUP(c, base) ((((int) (((c) - 1) / (base))) + 1) * (base))

#define GROWTH_DEFAULT 10

struct IntArray {
    int *buf;
    size_t count;               // 保持している要素の数
    size_t capacity;            // 現在のメモリで保持できる要素の数
    size_t growth;
    bool sorted;
};

/**
 * 確保しているメモリのサイズを変更する
 * @param a IntArray オブジェクト
 * @param newsize 新たに設定する配列の要素数
 * @return 成功した場合は新たに確保したメモリにおける配列の要素数, 失敗した場合は -1
 */
static int
IntArray_resize(IntArray *self, size_t newsize)
{
    if (newsize == self->capacity) {
        return self->capacity;
    }   // end if

    if (newsize == 0) {
        newsize = self->growth;
    }   // end if

    int *newbuf = (int *) realloc(self->buf, sizeof(int) * (newsize));
    if (NULL == newbuf) {
        return -1;
    }   // end if
    self->buf = newbuf;

    // 縮小動作の場合は条件が真にならないのでスキップされるだけ
    for (size_t n = self->capacity; n < newsize; ++n) {
        self->buf[n] = 0;
    }   // end if

    self->capacity = newsize;
    return self->capacity;
}   // end function: IntArray_resize

/**
 * create IntArray object
 * @return initialized IntArray object, or NULL if memory allocation failed.
 */
IntArray *
IntArray_new(size_t size)
{
    IntArray *self = (IntArray *) malloc(sizeof(IntArray));
    if (NULL == self)
        return NULL;

    // memset(self, 0, sizeof(IntArray));
    self->buf = NULL;
    self->count = 0;
    self->capacity = 0;
    self->growth = GROWTH_DEFAULT;
    self->sorted = false;

    if (0 > IntArray_resize(self, size)) {
        free(self);
        return NULL;
    }   // end if

    return self;
}   // end function: IntArray_new

/**
 * release IntArray object
 * @param self IntArray object to release
 */
void
IntArray_free(IntArray *self)
{
    if (NULL == self) {
        return;
    }   // end if

    free(self->buf);
    free(self);
}   // end function: IntArray_free

void
IntArray_reset(IntArray *self)
{
    assert(NULL != self);
    self->count = 0;
    self->sorted = false;
}   // end function: IntArray_reset

/**
 * IntArray オブジェクトに格納している INT 値を取得する
 * @param self IntArray オブジェクト
 * @param pos 要素の番号
 * @return 格納している INT 値
 */
int
IntArray_get(const IntArray *self, size_t pos)
{
    assert(NULL != self);
    assert(pos < self->count);
    return self->buf[pos];
}   // end function: IntArray_get

/**
 * IntArray オブジェクトに INT 値 を格納する
 * @param self IntArray オブジェクト
 * @param pos 要素の番号
 * @param val 格納する INT 値
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
IntArray_set(IntArray *self, size_t pos, int val)
{
    assert(NULL != self);
    self->sorted = false;
    if (self->capacity <= pos) {
        // 添え字の番号は 0-origin, 配列のサイズは 1-origin なので pos に 1 を加えている
        if (0 > IntArray_resize(self, ROUNDUP(pos + 1, self->growth))) {
            return -1;
        }   // end if
    }   // end if
    self->buf[pos] = val;
    if (self->count <= pos) {
        self->count = pos + 1;
    }   // end if
    return pos;
}   // end function: IntArray_set

/**
 * IntArray オブジェクトの末尾に INT 値を格納する
 * @param self IntArray オブジェクト
 * @param val 格納する文字列
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
IntArray_append(IntArray *self, int val)
{
    assert(NULL != self);
    return IntArray_set(self, self->count, val);
}   // end function: IntArray_append

/**
 * IntArray 配列の末尾要素を削除する
 * 配列が空の場合は何も起こらない
 * @param self IntArray オブジェクト
 */
void
IntArray_unappend(IntArray *self)
{
    assert(NULL != self);

    if (0 == self->count) {
        return;
    }   // end if

    // 末尾要素の削除なのでソート状態に変化はない
    --(self->count);
    self->buf[self->count] = 0;
}   // end function: IntArray_unappend

/**
 * IntArray オブジェクトが保持する要素の数を取得する
 * @param self IntArray オブジェクト
 * @return IntArray オブジェクトが保持する要素の数
 */
size_t
IntArray_getCount(const IntArray *self)
{
    assert(NULL != self);
    return self->count;
}   // end function: IntArray_getCount

/**
 * IntArray オブジェクトが保持する要素の数に合わせて, 確保しているメモリのサイズを調整する
 * @param self IntArray オブジェクト
 * @return 成功した場合は新たに確保したメモリにおける配列の要素数, 失敗した場合は -1
 * @attention 実際に確保する要素数は growth の倍数になるように調整される
 */
int
IntArray_adjustSize(IntArray *self)
{
    assert(NULL != self);
    return IntArray_resize(self, ROUNDUP(self->count, self->growth));
}   // end function: IntArray_adjustSize

/**
 * 予め必要な配列のサイズがわかっている場合に, 先に十分な大きさのメモリを確保する
 * @param self IntArray オブジェクト
 * @param size 確保する配列の要素数
 * @return 成功した場合は新たに確保したメモリにおける配列の要素数, 失敗した場合は -1
 * @attention 実際に確保する要素数は growth の倍数になるように調整される
 */
int
IntArray_reserve(IntArray *self, size_t size)
{
    assert(NULL != self);
    return self->capacity < size ? IntArray_resize(self, ROUNDUP(size, self->growth)) : -1;
}   // end function: IntArray_reserve

/**
 * 配列の拡張をおこなう単位を指定する
 * @param self IntArray オブジェクト
 * @return 配列の拡張をおこなう単位
 */
void
IntArray_setGrowth(IntArray *self, size_t growth)
{
    assert(NULL != self);
    self->growth = growth;
}   // end function: IntArray_setGrowth

static int
IntArray_compareElement(const void *p1, const void *p2)
{
    return *((const int *) p1) - *((const int *) p2);
}   // end function: IntArray_compareElement

/*
 * ソートをおこなう
 */
void
IntArray_sort(IntArray *self)
{
    assert(NULL != self);
    if (0 < self->count) {
        qsort(self->buf, self->count, sizeof(int), IntArray_compareElement);
    }   // end if
    self->sorted = true;
}   // end function: IntArray_sort

/*
 * 二分探索をおこなう. ソートが済んでいない場合は先にソートをおこなう.
 * @return マッチした場合は値が格納されている最初の要素のインデックス, マッチしなかった場合は -1
 */
int
IntArray_binarySearch(IntArray *self, int key)
{
    assert(NULL != self);
    if (!(self->sorted)) {
        IntArray_sort(self);
    }   // end if
    int *pval = (int *) bsearch(&key, self->buf, self->count, sizeof(int), IntArray_compareElement);
    return pval ? (pval - self->buf) : -1;  // (int *) どうしの減算なので, sizeof(int) で割る必要はない
}   // end function: IntArray_binarySearch

/*
 * 線形探索をおこなう.
 * @return マッチした場合は値が格納されている最初の要素のインデックス, マッチしなかった場合は -1
 */
int
IntArray_linearSearch(IntArray *self, int key)
{
    assert(NULL != self);
    int *pval =
        (int *) lfind(&key, self->buf, &(self->count), sizeof(int), IntArray_compareElement);
    return pval ? (pval - self->buf) : -1;  // (int *) どうしの減算なので, sizeof(int) で割る必要はない
}   // end function: IntArray_linearSearch

void
IntArray_shuffle(IntArray *self)
{
    assert(NULL != self);
    for (size_t i = 1; i < self->count; ++i) {
        size_t j = rand() % (i + 1);    // NOTE: self->count が大きいと偏る
        int swap_tmp = self->buf[j];
        self->buf[j] = self->buf[i];
        self->buf[i] = swap_tmp;
    }   // end for
    self->sorted = false;
}   // end function: IntArray_shuffle

IntArray *
IntArray_copy(const IntArray *orig)
{
    assert(NULL != orig);

    IntArray *self = (IntArray *) malloc(sizeof(IntArray));
    if (NULL == self) {
        return NULL;
    }   // end if

    // (ItrArray_resize のための) 初期化
    self->buf = NULL;
    self->count = 0;
    self->capacity = 0;
    self->growth = orig->growth;

    if (0 > IntArray_resize(self, orig->count)) {
        free(self);
        return NULL;
    }   // end if

    // 参照をコピー
    memcpy(self->buf, orig->buf, sizeof(int) * (orig->count));
    self->count = orig->count;
    self->sorted = orig->sorted;

    return self;
}   // end function: IntArray_copy
