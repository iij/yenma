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
#include <search.h>
#include <stdbool.h>
#include "ptrarray.h"

#define ROUNDUP(c, base) ((((int) (((c) - 1) / (base))) + 1) * (base))

#define GROWTH_DEFAULT 10

struct PtrArray {
    void **buf;
    size_t count;               // 保持している要素の数
    size_t capacity;            // 現在のメモリで保持できる要素の数
    size_t growth;
    bool sorted;
    void (*element_destructor) (void *element);
};

/**
 * 指定した配列の要素を開放する
 * デストラクタが設定されている場合は適用する
 * @param self PtrArray オブジェクト
 * @param pos 要素の番号
 */
static void
PtrArray_freeElement(PtrArray *self, size_t pos)
{
    if (NULL != self->buf[pos]) {
        if (NULL != self->element_destructor) {
            self->element_destructor(self->buf[pos]);
        }   // end if
        self->buf[pos] = NULL;
    }   // end if
}   // end function: PtrArray_freeElement

/**
 * 確保しているメモリのサイズを変更する
 * @param self PtrArray オブジェクト
 * @param newsize 新たに設定する配列の要素数
 * @return 成功した場合は新たに確保したメモリにおける配列の要素数, 失敗した場合は -1
 */
static int
PtrArray_resize(PtrArray *self, size_t newsize)
{
    void **newbuf;
    size_t n;

    if (0 == newsize) {
        // 0 は許容しない仕様
        newsize = self->growth;
    }   // end if

    if (newsize == self->capacity) {
        // 領域を増減させる必要はない
        return self->capacity;
    }   // end if

    if (newsize > self->capacity) { // 拡大
        newbuf = (void **) realloc(self->buf, sizeof(void *) * (newsize));
        if (NULL == newbuf) {
            return -1;
        }   // end if
        self->buf = newbuf;
        for (n = self->capacity; n < newsize; ++n) {
            self->buf[n] = NULL;
        }   // end for

    } else {    // 縮小
        for (n = newsize; n < self->count; ++n) {
            PtrArray_freeElement(self, n);
        }   // end for
        newbuf = (void **) realloc(self->buf, sizeof(void *) * (newsize));
        if (NULL == newbuf) {
            return -1;
        }   // end if
        self->buf = newbuf;
    }   // end if

    self->capacity = newsize;
    return self->capacity;
}   // end function: PtrArray_resize

/**
 * create PtrArray object
 * @param size 配列の初期サイズ
 * @param element_destructor 配列の各要素を解放するデストラクタ, 不要な場合は NULL
 * @return initialized PtrArray object, or NULL if memory allocation failed.
 */
PtrArray *
PtrArray_new(size_t size, void (*element_destructor) (void *element))
{
    PtrArray *self = (PtrArray *) malloc(sizeof(PtrArray));
    if (NULL == self) {
        return NULL;
    }   // end if

    // 初期化
    self->buf = NULL;
    self->count = 0;
    self->capacity = 0;
    self->growth = GROWTH_DEFAULT;
    self->sorted = false;
    self->element_destructor = element_destructor;

    if (0 > PtrArray_resize(self, size)) {
        free(self);
        return NULL;
    }   // end if

    return self;
}   // end function: PtrArray_new

/**
 * release PtrArray object
 * @param self PtrArray object to release
 * @attention デストラクタを使用していない場合はメモリリークに注意
 */
void
PtrArray_free(PtrArray *self)
{
    if (NULL == self) {
        return;
    }   // end if

    if (NULL != self->buf) {
        for (size_t n = 0; n < self->count; ++n) {
            PtrArray_freeElement(self, n);
        }   // end for
        free(self->buf);
    }   // end if
    free(self);
}   // end function: PtrArray_free

/**
 * PtrArray オブジェクトが管理している全ての要素を解放し, PtrArray オブジェクトを再初期化する．
 * PtrArray オブジェクトそのものは解放しない
 * @param self リセットする PtrArray オブジェクト
 * @attention デストラクタを使用していない場合はメモリリークに注意
 */
void
PtrArray_reset(PtrArray *self)
{
    assert(NULL != self);
    for (size_t n = 0; n < self->count; ++n) {
        PtrArray_freeElement(self, n);
    }   // end if
    self->count = 0;
    self->sorted = false;
}   // end function: PtrArray_reset

/**
 * PtrArray オブジェクトに格納している要素へのポインタを取得する
 * @param self PtrArray オブジェクト
 * @param pos 要素の番号
 * @return 格納している要素へのポインタ
 */
void *
PtrArray_get(const PtrArray *self, size_t pos)
{
    assert(NULL != self);
    assert(pos < self->count);
    return self->buf[pos];
}   // end function: PtrArray_get

void *
PtrArray_steal(PtrArray *self, size_t pos)
{
    assert(NULL != self);
    assert(pos < self->count);

    void *p = self->buf[pos];
    self->buf[pos] = NULL;
    return p;
}   // end function: PtrArray_steal

/**
 * PtrArray オブジェクトにポインタを格納する
 * @param self PtrArray オブジェクト
 * @param pos 要素の番号
 * @param val 格納するポインタ
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 * @attention デストラクタを使用していない場合はメモリリークに注意
 */
int
PtrArray_set(PtrArray *self, size_t pos, void *val)
{
    assert(NULL != self);
    self->sorted = false;
    if (self->capacity <= pos) {
        // 添え字の番号は 0-origin, 配列のサイズは 1-origin なので pos に 1 を加えている
        if (0 > PtrArray_resize(self, ROUNDUP(pos + 1, self->growth))) {
            return -1;
        }   // end if
    }   // end if

    // 既に使われている場合は解放
    PtrArray_freeElement(self, pos);

    self->buf[pos] = val;
    if (self->count <= pos) {
        self->count = pos + 1;
    }   // end if
    return pos;
}   // end function: PtrArray_set

/**
 * PtrArray オブジェクトの末尾にポインタを格納する
 * @param self PtrArray オブジェクト
 * @param val 格納するポインタ
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
PtrArray_append(PtrArray *self, void *val)
{
    assert(NULL != self);
    return PtrArray_set(self, self->count, val);
}   // end function: PtrArray_append

/**
 * PtrArray 配列の末尾要素を削除する
 * 配列が空の場合は何も起こらない
 * @param self PtrArray オブジェクト
 * @attention デストラクタを使用していない場合はメモリリークに注意
 */
void
PtrArray_unappend(PtrArray *self)
{
    assert(NULL != self);

    // 末尾要素の削除なのでソート状態に変化はない

    if (0 == self->count) {
        return;
    }   // end if

    --(self->count);
    PtrArray_freeElement(self, self->count);
}   // end function: PtrArray_unappend

/**
 * PtrArray オブジェクトが保持する要素の数を取得する
 * @param self PtrArray オブジェクト
 * @return PtrArray オブジェクトが保持する要素の数
 */
size_t
PtrArray_getCount(const PtrArray *self)
{
    assert(NULL != self);
    return self->count;
}   // end function: PtrArray_getCount

/**
 * PtrArray オブジェクトが保持する要素の数に合わせて, 確保しているメモリのサイズを調整する
 * @param self PtrArray オブジェクト
 * @return 成功した場合は新たに確保したメモリにおける配列の要素数, 失敗した場合は -1
 * @attention 確保する要素数は growth の倍数になるように調整される
 */
int
PtrArray_adjustSize(PtrArray *self)
{
    assert(NULL != self);
    return PtrArray_resize(self, ROUNDUP(self->count, self->growth));
}   // end function: PtrArray_adjustSize

/**
 * 予め必要な配列のサイズがわかっている場合に, 先に十分な大きさのメモリを確保する
 * @param self PtrArray オブジェクト
 * @param size 確保する配列の要素数
 * @return 成功した場合は新たに確保したメモリにおける配列の要素数, 失敗した場合は -1
 * @attention 確保する要素数は growth の倍数になるように調整される
 * @attention デストラクタを使用していない場合はメモリリークに注意
 */
int
PtrArray_reserve(PtrArray *self, size_t size)
{
    assert(NULL != self);
    return self->capacity < size ? PtrArray_resize(self, ROUNDUP(size, self->growth)) : -1;
}   // end function: PtrArray_reserve

/**
 * 配列の拡張をおこなう単位を指定する
 * @param self PtrArray オブジェクト
 * @return 配列の拡張をおこなう単位
 */
void
PtrArray_setGrowth(PtrArray *self, size_t growth)
{
    assert(NULL != self);
    self->growth = growth;
}   // end function: PtrArray_setGrowth

void
PtrArray_sort(PtrArray *self, int (*ecompar) (const void *p1, const void *p2))
{
    assert(NULL != self);
    assert(NULL != ecompar);
    if (0 < self->count) {
        qsort(self->buf, self->count, sizeof(void *), ecompar);
    }   // end if
    self->sorted = true;
}   // end function: PtrArray_sort

int
PtrArray_binarySearch(PtrArray *self, const void *key,
                      int (*kcompar) (const void *keyObj, const void *arrayElement),
                      int (*ecompar) (const void *p1, const void *p2))
{
    assert(NULL != self);
    assert(NULL != kcompar);
    if (!(self->sorted) && NULL != ecompar) {
        PtrArray_sort(self, ecompar);
    }   // end if
    void **pelement = (void **) bsearch(key, self->buf, self->count, sizeof(void *), kcompar);
    return pelement ? (pelement - self->buf) : -1;
}   // end function: PtrArray_binarySearch

int
PtrArray_linearSearch(PtrArray *self, const void *key,
                      int (*kcompar) (const void *keyObj, const void *arrayElement))
{
    assert(NULL != self);
    assert(NULL != kcompar);
    void **pelement = (void **) lfind(key, self->buf, &(self->count), sizeof(void *), kcompar);
    return pelement ? (pelement - self->buf) : -1;
}   // end function: PtrArray_linearSearch

void
PtrArray_shuffle(PtrArray *self)
{
    for (size_t i = 1; i < self->count; ++i) {
        size_t j = rand() % (i + 1);    // NOTE: self->count が大きいと偏る
        void *swap_tmp = self->buf[j];
        self->buf[j] = self->buf[i];
        self->buf[i] = swap_tmp;
    }   // end for
    self->sorted = false;
}   // end function: PtrArray_shuffle

/**
 * PtrArray の shallow copy を作成する. つまり, 配列インデックスはコピーするが, ポインタの参照先はコピーしない.
 * ポインタ参照先の所有権は移動しない. つまり, 配列の要素に対するデストラクタは設定されず,
 * オリジナルの要素の解放はコピー元の PtrArray によっておこなわれる.
 * @attention コピー元配列の要素が更新/削除された場合, この関数によって作成されたコピーは無効な領域を指すことになることに注意.
 */
PtrArray *
PtrArray_copyShallowly(const PtrArray *orig)
{
    PtrArray *self = (PtrArray *) malloc(sizeof(PtrArray));
    if (NULL == self) {
        return NULL;
    }   // end if

    // (PtrArray_resize のための) 初期化
    self->buf = NULL;
    self->count = 0;
    self->capacity = 0;
    self->growth = orig->growth;
    self->element_destructor = NULL;    // デストラクタはコピーしない仕様

    if (0 > PtrArray_resize(self, orig->count)) {
        free(self);
        return NULL;
    }   // end if

    // 参照をコピー
    memcpy(self->buf, orig->buf, sizeof(void *) * (orig->count));
    self->count = orig->count;
    self->sorted = orig->sorted;

    return self;
}   // end function: PtrArray_copyShallowly
