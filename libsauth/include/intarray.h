/*
 * Copyright (c) 2006-2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __INT_ARRAY_H__
#define __INT_ARRAY_H__

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct IntArray;
typedef struct IntArray IntArray;

extern IntArray *IntArray_new(size_t size);
extern void IntArray_free(IntArray *self);
extern void IntArray_reset(IntArray *self);
extern int IntArray_get(const IntArray *self, size_t pos);
extern int IntArray_set(IntArray *self, size_t pos, int val);
extern int IntArray_append(IntArray *self, int val);
extern void IntArray_unappend(IntArray *self);
extern size_t IntArray_getCount(const IntArray *self);
extern int IntArray_adjustSize(IntArray *self);
extern int IntArray_reserve(IntArray *self, size_t size);
extern void IntArray_setGrowth(IntArray *self, size_t growth);
extern void IntArray_sort(IntArray *self);
extern int IntArray_binarySearch(IntArray *self, int key);
extern int IntArray_linearSearch(IntArray *self, int key);
extern void IntArray_shuffle(IntArray *self);
extern IntArray *IntArray_copy(const IntArray *orig);

#ifdef __cplusplus
}
#endif

#endif /* __INT_ARRAY_H__ */
