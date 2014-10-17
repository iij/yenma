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

#ifndef __PTR_ARRAY_H__
#define __PTR_ARRAY_H__

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PtrArray PtrArray;

extern PtrArray *PtrArray_new(size_t size, void (*element_destructor) (void *element));
extern void PtrArray_free(PtrArray *self);
extern void PtrArray_reset(PtrArray *self);
extern void *PtrArray_get(const PtrArray *self, size_t pos);
extern void *PtrArray_steal(PtrArray *self, size_t pos);
extern int PtrArray_set(PtrArray *self, size_t pos, void *val);
extern int PtrArray_append(PtrArray *self, void *val);
extern void PtrArray_unappend(PtrArray *self);
extern size_t PtrArray_getCount(const PtrArray *self);
extern int PtrArray_adjustSize(PtrArray *self);
extern int PtrArray_reserve(PtrArray *self, size_t size);
extern void PtrArray_setGrowth(PtrArray *self, size_t growth);
extern void PtrArray_sort(PtrArray *self, int (*scompar) (const void *p1, const void *p2));
extern int PtrArray_binarySearch(PtrArray *self, const void *key,
                                 int (*kcompar) (const void *keyObj, const void *arrayElement),
                                 int (*scompar) (const void *p1, const void *p2));
extern int PtrArray_linearSearch(PtrArray *self, const void *key,
                                 int (*kcompar) (const void *keyObj, const void *arrayElement));
extern void PtrArray_shuffle(PtrArray *self);
extern PtrArray *PtrArray_copyShallowly(const PtrArray *orig);

#ifdef __cplusplus
}
#endif

#endif /* __PTR_ARRAY_H__ */
