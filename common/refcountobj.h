/*
 * Copyright (c) 2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __REFCOUNT_OBJ_H__
#define __REFCOUNT_OBJ_H__

#include <sys/types.h>
#include <stddef.h>
#include <pthread.h>

#define RefCountObj_MEMBER            \
    size_t refcount;                  \
    pthread_mutex_t refcount_lock;    \
    void (*freefunc)(void *)

#define RefCountObj_INIT(_self) ((_self)->refcount = 1, pthread_mutex_init(&((_self)->refcount_lock), NULL))
#define RefCountObj_FINI(_self) pthread_mutex_destroy(&((_self)->refcount_lock))

typedef struct RefCountObj {
    RefCountObj_MEMBER;
} RefCountObj;

extern RefCountObj *RefCountObj_ref(RefCountObj *self);
extern void RefCountObj_unref(RefCountObj *self);

#endif /* __REFCOUNT_OBJ_H__ */
