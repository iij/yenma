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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>

#include "loghandler.h"
#include "refcountobj.h"

RefCountObj *
RefCountObj_ref(RefCountObj *self)
{
    if (NULL == self) {
        return NULL;
    }   // end if

    int ret = pthread_mutex_lock(&(self->refcount_lock));
    if (0 != ret) {
        LogError("pthread_mutex_lock failed: errno=%s", strerror(ret));
        return NULL;
    }   // end if

    RefCountObj *retobj;
    if (0 == self->refcount) {
        retobj = NULL;
    } else {
        ++(self->refcount);
        retobj = self;
    }   // end if

    ret = pthread_mutex_unlock(&(self->refcount_lock));
    if (0 != ret) {
        LogError("pthread_mutex_unlock failed: errno=%s", strerror(ret));
    }   // end if

    return retobj;
}   // end function: RefCountObj_ref

void
RefCountObj_unref(RefCountObj *self)
{
    if (NULL == self) {
        return;
    }   // end if

    int ret = pthread_mutex_lock(&(self->refcount_lock));
    if (0 != ret) {
        LogError("pthread_mutex_lock failed: errno=%s", strerror(ret));
    }   // end if

    bool destruct_obj = false;
    if (1 < self->refcount) {
        --(self->refcount);
    } else {
        destruct_obj = true;
    }   // end if

    ret = pthread_mutex_unlock(&(self->refcount_lock));
    if (0 != ret) {
        LogError("pthread_mutex_unlock failed: errno=%s", strerror(ret));
    }   // end if

    if (destruct_obj) {
        self->freefunc(self);
    }   // end if
}   // end function: RefCountObj_unref
