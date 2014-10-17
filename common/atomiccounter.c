/*
 * Copyright (c) 2010-2014 Internet Initiative Japan Inc. All rights reserved.
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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>

#include "loghandler.h"
#include "atomiccounter.h"

struct AtomicCounter {
    int32_t counter;
    pthread_mutex_t lock;
    pthread_cond_t cond0;
};

AtomicCounter *
AtomicCounter_new(void)
{
    AtomicCounter *self = (AtomicCounter *) malloc(sizeof(AtomicCounter));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(AtomicCounter));

    self->counter = 1;
    int ret = pthread_mutex_init(&(self->lock), NULL);
    if (0 != ret) {
        LogError("pthread_mutex_init failed: errno=%s", strerror(ret));
        free(self);
        return NULL;
    }   // end if

    ret = pthread_cond_init(&(self->cond0), NULL);
    if (0 != ret) {
        LogError("pthread_cond_init failed: errno=%s", strerror(ret));
        (void) pthread_mutex_destroy(&(self->lock));
        free(self);
        return NULL;
    }   // end if

    return self;
}   // end function: AtomicCounter_new

void
AtomicCounter_free(AtomicCounter *self)
{
    if (NULL == self) {
        return;
    }   // end if

    int ret = pthread_mutex_destroy(&(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_destroy failed: errno=%s", strerror(ret));
    }   // end if

    ret = pthread_cond_destroy(&(self->cond0));
    if (0 != ret) {
        LogError("pthread_cond_destroy failed: errno=%s", strerror(ret));
    }   // end if

    free(self);
}   // end function: AtomicCounter_free

static int
AtomicCounter_add(AtomicCounter *self, int32_t addend)
{
    assert(NULL != self);

    int ret = pthread_mutex_lock(&(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_lock failed: errno=%s", strerror(ret));
        return ret;
    }   // end if

    if (0 > self->counter + addend) {
        // カウンタの値が負になってしまう
        (void) pthread_mutex_unlock(&(self->lock));
        return EINVAL;
    }   // end if

    self->counter += addend;

    if (0 >= self->counter) {
        ret = pthread_cond_broadcast(&(self->cond0));
        if (0 != ret) {
            LogError("pthread_cond_broadcast failed: errno=%s", strerror(ret));
        }   // end if
    }   // end if

    ret = pthread_mutex_unlock(&(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_unlock failed: errno=%s", strerror(ret));
    }   // end if

    return 0;
}   // end function: AtomicCounter_add

int
AtomicCounter_peek(AtomicCounter *self, int32_t *counter)
{
    assert(NULL != self);

    int ret = pthread_mutex_lock(&(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_lock failed: errno=%s", strerror(ret));
        return ret;
    }   // end if

    *counter = self->counter;

    ret = pthread_mutex_unlock(&(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_unlock failed: errno=%s", strerror(ret));
    }   // end if

    return 0;
}   // end function: AtomicCounter_peek

int
AtomicCounter_increment(AtomicCounter *self)
{
    return AtomicCounter_add(self, 1);
}   // end function: AtomicCounter_increment

int
AtomicCounter_decrement(AtomicCounter *self)
{
    return AtomicCounter_add(self, -1);
}   // end function: AtomicCounter_decrement

/**
 * @return 0 for success, otherwise status code that indicates error.
 * @error ETIMEDOUT
 * @error EPERM, EINVAL, EDEADLK, ENOMEM
 */
int
AtomicCounter_wait0(AtomicCounter *self, time_t timeout)
{
    assert(NULL != self);

    struct timespec abstime;
    if (0 < timeout) {
        struct timeval now;
        gettimeofday(&now, NULL);
        abstime.tv_sec = now.tv_sec + timeout;
        abstime.tv_nsec = now.tv_usec * 1000;
    }   // end if

    int ret = pthread_mutex_lock(&(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_lock failed: errno=%s", strerror(ret));
        return ret;
    }   // end if

    int exitstatus = 0;
    while (0 == exitstatus && 0 < self->counter) {
        if (0 < timeout) {
            exitstatus = pthread_cond_timedwait(&(self->cond0), &(self->lock), &abstime);
        } else {
            exitstatus = pthread_cond_wait(&(self->cond0), &(self->lock));
        }   // end if
    }   // end while

    ret = pthread_mutex_unlock(&(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_unlock failed: errno=%s", strerror(ret));
    }   // end if

    return exitstatus;
}   // end function: AtomicCounter_wait0
