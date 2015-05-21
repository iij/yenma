/*
 * Copyright (c) 2010-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __ATOMIC_COUNTER_H__
#define __ATOMIC_COUNTER_H__

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AtomicCounter AtomicCounter;

extern AtomicCounter *AtomicCounter_new(void);
extern void AtomicCounter_free(AtomicCounter *self);
extern int AtomicCounter_peek(AtomicCounter *self, int32_t *counter);
extern int AtomicCounter_increment(AtomicCounter *self);
extern int AtomicCounter_decrement(AtomicCounter *self);
extern int AtomicCounter_wait0(AtomicCounter *self, time_t timeout);

#ifdef __cplusplus
}
#endif

#endif /* __ATOMIC_COUNTER_H__ */
