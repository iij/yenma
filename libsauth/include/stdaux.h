/*
 * Copyright (c) 2008-2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __STDAUX_H__
#define __STDAUX_H__

#include <stdbool.h>
#include <errno.h>

#ifndef SKIP_EINTR
#define SKIP_EINTR(__expr) do {} while (-1 == (__expr) && EINTR == errno)
#endif

#ifndef bool_cast
#define bool_cast(__expr) ((__expr) ? true : false)
#endif

#ifndef MIN
#define MIN(__a, __b)   ((__a) < (__b) ? (__a) : (__b))
#endif

#ifndef MAX
#define MAX(__a, __b)   ((__a) > (__b) ? (__a) : (__b))
#endif

#endif /*__STDAUX_H__*/
