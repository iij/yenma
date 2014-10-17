/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __PTROP_H__
#define __PTROP_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#ifndef PTRINIT
/// macro that applies free() to the non-NULL pointer and substitutes NULL
#define PTRINIT(__p) \
    do { \
        if (NULL != (__p)) { \
            free(__p); \
            (__p) = NULL; \
        } \
    } while (0)
#endif

#ifndef SETDEREF
/// macro that substitutes NULL to the non-NULL pointer
#define SETDEREF(__p, __v) \
    do { \
        if (NULL != (__p)) { \
            *(__p) = (__v); \
        } \
    } while (0)
#endif

#ifndef NNSTR
/// macro that avoids NULL-pointer access (mainly used with *printf)
#define NNSTR(__s)  (NULL != (__s) ? (__s) : "(NULL)")
#endif

#ifndef PTROR
/// macro that returns first argument if it isn't NULL, otherwise returns second argument (behaves like "or" operator of Python)
#define PTROR(__p, __q) (NULL != (__p) ? (__p) : (__q))
#endif

#ifndef STRTAIL
#define STRTAIL(__s)    ((__s) + strlen(__s))
#endif

/// macro that accesses the pointer of structure member with offset
#ifndef STRUCT_MEMBER_P
#define STRUCT_MEMBER_P(__struct_p, __struct_offset) \
        ((void *) ((char *) (__struct_p) + (ptrdiff_t) (__struct_offset)))
#endif
/// macro that accesses the value of structure member with offset
#ifndef STRUCT_MEMBER
#define STRUCT_MEMBER(__member_type, __struct_p, __struct_offset) \
        (*(__member_type *) STRUCT_MEMBER_P((__struct_p), (__struct_offset)))
#endif

#endif /* __PTROP_H__ */
