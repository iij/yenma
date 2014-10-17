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

#ifndef __FIELD_MASK_H__
#define __FIELD_MASK_H__

#include <sys/types.h>

// modification of FD_* macros (imported from FreeBSD)
typedef unsigned long __field_mask;
#define FIELD_SETSIZE       256U
#define _NFIELDBITS         (sizeof(__field_mask) * 8)  /* bits per mask */
#define _howmanyfield(x, y) (((x) + ((y) - 1)) / (y))
typedef struct field_set {
    __field_mask __field_bits[_howmanyfield(FIELD_SETSIZE, _NFIELDBITS)];
} field_set;
#define __fieldset_mask(n)  ((__field_mask)1 << ((n) % _NFIELDBITS))
#define FIELD_CLR(n, p)     ((p)->__field_bits[(n)/_NFIELDBITS] &= ~__fieldset_mask(n))
#define FIELD_ISSET(n, p)   (((p)->__field_bits[(n)/_NFIELDBITS] & __fieldset_mask(n)) != 0)
#define FIELD_SET(n, p)     ((p)->__field_bits[(n)/_NFIELDBITS] |= __fieldset_mask(n))
#define FIELD_ZERO(p) do {                              \
        field_set *_p;                                  \
        size_t _n;                                      \
                                                        \
        _p = (p);                                       \
        _n = _howmanyfield(FIELD_SETSIZE, _NFIELDBITS); \
        while (_n > 0)                                  \
                _p->__field_bits[--_n] = 0;             \
} while (0)

#endif /* __FIELD_MASK_H__ */
