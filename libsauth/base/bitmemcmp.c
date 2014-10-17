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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdint.h>
#include <string.h>
#include "bitmemcmp.h"

/**
 * compares the first N bits of the arguments
 * @return an integer less than, equal to, or greater than 0, according as
 *         s1 is lexicographically less than, equal to, or greater than s2.
 *         0 if bits is 0.
 */
int
bitmemcmp(const void *s1, const void *s2, size_t bits)
{
    static const uint8_t bitmask[] = {
        0,
        0x80, 0xc0, 0xe0, 0xf0,
        0xf8, 0xfc, 0xfe, 0xff,
    };

    size_t bytes = bits / 8;
    if (bytes > 0) {
        int cmpstat = memcmp(s1, s2, bytes);
        if (0 != cmpstat) {
            return cmpstat;
        }   // end if
    }   // end if

    size_t oddbits = bits % 8;
    if (oddbits != 0) {
        uint8_t odd1 = ((const uint8_t *) s1)[bytes];
        uint8_t odd2 = ((const uint8_t *) s2)[bytes];
        if ((odd1 & bitmask[oddbits]) != (odd2 & bitmask[oddbits])) {
            return (odd1 & bitmask[oddbits]) > (odd2 & bitmask[oddbits]) ? 1 : -1;
        }   // end if
    }   // end if

    return 0;
}   // end function: bitmemcmp
