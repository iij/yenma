/*
 * Copyright (c) 2006-2011 Internet Initiative Japan Inc. All rights reserved.
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
#include <string.h>

#include "ptrop.h"
#include "stdaux.h"
#include "xskip.h"
#include "dkimwildcard.h"

static bool
DkimWildcard_matchPubkeyGranularityImpl(const char *pattern_head, const char *pattern_tail,
                                        const char *target_head, const char *target_tail,
                                        bool accept_wildcard)
{
    /*
     * the ABNF of key-g-tag-lpart says only one wildcard is acceptable.
     * But '*' itself is included in dot-atom-text.
     * So this function treats the first occurrence of '*' as wildcard,
     * and next or later occurrence of '*' as character.
     *
     * [RFC4871] 3.6.1.
     * key-g-tag       = %x67 [FWS] "=" [FWS] key-g-tag-lpart
     * key-g-tag-lpart = [dot-atom-text] ["*" [dot-atom-text] ]
     */

    const char *pattern;
    const char *target;

    for (pattern = pattern_head, target = target_head; pattern < pattern_tail; ++pattern, ++target) {
        if ('*' == *pattern) {
            if (accept_wildcard) {
                // treat '*' as wildcard
                ++pattern;
                for (const char *bq = target_tail; target <= bq; --bq) {
                    if (DkimWildcard_matchPubkeyGranularityImpl
                        (pattern, pattern_tail, bq, target_tail, false)) {
                        return true;
                    }   // end if
                }   // end for
                return false;
            } else {
                // treat '*' as (not wildcard but) character
                if (target_tail <= target || '*' != *target) {
                    return false;
                }   // end if
            }   // end if
        } else if (IS_ATEXT(*pattern) || '.' == *pattern) {
            /*
             * compare case-sensitively.
             *
             * [RFC6376] 3.2.
             * Values MUST be
             * processed as case sensitive unless the specific tag description of
             * semantics specifies case insensitivity.
             *
             * And the local-part of mailbox is essentially treated as case-sensitive.
             *
             * [RFC5321] 2.4.
             * ... The
             * local-part of a mailbox MUST BE treated as case sensitive.
             */
            if (target_tail <= target || *pattern != *target) {
                return false;
            }   // end if
        } else {
            // neither atext nor '.' (included in dot-atom-text)
            return false;
        }   // end if
    }   // end for
    return bool_cast(pattern == pattern_tail && target == target_tail);
}   // end function: DkimWildcard_matchPubkeyGranularityImpl

/**
 * compare "target" (generally localpart of AUID) with "pattern"
 * (key-g-tag, granularity of DKIM public key record, which is obsoleted by RFC6376).
 *
 * @param pattern_head
 * @param pattern_tail
 * @param target_head
 * @param target_tail
 * @return true if pattern matches target, false otherwise
 * @attention only first '*' of given pattern is treated as wildcard,
 *            second or later '*' is treated as character.
 */
bool
DkimWildcard_matchPubkeyGranularity(const char *pattern_head, const char *pattern_tail,
                                    const char *target_head, const char *target_tail)
{
    /*
     * [RFC4871] 3.6.1.
     * An empty "g=" value never matches any addresses.
     */
    if (pattern_head == pattern_tail) {
        return false;
    }   // end if

    return DkimWildcard_matchPubkeyGranularityImpl(pattern_head, pattern_tail, target_head,
                                                   target_tail, true);
}   // end function: DkimWildcard_matchPubkeyGranularity
