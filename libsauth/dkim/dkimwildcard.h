/*
 * Copyright (c) 2006-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __DKIM_WILDCARD_H__
#define __DKIM_WILDCARD_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

extern bool DkimWildcard_matchPubkeyGranularity(const char *patternhead, const char *patterntail,
                                                const char *inputhead, const char *inputtail);

#ifdef __cplusplus
}
#endif

#endif /* __DKIM_WILDCARD_H__ */
