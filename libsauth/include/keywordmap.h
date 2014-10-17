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

#ifndef __KEYWORD_MAP_H__
#define __KEYWORD_MAP_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KeywordMap {
    const char *keyword;
    const int value;
} KeywordMap;

typedef struct KeywordMap64 {
    const char *keyword;
    const uint64_t value;
} KeywordMap64;

extern int KeywordMap_lookupByString(const KeywordMap *table, const char *keyword);
extern int KeywordMap_lookupByStringSlice(const KeywordMap *table, const char *head,
                                          const char *tail);
extern int KeywordMap_lookupByCaseString(const KeywordMap *table, const char *keyword);
extern int KeywordMap_lookupByCaseStringSlice(const KeywordMap *table, const char *head,
                                              const char *tail);
extern const char *KeywordMap_lookupByValue(const KeywordMap *table, int value);

extern uint64_t KeywordMap64_lookupByCaseString(const KeywordMap64 *table, const char *keyword);
extern uint64_t KeywordMap64_lookupByCaseStringSlice(const KeywordMap64 *table, const char *head,
                                                     const char *tail);
extern const char *KeywordMap64_lookupByValue(const KeywordMap64 *table, uint64_t value);

#ifdef __cplusplus
}
#endif

#endif /* __KEYWORD_MAP_H__ */
