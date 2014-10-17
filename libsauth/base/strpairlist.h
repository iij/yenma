/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __STR_PAIR_LIST_H__
#define __STR_PAIR_LIST_H__

#include <sys/types.h>

struct StrPairList;
typedef struct StrPairList StrPairList;

struct StrPairListItem;
typedef struct StrPairListItem StrPairListItem;

extern StrPairList *StrPairList_new(void);
extern void StrPairList_freeShallowly(StrPairList *self);
extern StrPairListItem *StrPairList_insertShallowly(StrPairList *self, StrPairListItem *cur,
                                                    const char *key, const char *val);
extern void StrPairList_deleteShallowly(StrPairList *self, StrPairListItem *cur);
extern size_t StrPairList_count(const StrPairList *self);
extern StrPairListItem *StrPairList_head(const StrPairList *self);
extern StrPairListItem *StrPairList_tail(const StrPairList *self);
extern StrPairListItem *StrPairList_prev(const StrPairList *self, StrPairListItem *cur);
extern StrPairListItem *StrPairList_next(const StrPairList *self, StrPairListItem *cur);
extern StrPairListItem *StrPairList_rfindIgnoreCaseByKey(const StrPairList *self,
                                                         const char *keyword,
                                                         StrPairListItem *start);
extern StrPairListItem *StrPairList_findIgnoreCaseByKey(const StrPairList *self,
                                                        const char *keyword,
                                                        StrPairListItem *start);

extern const char *StrPairListItem_key(const StrPairListItem *self);
extern const char *StrPairListItem_value(const StrPairListItem *self);

#endif /* __STR_PAIR_LIST_H__ */
