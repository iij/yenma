/*
 * Copyright (c) 2006-2012 Internet Initiative Japan Inc. All rights reserved.
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
#include <stdlib.h>
#include <strings.h>
#include "strpairlist.h"

struct StrPairListItem {
    const char *key;
    const char *val;
    struct StrPairListItem *prev;
    struct StrPairListItem *next;
};

struct StrPairList {
    struct StrPairListItem *head;
    struct StrPairListItem *tail;
    size_t count;               // 保持している要素の数
};

/**
 * create StrPairList object
 * @return initialized StrPairList object, or NULL if memory allocation failed.
 */
StrPairList *
StrPairList_new(void)
{
    StrPairList *self = (StrPairList *) malloc(sizeof(StrPairList));
    if (NULL == self) {
        return NULL;
    }   // end if

    self->count = 0;
    self->head = NULL;
    self->tail = NULL;

    return self;
}   // end function: StrPairList_new

/**
 * release StrPairList object
 * @param self StrPairList object to release
 */
void
StrPairList_freeShallowly(StrPairList *self)
{
    if (NULL == self) {
        return;
    }   // end if

    StrPairListItem *cur, *pnext;
    pnext = self->head;
    while (NULL != (cur = pnext)) {
        pnext = cur->next;
        free(cur);
    }   // end for
    free(self);
}   // end function: StrPairList_freeShallowly

StrPairListItem *
StrPairList_insertShallowly(StrPairList *self, StrPairListItem *item, const char *key,
                            const char *val)
{
    assert(NULL != self);

    StrPairListItem *newitem = (StrPairListItem *) malloc(sizeof(StrPairListItem));
    if (NULL == newitem)
        return NULL;

    newitem->key = key;
    newitem->val = val;

    if (NULL == self->head && NULL == self->tail) { // 最初の1個の挿入
        newitem->prev = NULL;
        newitem->next = NULL;
        self->head = newitem;
        self->tail = newitem;

    } else if (NULL == item) {  // 先頭への挿入
        newitem->prev = NULL;
        newitem->next = self->head;
        self->head = newitem;
        self->head->prev = newitem;

    } else if (item == self->tail) {    // 末尾への挿入
        assert(item->next == NULL);
        newitem->prev = self->tail;
        newitem->next = NULL;
        self->tail->next = newitem;
        self->tail = newitem;

    } else {    // 先頭や末尾以外への挿入
        newitem->prev = item;
        newitem->next = item->next;
        item->next = newitem;
        item->next->prev = newitem;
    }   // end if

    ++self->count;
    return newitem;
}   // end function: StrPairList_insertShallowly

void
StrPairList_deleteShallowly(StrPairList *self, StrPairListItem *item)
{
    assert(NULL != self);
    assert(NULL != item);

    if (NULL == item->prev) {
        assert(self->head == item);
        self->head = item->next;
    } else {
        item->prev->next = item->next;
    }   // end if

    if (NULL == item->next) {
        assert(self->tail == item);
        self->tail = item->prev;
    } else {
        item->next->prev = item->prev;
    }   // end if

    free(item);
    --self->count;
    return;
}   // end function: StrPairList_deleteShallowly

size_t
StrPairList_count(const StrPairList *self)
{
    assert(NULL != self);
    return self->count;
}   // end function: StrPairList_head

StrPairListItem *
StrPairList_head(const StrPairList *self)
{
    assert(NULL != self);
    return self->head;
}   // end function: StrPairList_head

StrPairListItem *
StrPairList_tail(const StrPairList *self)
{
    assert(NULL != self);
    return self->tail;
}   // end function: StrPairList_tail

StrPairListItem *
StrPairList_prev(const StrPairList *self, StrPairListItem *item)
{
    assert(NULL != self);
    if (NULL != item) {
        return item->prev;
    }   // end if
    return self->tail;
}   // end function: StrPairList_prev

StrPairListItem *
StrPairList_next(const StrPairList *self, StrPairListItem *item)
{
    assert(NULL != self);
    if (NULL != item) {
        return item->next;
    }   // end if
    return self->head;
}   // end function: StrPairList_next

const char *
StrPairListItem_key(const StrPairListItem *self)
{
    assert(NULL != self);
    return self->key;
}   // end function: StrPairListItem_key

const char *
StrPairListItem_value(const StrPairListItem *self)
{
    assert(NULL != self);
    return self->val;
}   // end function: StrPairListItem_value

StrPairListItem *
StrPairList_findIgnoreCaseByKey(const StrPairList *self, const char *keyword,
                                StrPairListItem *start)
{
    assert(NULL != self);

    StrPairListItem *cur;

    for (cur = start ? start->next : self->head; cur; cur = cur->next) {
        if (0 == strcasecmp(keyword, cur->key)) {
            return cur;
        }   // end if
    }   // end for

    return NULL;
}   // end function: StrPairList_findIgnoreCaseByKey

StrPairListItem *
StrPairList_rfindIgnoreCaseByKey(const StrPairList *self, const char *keyword,
                                 StrPairListItem *start)
{
    assert(NULL != self);

    StrPairListItem *cur;

    for (cur = start ? start->prev : self->tail; cur; cur = cur->prev) {
        if (0 == strcasecmp(keyword, cur->key)) {
            return cur;
        }   //end if
    }   // end for

    return NULL;
}   // end function: StrPairList_rfindIgnoreCaseByKey
