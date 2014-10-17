/*
 * Copyright (c) 2008-2012 Internet Initiative Japan Inc. All rights reserved.
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

#include <string.h>
#include <strings.h>
#include "keywordmap.h"

int
KeywordMap_lookupByString(const KeywordMap *table, const char *keyword)
{
    const KeywordMap *p;
    for (p = table; NULL != p->keyword; ++p) {
        if (0 == strcmp(p->keyword, keyword)) {
            return p->value;
        }   // end if
    }   // end for
    return p->value;
}   // end function: KeywordMap_lookupByString

int
KeywordMap_lookupByStringSlice(const KeywordMap *table, const char *head, const char *tail)
{
    const KeywordMap *p;
    for (p = table; NULL != p->keyword; ++p) {
        if (0 == strncmp(p->keyword, head, tail - head) && '\0' == p->keyword[tail - head]) {
            return p->value;
        }   // end if
    }   // end for
    return p->value;
}   // end function: KeywordMap_lookupByStringSlice

int
KeywordMap_lookupByCaseString(const KeywordMap *table, const char *keyword)
{
    const KeywordMap *p;
    for (p = table; NULL != p->keyword; ++p) {
        if (0 == strcasecmp(p->keyword, keyword)) {
            return p->value;
        }   // end if
    }   // end for
    return p->value;
}   // end function: KeywordMap_lookupByCaseString

int
KeywordMap_lookupByCaseStringSlice(const KeywordMap *table, const char *head, const char *tail)
{
    const KeywordMap *p;
    for (p = table; NULL != p->keyword; ++p) {
        if (0 == strncasecmp(p->keyword, head, tail - head) && '\0' == p->keyword[tail - head]) {
            return p->value;
        }   // end if
    }   // end for
    return p->value;
}   // end function: KeywordMap_lookupByCaseStringSlice

const char *
KeywordMap_lookupByValue(const KeywordMap *table, int value)
{
    const KeywordMap *p;
    for (p = table; NULL != p->keyword; ++p) {
        if (p->value == value) {
            return p->keyword;
        }   // end if
    }   // end for
    return NULL;
}   // end function: KeywordMap_lookupByValue

const char *
KeywordMap64_lookupByValue(const KeywordMap64 *table, uint64_t value)
{
    const KeywordMap64 *p;
    for (p = table; NULL != p->keyword; ++p) {
        if (p->value == value) {
            return p->keyword;
        }   // end if
    }   // end for
    return NULL;
}   // end function: KeywordMap64_lookupByValue

uint64_t
KeywordMap64_lookupByCaseString(const KeywordMap64 *table, const char *keyword)
{
    const KeywordMap64 *p;
    for (p = table; NULL != p->keyword; ++p) {
        if (0 == strcasecmp(p->keyword, keyword)) {
            return p->value;
        }   // end if
    }   // end for
    return p->value;
}   // end function: KeywordMap64_lookupByCaseString

uint64_t
KeywordMap64_lookupByCaseStringSlice(const KeywordMap64 *table, const char *head, const char *tail)
{
    const KeywordMap64 *p;
    for (p = table; NULL != p->keyword; ++p) {
        if (0 == strncasecmp(p->keyword, head, tail - head) && '\0' == p->keyword[tail - head]) {
            return p->value;
        }   // end if
    }   // end for
    return p->value;
}   // end function: KeywordMap64_lookupByCaseStringSlice
