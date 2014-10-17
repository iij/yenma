/*
 * Copyright (c) 2006-2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __INET_MAIL_HEADERS_H__
#define __INET_MAIL_HEADERS_H__

#include <sys/types.h>
#include <stdbool.h>
#include "strpairarray.h"
#include "inetmailbox.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum HeaderStautus {
    HEADER_STAT_NULL = 0,
    HEADER_STAT_OK = 1,
    HEADER_NOT_EXIST,
    HEADER_NOT_UNIQUE,
    HEADER_BAD_SYNTAX,
    HEADER_NO_RESOURCE,
} HeaderStautus;

typedef struct InetMailHeaders InetMailHeaders;

extern InetMailHeaders *InetMailHeaders_new(size_t size);
extern void InetMailHeaders_reset(InetMailHeaders *self);
extern void InetMailHeaders_free(InetMailHeaders *self);
extern int InetMailHeaders_getNonEmptyHeaderIndex(const InetMailHeaders *self, const char *fieldname,
                                              bool *multiple);
extern HeaderStautus InetMailHeaders_extractAuthors(const InetMailHeaders *self, const InetMailboxArray **authors);
extern size_t InetMailHeaders_getCount(const InetMailHeaders *self);
extern void InetMailHeaders_get(const InetMailHeaders *self, size_t pos, const char **pkey, const char **pval);
extern int InetMailHeaders_append(InetMailHeaders *self, const char *key, const char *val);

// header field name of From header (as Author)
#ifndef FROMHEADER
#define FROMHEADER          "From"
#endif

#ifdef __cplusplus
}
#endif

#endif /* __INET_MAIL_HEADERS_H__ */
