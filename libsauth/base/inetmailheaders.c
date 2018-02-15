/*
 * Copyright (c) 2006-2018 Internet Initiative Japan Inc. All rights reserved.
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
#include <sys/types.h>
#include <strings.h>

#include "ptrop.h"
#include "xskip.h"
#include "strpairarray.h"
#include "inetmailbox.h"
#include "inetmailheaders.h"

struct InetMailHeaders {
    StrPairArray *headers;
    HeaderStautus author_parse_stat;
    InetMailboxArray *authors;
};

void
InetMailHeaders_free(InetMailHeaders *self)
{
    if (NULL == self) {
        return;
    }   // end if

    StrPairArray_free(self->headers);
    InetMailboxArray_free(self->authors);
    free(self);
}   // end function: InetMailHeaders_free

/**
 * create InetMailHeaders object
 * @return initialized InetMailHeaders object, or NULL if memory allocation failed.
 */
InetMailHeaders *
InetMailHeaders_new(size_t size)
{
    InetMailHeaders *self = (InetMailHeaders *) malloc(sizeof(InetMailHeaders));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(InetMailHeaders));
    self->headers = StrPairArray_new(size);
    if (NULL == self->headers) {
        free(self);
        return NULL;
    }   // end if
    self->author_parse_stat = HEADER_STAT_NULL;
    return self;
}   // end function: InetMailHeaders_new

void
InetMailHeaders_reset(InetMailHeaders *self)
{
    StrPairArray_reset(self->headers);
    self->author_parse_stat = HEADER_STAT_NULL;
    InetMailboxArray_free(self->authors);
    self->authors = NULL;
}   // end function: InetMailHeaders_reset

size_t
InetMailHeaders_getCount(const InetMailHeaders *self)
{
    return StrPairArray_getCount(self->headers);
}   // end function: InetMailHeaders_getCount

void
InetMailHeaders_get(const InetMailHeaders *self, size_t pos, const char **pkey, const char **pval)
{
    return StrPairArray_get((self->headers), pos, pkey, pval);
}   // end function: InetMailHeaders_get

int
InetMailHeaders_append(InetMailHeaders *self, const char *key, const char *val)
{
    return StrPairArray_append(self->headers, key, val);
}   // end function: InetMailHeaders_append

/**
 * InetMailHeader オブジェクトから最初に fieldname にマッチするヘッダへのインデックスを返す.
 * @param multiple マッチするヘッダが複数存在することを示すフラグを受け取る変数へのポインタ.
 * @return fieldname に最初にマッチしたヘッダへのインデックス. 見つからなかった場合は -1.
 *
 */
static int
InetMailHeaders_getHeaderIndexImpl(const InetMailHeaders *self, const char *fieldname,
                                   bool ignore_empty_header, bool *multiple)
{
    int keyindex = -1;
    int headernum = InetMailHeaders_getCount(self);
    for (int i = 0; i < headernum; ++i) {
        const char *headerf, *headerv;
        InetMailHeaders_get(self, i, &headerf, &headerv);
        if (0 != strcasecmp(headerf, fieldname)) {
            continue;
        }   // end if

        // Header Field Name が一致した

        if (ignore_empty_header) {
            // Header Field Value が non-empty であることを確認する

            // [RFC4407 2.]
            // For the purposes of this algorithm, a header field is "non-empty" if
            // and only if it contains any non-whitespace characters.  Header fields
            // that are otherwise relevant but contain only whitespace are ignored
            // and treated as if they were not present.

            const char *nextp;
            const char *headerv_tail = STRTAIL(headerv);
            XSkip_fws(headerv, headerv_tail, &nextp);
            if (nextp == headerv_tail) {
                // empty header は無視する
                continue;
            }   // end if
        }   // end if

        if (0 <= keyindex) {
            // 2個目のヘッダが見つかった
            *multiple = true;
            return keyindex;
        }   // end if

        keyindex = i;
        // 他にもマッチするヘッダが存在しないか確かめるため, 検索は続行
    }   // end for

    *multiple = false;
    return keyindex;
}   // end function: InetMailHeaders_getHeaderIndexImpl

/**
 * InetMailHeader オブジェクトから最初に fieldname にマッチする空でないヘッダへのインデックスを返す.
 * @param multiple マッチするヘッダが複数存在することを示すフラグを受け取る変数へのポインタ.
 * @return fieldname に最初にマッチしたヘッダへのインデックス. 見つからなかった場合は -1.
 * TODO: ユニットテスト
 */
int
InetMailHeaders_getNonEmptyHeaderIndex(const InetMailHeaders *self, const char *fieldname,
                                       bool *multiple)
{
    assert(NULL != self);
    assert(NULL != fieldname);

    return InetMailHeaders_getHeaderIndexImpl(self, fieldname, true, multiple);
}   // end function: InetMailHeaders_getNonEmptyHeaderIndex

InetMailboxArray *
InetMailHeaders_parseMailboxList(const char *head, const char *tail, const char **errptr)
{
    const char *p = NULL;
    InetMailboxArray *authors = InetMailboxArray_build2822MailboxList(head, tail, &p, errptr);
    if (NULL == authors) {
        return NULL;
    }   // end if

    XSkip_fws(p, tail, &p); // ignore trailing FWS
    if (p == tail) {
        return authors;
    } else {
        *errptr = p;
        InetMailboxArray_free(authors);
        return NULL;
    }   // end if
}   // end function: InetMailHeaders_parseMailboxList

static void
InetMailHeaders_extractAuthorImpl(InetMailHeaders *self)
{
    bool multiple;
    int author_header_index =
        InetMailHeaders_getHeaderIndexImpl(self, FROMHEADER, false, &multiple);
    if (author_header_index < 0) {
        // No From: header is found.
        self->author_parse_stat = HEADER_NOT_EXIST;
        self->authors = NULL;
        return;
    } else if (multiple) {
        // Multiple "Author"-candidate headers are found. It must be unique.
        self->author_parse_stat = HEADER_NOT_UNIQUE;
        self->authors = NULL;
        return;
    }   // end if

    // An unique "Author" header is found.

    // Extracts "mailbox" by parsing the found "Author" header.
    const char *headerf, *headerv;
    const char *errptr = NULL;
    InetMailHeaders_get(self, author_header_index, &headerf, &headerv);
    self->authors = InetMailHeaders_parseMailboxList(headerv, STRTAIL(headerv), &errptr);
    if (NULL == self->authors) {
        if (NULL == errptr) {
            // memory allocation error
            self->author_parse_stat = HEADER_NO_RESOURCE;
        } else {
            // parse error
            self->author_parse_stat = HEADER_BAD_SYNTAX;
        }   // end if
        return;
    }   // end if
    self->author_parse_stat = HEADER_STAT_OK;
    return;
}   // end function: InetMailHeaders_extractAuthorImpl

/**
 * @param mailbox A pointer to a variable to receive the InetMailboxArray object
 *                build from the extracted "Author" (actually "From") header.
 *                NULL if the return value is not HEADER_STAT_OK.
 * @return HEADER_STAT_OK for success, otherwise status code that indicates error.
 * @error HEADER_NOT_EXIST No Author header is found
 * @error HEADER_NOT_UNIQUE multiple Author headers are found
 * @error HEADER_BAD_SYNTAX unable to parse Author header field value
 * @error HEADER_NO_RESOURCE memory allocation error
 */
HeaderStautus
InetMailHeaders_extractAuthors(const InetMailHeaders *self, const InetMailboxArray **authors)
{
    assert(NULL != self);
    assert(NULL != authors);

    /*
     * [RFC5617] 2.3.
     * An "Author Address" is an email address in the From: header field of
     * a message [RFC5322].  If the From: header field contains multiple
     * addresses, the message has multiple Author Addresses.
     */
    if (HEADER_STAT_NULL == self->author_parse_stat) {  // not cached
        InetMailHeaders_extractAuthorImpl((InetMailHeaders *) self);
    }   // end if
    *authors = self->authors;
    return self->author_parse_stat;
}   // end function: InetMailHeaders_extractAuthor
