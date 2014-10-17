/*
 * Copyright (c) 2013,2014 Internet Initiative Japan Inc. All rights reserved.
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

#include <stddef.h>
#include <limits.h>
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>

#include "radtree.h"
#include "pstring.h"
#include "loghandler.h"
#include "ptrop.h"
#include "xskip.h"
#include "dkim.h"
#include "dmarc.h"

typedef enum PublicSuffixRule {
    RULE_NULL = 0,
    RULE_EXCEPTION,
    RULE_WILDCARD,
    RULE_NORMAL,
} PublicSuffixRule;

struct PublicSuffix {
    struct radtree rt;
};

void
PublicSuffix_free(PublicSuffix *self)
{
    if (NULL == self) {
        return;
    }   // end if
    radix_tree_clear(&self->rt);
    free(self);
}   // end function: PublicSuffix_free

static void
strpdowncpy(char *dst, const char *src_head, const char *src_tail)
{
    for (const char *p = src_head; p < src_tail; ++dst, ++p) {
        *dst = (char) tolower(*p);
    }   // end for
}   // end function: strpdowncpy

static void
PublicSuffix_canonicalize(const char *domain, size_t domainlen, char *buf, size_t buflen,
                          size_t *resultlen)
{
    assert(domainlen <= buflen);
    const char *tailp = domain + domainlen;
    char *bufp = buf;
    // exclude the tailing dot
    if (domain < tailp && '.' == *(tailp - 1)) {
        --tailp;
    }   // end if
    const char *label_head = NULL;
    while (NULL != (label_head = strprchr(domain, tailp, '.'))) {
        strpdowncpy(bufp, label_head + 1, tailp);
        bufp += (tailp - label_head);
        *(bufp - 1) = '\0';
        tailp = label_head;
    }   // end while
    strpdowncpy(bufp, domain, tailp);
    *resultlen = bufp - buf + (tailp - domain);
}   // end function: PublicSuffix_canonicalize

static char *
rstrip(char *head, char *tail)
{
    char *p;
    for (p = tail - 1; head <= p && (IS_WSP(*p) || IS_CR(*p) || IS_LF(*p)); --p);
    *(p + 1) = '\0';
    return p + 1;
}   // end function: rstrip

DkimStatus
PublicSuffix_build(const char *filename, PublicSuffix **publicsuffix)
{
    PublicSuffix *self = (PublicSuffix *) malloc(sizeof(PublicSuffix));
    if (NULL == self) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    radix_tree_init(&self->rt);

    if (NULL == filename) {
        // return empty tree
        *publicsuffix = self;
        return DSTAT_OK;
    }   // end if

    FILE *fp = NULL;
    if (NULL == (fp = fopen(filename, "r"))) {
        LogError("failed to open file: filename=%s, errno=%s", filename, strerror(errno));
        return DSTAT_CFGERR_FILE_NOT_FOUND;
    }   // end if

    char buf[LINE_MAX];
    while (NULL != fgets(buf, sizeof(buf), fp)) {
        char *tail = STRTAIL(buf);
        char *p = buf;
        XSkip_wsp(p, tail, (const char **) &p); // as lstrip
        tail = rstrip(p, tail);

        if (p == tail || 0 < XSkip_string(p, tail, "//", (const char **) &p)) {
            // skip comments
            continue;
        }   // end if

        PublicSuffixRule rule = RULE_NULL;
        if (0 < XSkip_char(p, tail, '!', (const char **) &p)) {
            rule = RULE_EXCEPTION;
        } else if (0 < XSkip_string(p, tail, "*.", (const char **) &p)) {
            rule = RULE_WILDCARD;
        } else {
            rule = RULE_NORMAL;
        }   // end if

        // XXX How can we check the syntax of the rule?

        size_t domainlen = tail - p;
        char keybuf[domainlen];
        size_t keylen;
        PublicSuffix_canonicalize(p, domainlen, keybuf, sizeof(keybuf), &keylen);
        errno = 0;
        if (NULL == radix_insert(&self->rt, (uint8_t *) keybuf, keylen, (void *) rule)) {
            if (ENOMEM == errno) {
                (void) fclose(fp);
                LogNoResource();
                return DSTAT_SYSERR_NORESOURCE;
            } else {
                LogNotice
                    ("the inserting public suffix is already registered: filename=%s, domain=%.*s, type=%d",
                     filename, (int) domainlen, p, rule);
            }   // end if
        }   // end if
    }   // end while

    int ferrno = ferror(fp);
    if (0 != ferrno) {
        (void) fclose(fp);
        LogError("file read error: filename=%s, errno=%s", filename, strerror(ferrno));
        return DSTAT_SYSERR_IO_ERROR;
    }   // end if

    (void) fclose(fp);
    *publicsuffix = self;
    return DSTAT_OK;
}   // end function: PublicSuffix_build

static const char *
PublicSuffix_applyRule(const char *domain, size_t domainlen, size_t matchlen, PublicSuffixRule rule)
{
    const char *tailp = domain + domainlen;
    // exclude the tailing dot
    if (domain < tailp && '.' == *(tailp - 1)) {
        --tailp;
    }   // end if

    if (0 < matchlen) {
        tailp -= matchlen;
        if (tailp < domain || (domain < tailp && '.' != *(tailp - 1))) {
            // should not be here
            LogError("invalid matchlen: domain=%.*s, matchlen=%zu, rule=%d", (int) domainlen,
                     domain, matchlen, (int) rule);
            return NULL;
        }   // end if
    }   // end if

    int level;
    switch (rule) {
    case RULE_EXCEPTION:
        return tailp;
    case RULE_NORMAL:
        level = 1;
        break;
    case RULE_WILDCARD:
        level = 2;
        break;
    default:
        abort();
        break;
    }   // end switch

    if (0 == matchlen) {
        // This means no rules match and the prevailing rule is "*".
        // Normally tailp points the head of the matched label. But in this (0 == matchles) case,
        // tailp points the end of the previous label. So we adjust tailp.
        ++tailp;
    }   // end if

    for (int i = 0; i < level; ++i) {
        if (domain == tailp) {
            return NULL;
        }   // end if
        tailp = strprchr(domain, tailp - 1, '.');
        if (NULL != tailp) {
            ++tailp;
        } else {
            tailp = domain;
        }   // end if
    }   // end for

    return tailp;
}   // end function: PublicSuffix_applyRule

const char *
PublicSuffix_getOrganizationalDomain(const PublicSuffix *self, const char *domain)
{
    if (NULL == domain) {
        return NULL;
    }   // end if

    size_t domainlen = strlen(domain);
    char needle[domainlen];
    size_t needlelen;
    PublicSuffix_canonicalize(domain, domainlen, needle, sizeof(needle), &needlelen);
    char *needle_tail = needle + needlelen;
    struct radnode *n = NULL;
    while (NULL == (n = radix_search(&self->rt, (uint8_t *) needle, needle_tail - needle))) {
        needle_tail = (char *) strprchr(needle, needle_tail, '\0');
        if (NULL == needle_tail) {
            // If no rules match, the prevailing rule is "*".
            return PublicSuffix_applyRule(domain, domainlen, 0, (PublicSuffixRule) RULE_WILDCARD);
        }   // end if
    }   // end while

    return PublicSuffix_applyRule(domain, domainlen, needle_tail - needle,
                                  (PublicSuffixRule) n->elem);
}   // end function: PublicSuffix_getOrganizationalDomain
