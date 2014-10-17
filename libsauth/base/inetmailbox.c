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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <sys/types.h>

#include "ptrop.h"
#include "ptrarray.h"
#include "xskip.h"
#include "xparse.h"
#include "xbuffer.h"
#include "inetmailbox.h"

struct InetMailbox {
    char *localpart;
    char *domain;
    char buf[];
};

/**
 * create InetMailbox object
 * @return initialized InetMailbox object, or NULL if memory allocation failed.
 */
static InetMailbox *
InetMailbox_new(size_t buflen)
{
    InetMailbox *self = (InetMailbox *) malloc(sizeof(InetMailbox) + buflen);
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(InetMailbox));   // 0 で埋めるのは先頭部分だけで十分

    return self;
}   // end function: InetMailbox_new

/**
 * release InetMailbox object
 * @param self InetMailbox object to release
 */
void
InetMailbox_free(InetMailbox *self)
{
    free(self);
}   // end function: InetMailbox_free

const char *
InetMailbox_getLocalPart(const InetMailbox *self)
{
    return self->localpart;
}   // end function: InetMailbox_getLocalPart

const char *
InetMailbox_getDomain(const InetMailbox *self)
{
    return self->domain;
}   // end function: InetMailbox_getDomain

/*
 * いわゆる "<>" かどうかを調べる.
 */
bool
InetMailbox_isNullAddr(const InetMailbox *self)
{
    return (NULL != self->localpart) && ('\0' == *(self->localpart))
        && ('\0' == *(self->domain));
}   // end function: InetMailbox_isNullAddr

/*
 * @param errptr エラー情報を返す. メモリの確保に失敗した場合は NULL をセットする.
 *               parse に失敗した場合は失敗した位置へのポインタを返す.
 *
 * addr-spec = local-part "@" domain
 */
static InetMailbox *
InetMailbox_parse(const char *head, const char *tail, const char **nextp,
                  xparse_funcp xparse_localpart, bool require_localpart,
                  xparse_funcp xparse_domain, bool require_domain, const char **errptr)
{
    const char *p = head;

    XBuffer *xbuf = XBuffer_new(tail - head);
    if (NULL == xbuf) {
        SETDEREF(errptr, NULL);
        goto cleanup;
    }   // end if

    if (0 >= xparse_localpart(p, tail, &p, xbuf) && require_localpart) {
        SETDEREF(errptr, p);
        goto cleanup;
    }   // end if

    if (0 != XBuffer_status(xbuf)) {
        SETDEREF(errptr, NULL);
        goto cleanup;
    }   // end if

    size_t localpartlen = XBuffer_getSize(xbuf);
    if (0 > XBuffer_appendChar(xbuf, '\0')) {   // local-part と domain の区切りの NULL 文字
        SETDEREF(errptr, NULL);
        goto cleanup;
    }   // end if

    if (0 >= XSkip_char(p, tail, '@', &p)) {
        SETDEREF(errptr, p);
        goto cleanup;
    }   // end if

    if (0 >= xparse_domain(p, tail, &p, xbuf) && require_domain) {
        SETDEREF(errptr, p);
        goto cleanup;
    }   // end if

    if (0 != XBuffer_status(xbuf)) {
        SETDEREF(errptr, NULL);
        goto cleanup;
    }   // end if

    size_t xbuflen = XBuffer_getSize(xbuf);
    InetMailbox *self = InetMailbox_new(xbuflen + 1);   // 1 は NULL 文字の分
    if (NULL == self) {
        SETDEREF(errptr, NULL);
        goto cleanup;
    }   // end if

    memcpy(self->buf, XBuffer_getBytes(xbuf), xbuflen);
    self->buf[xbuflen] = '\0';
    self->localpart = self->buf;
    self->domain = self->buf + localpartlen + 1;

    XBuffer_free(xbuf);
    *nextp = p;
    SETDEREF(errptr, NULL);
    return self;

  cleanup:
    XBuffer_free(xbuf);
    *nextp = head;
    return NULL;
}   // end function: InetMailbox_parse

/*
 * @attention source route は取り扱わない.
 *
 * [RFC2821]
 * Reverse-path = Path
 * Forward-path = Path
 * Path = "<" [ A-d-l ":" ] Mailbox ">"
 * A-d-l = At-domain *( "," A-d-l )
 *       ; Note that this form, the so-called "source route",
 *       ; MUST BE accepted, SHOULD NOT be generated, and SHOULD be
 *       ; ignored.
 * At-domain = "@" domain
 * Mailbox = Local-part "@" Domain
 * Local-part = Dot-string / Quoted-string
 *       ; MAY be case-sensitive
 */
static InetMailbox *
InetMailbox_buildPathImpl(const char *head, const char *tail, const char **nextp, xparse_funcp xparse_localpart, xparse_funcp xparse_domain,
                              bool require_bracket, bool accept_null_addr, const char **errptr)
{
    if (accept_null_addr && 0 < XSkip_string(head, tail, "<>", nextp)) {
        SETDEREF(errptr, NULL);
        return InetMailbox_build("", "");
    }   // end if

    InetMailbox *self = NULL;
    bool have_bracket = false;

    const char *p = head;
    if (0 < XSkip_char(p, tail, '<', &p)) {
        have_bracket = true;
    } else {
        if (require_bracket) {
            SETDEREF(errptr, p);
            goto cleanup;
        }   // end if
    }   // end if

    self = InetMailbox_parse(p, tail, &p, xparse_localpart, true, xparse_domain, true, errptr);
    if (NULL == self) {
        goto cleanup;
    }   // end if

    if (have_bracket && 0 >= XSkip_char(p, tail, '>', &p)) {
        // "<" で始まっているのに対応する ">" が見つからなかった場合
        SETDEREF(errptr, p);
        goto cleanup;
    }   // end if

    *nextp = p;
    return self;

  cleanup:
    InetMailbox_free(self);
    *nextp = head;
    return NULL;
}   // end function: InetMailbox_buildPathImpl

/*
 * [RFC2822]
 * mailbox      = name-addr / addr-spec
 * mailbox-list = (mailbox *("," mailbox)) / obs-mbox-list
 * name-addr    = [display-name] angle-addr
 * angle-addr   = [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr
 * display-name = phrase
 * addr-spec    = local-part "@" domain
 */
InetMailbox *
InetMailbox_build2822Mailbox(const char *head, const char *tail, const char **nextp,
                             const char **errptr)
{
    bool guessNameaddr;         // mailbox = name-addr を想定している ('<' が見つかった) 場合に真

    // ABNF をまとめると
    // mailbox = ([phrase] [CFWS] "<" addr-spec ">" [CFWS]) / addr-spec
    // 判断基準は '<', '>' の存在だけ

    // display-name を捨てて addr-spec にたどり着くために
    // name-addr にマッチするか調べる
    const char *p = head;
    XSkip_phrase(p, tail, &p);  // display-name の実体
    XSkip_cfws(p, tail, &p);
    if (0 < XSkip_char(p, tail, '<', &p)) {
        // mailbox = name-addr
        guessNameaddr = true;
    } else {
        // mailbox = addr-spec
        p = head;
        guessNameaddr = false;
    }   // end if

    InetMailbox *self =
        InetMailbox_parse(p, tail, &p, XParse_2822LocalPart, true, XParse_2822Domain, true, errptr);
    if (NULL == self) {
        goto cleanup;
    }   // end if

    if (guessNameaddr) {
        // mailbox = name-addr なのに '>' が存在しない
        if (0 >= XSkip_char(p, tail, '>', &p)) {
            SETDEREF(errptr, p);
            goto cleanup;
        }   // end if
        XSkip_cfws(p, tail, &p);
    }   // end if

    *nextp = p;
    return self;

  cleanup:
    InetMailbox_free(self);
    *nextp = head;
    return NULL;
}   // end function: InetMailbox_build2822Mailbox

/*
 * @attention source route は取り扱わない.
 *
 * [RFC2821]
 * Mailbox = Local-part "@" Domain
 * Local-part = Dot-string / Quoted-string
 *       ; MAY be case-sensitive
 */
InetMailbox *
InetMailbox_build2821Mailbox(const char *head, const char *tail, const char **nextp,
                             const char **errptr)
{
    return InetMailbox_parse(head, tail, nextp, XParse_2821LocalPart, true, XParse_2821Domain, true, errptr);
}   // end function: InetMailbox_build2821Mailbox

InetMailbox *
InetMailbox_build2821Path(const char *head, const char *tail, const char **nextp,
                          const char **errptr)
{
    return InetMailbox_buildPathImpl(head, tail, nextp, XParse_2821LocalPart, XParse_2821Domain, true, false, errptr);
}   // end function: InetMailbox_build2821Path

/*
 * sendmail の envelope from/rcpt に "<", ">" なしのメールアドレスを受け付ける実装に対応しつつ InetMailbox オブジェクトを構築する.
 * "<>" は受け付けない.
 */
InetMailbox *
InetMailbox_buildSendmailPath(const char *head, const char *tail, const char **nextp,
                              const char **errptr)
{
    return InetMailbox_buildPathImpl(head, tail, nextp, XParse_2821LocalPart, XParse_2821Domain, false, false, errptr);
}   // end function: InetMailbox_buildSendmailPath

InetMailbox *
InetMailbox_buildSmtpPath(const char *head, const char *tail, const char **nextp,
                              const char **errptr)
{
    return InetMailbox_buildPathImpl(head, tail, nextp, XParse_smtpLocalPart, XParse_2821Domain, false, false, errptr);
}   // end function: InetMailbox_buildSmtpPath

/*
 * @attention 厳密には Reverse-path には "<>" は含まれない
 */
InetMailbox *
InetMailbox_build2821ReversePath(const char *head, const char *tail, const char **nextp,
                                 const char **errptr)
{
    return InetMailbox_buildPathImpl(head, tail, nextp, XParse_2821LocalPart, XParse_2821Domain, true, true, errptr);
}   // end function: InetMailbox_build2821ReversePath

/*
 * sendmail の envelope from/rcpt に "<", ">" なしのメールアドレスを受け付ける実装に対応しつつ InetMailbox オブジェクトを構築する.
 * "<>" を受け付ける.
 */
InetMailbox *
InetMailbox_buildSendmailReversePath(const char *head, const char *tail, const char **nextp,
                                     const char **errptr)
{
    return InetMailbox_buildPathImpl(head, tail, nextp, XParse_2821LocalPart, XParse_2821Domain, false, true, errptr);
}   // end function: InetMailbox_buildSendmailReversePath

InetMailbox *
InetMailbox_buildSmtpReversePath(const char *head, const char *tail, const char **nextp,
                                     const char **errptr)
{
    return InetMailbox_buildPathImpl(head, tail, nextp, XParse_smtpLocalPart, XParse_2821Domain, false, true, errptr);
}   // end function: InetMailbox_buildSmtpReversePath

/*
 * [RFC6376]
 * sig-i-tag       = %x69 [FWS] "=" [FWS] [ Local-part ]
 *                            "@" domain-name
 */
InetMailbox *
InetMailbox_buildDkimIdentity(const char *head, const char *tail, const char **nextp,
                              const char **errptr)
{
    return InetMailbox_parse(head, tail, nextp, XParse_2821LocalPart, false, XParse_domainName,
                             true, errptr);
}   // end function: InetMailbox_buildDkimIdentity


InetMailbox *
InetMailbox_buildWithLength(const char *localpart, size_t localpart_len, const char *domain,
                            size_t domain_len)
{
    assert(NULL != localpart);
    assert(NULL != domain);

    InetMailbox *self = InetMailbox_new(localpart_len + domain_len + 2);
    if (NULL == self) {
        return NULL;
    }   // end if

    memcpy(self->buf, localpart, localpart_len);
    self->buf[localpart_len] = '\0';
    memcpy(self->buf + localpart_len + 1, domain, domain_len);
    self->buf[localpart_len + 1 + domain_len] = '\0';
    self->localpart = self->buf;
    self->domain = self->buf + localpart_len + 1;

    return self;
}   // end function: InetMailbox_build

/**
 * local-part と domain を指定して InetMailbox オブジェクトを構築する
 * @param localpart local-part を指定する. NULL は許されない.
 * @param domain domain を指定する. NULL は許されない.
 * @return 構築した InetMailbox オブジェクト. 失敗した場合は NULL
 */
InetMailbox *
InetMailbox_build(const char *localpart, const char *domain)
{
    return InetMailbox_buildWithLength(localpart, strlen(localpart), domain, strlen(domain));
}   // end function: InetMailbox_build

/**
 * InetMailbox オブジェクトを複製する.
 * @param mailbox 複製したい InetMailbox オブジェクト.
 * @return 構築した InetMailbox オブジェクト. 失敗した場合は NULL.
 */
InetMailbox *
InetMailbox_duplicate(const InetMailbox *mailbox)
{
    assert(NULL != mailbox);
    return InetMailbox_build(mailbox->localpart, mailbox->domain);
}   // end function: InetMailbox_duplicate

/*
 * local-part + "@" + domain の長さを返す.
 */
size_t
InetMailbox_getRawAddrLength(const InetMailbox *self)
{
    assert(NULL != self);
    return strlen(self->localpart) + strlen(self->domain) + 1;  // 1 は '@' の分
}   // end function: InetMailbox_getRawAddrLength

/*
 * @return 成功した場合は 0, エラーが発生した場合はエラーコード
 */
int
InetMailbox_writeRawAddr(const InetMailbox *self, XBuffer *xbuf)
{
    assert(NULL != self);
    assert(NULL != xbuf);
    XBuffer_appendString(xbuf, self->localpart);
    XBuffer_appendChar(xbuf, '@');
    XBuffer_appendString(xbuf, self->domain);
    return XBuffer_status(xbuf);
}   // end function: InetMailbox_writeRawAddr

/*
 * localpart が dot-atom-text にマッチするかを調べる.
 * マッチしない場合は, ヘッダに書き出す際には localpart を DQUOTE で括る必要がある.
 */
bool
InetMailbox_isLocalPartQuoted(const InetMailbox *self)
{
    assert(NULL != self);
    assert(NULL != self->localpart);
    const char *nextp = NULL;
    const char *localparttail = STRTAIL(self->localpart);
    XSkip_looseDotAtomText(self->localpart, localparttail, &nextp);
    return nextp < localparttail;
}   // end function: InetMailbox_isLocalPartQuoted

/*
 * @attention "<>" は扱わない. "<>" も扱いたい場合は InetMailbox_writeMailbox() を使用のこと.
 */
int
InetMailbox_writeAddrSpec(const InetMailbox *self, XBuffer *xbuf)
// localpart に NULL, CR, LF は含まれないという前提
{
    assert(NULL != self);
    assert(NULL != xbuf);

    const char *localparttail = STRTAIL(self->localpart);
    bool quoted = InetMailbox_isLocalPartQuoted(self);

    if (quoted) {
        XBuffer_appendChar(xbuf, '"');
    }   // end if

    for (const char *p = self->localpart; p < localparttail; ++p) {
        switch (*p) {
        case '\r':
        case '\n':
            // quoted-pair にもならない, そもそも含まれていてはならない
            // abort();
            break;

        case ' ':
        case '"':
        case '\\':
        case '\t':
            // text にはマッチするが qtext にはマッチしない文字を quote する
            XBuffer_appendChar(xbuf, '\\');
            break;

        default:
            // do nothing
            break;
        }   // end switch
        XBuffer_appendChar(xbuf, *p);
    }   // end for

    if (quoted) {
        XBuffer_appendChar(xbuf, '"');
    }   // end if

    XBuffer_appendChar(xbuf, '@');
    XBuffer_appendString(xbuf, self->domain);
    return XBuffer_status(xbuf);
}   // end function: InetMailbox_writeAddrSpec

int
InetMailbox_writeMailbox(const InetMailbox *self, XBuffer *xbuf)
// localpart に NULL, CR, LF は含まれないという前提
{
    if (InetMailbox_isNullAddr(self)) {
        XBuffer_appendString(xbuf, "<>");
        return XBuffer_status(xbuf);
    } else {
        return InetMailbox_writeAddrSpec(self, xbuf);
    }   // end if
}   // end function: InetMailbox_writeMailbox

/**
 * allocate InetMailboxArray object
 * @return initialized InetMailboxArray object, or NULL if memory allocation failed.
 */
InetMailboxArray *
InetMailboxArray_new(size_t size)
{
    return PtrArray_new(size, (void (*)(void *)) InetMailbox_free);
}   // end function: InetMailboxArray_new

int
InetMailboxArray_set(InetMailboxArray *self, size_t pos, const InetMailbox *elem)
{
    InetMailbox *newelem = InetMailbox_duplicate(elem);
    if (NULL == newelem) {
        return -1;
    }   // end if
    int ret = PtrArray_set(self, pos, newelem);
    if (0 > ret) {
        InetMailbox_free(newelem);
    }   // end if
    return ret;
}   // end function: InetMailboxArray_set

int
InetMailboxArray_setWithoutCopy(InetMailboxArray *self, size_t pos, InetMailbox *elem)
{
    return PtrArray_set(self, pos, elem);
}   // end function: InetMailboxArray_setWithoutCopy

int
InetMailboxArray_append(InetMailboxArray *self, const InetMailbox *elem)
{
    return InetMailboxArray_set(self, InetMailboxArray_getCount(self), elem);
}   // end function: InetMailboxArray_append

int
InetMailboxArray_appendWithoutCopy(InetMailboxArray *self, InetMailbox *elem)
{
    return InetMailboxArray_setWithoutCopy(self, InetMailboxArray_getCount(self), elem);
}   // end function: InetMailboxArray_appendWithoutCopy

/*
 * [RFC2822]
 * mailbox-list = (mailbox *("," mailbox)) / obs-mbox-list
 */
InetMailboxArray *
InetMailboxArray_build2822MailboxList(const char *head, const char *tail, const char **nextp,
                                      const char **errptr)
{
    InetMailboxArray *self = InetMailboxArray_new(0);
    if (NULL == self) {
        SETDEREF(errptr, NULL);
        return NULL;
    }   // end if

    const char *p = head;
    while (true) {
        const char *mailbox_errptr = NULL;
        InetMailbox *mailbox = InetMailbox_build2822Mailbox(p, tail, &p, &mailbox_errptr);
        if (NULL == mailbox) {
            if (NULL != mailbox_errptr && 0 < InetMailboxArray_getCount(self)) {
                return self;
            } else {
                SETDEREF(errptr, mailbox_errptr);
                goto cleanup;
            }   // end if
        }   // end if
        if (0 > InetMailboxArray_appendWithoutCopy(self, mailbox)) {
            SETDEREF(errptr, NULL);
            goto cleanup;
        }   // end if
        *nextp = p;
        XSkip_fws(p, tail, &p); // out of spec
        if (0 >= XSkip_char(p, tail, ',', &p)) {
            return self;
        }   // end if
        XSkip_fws(p, tail, &p); // out of spec
    }   // end while

  cleanup:
    InetMailboxArray_free(self);
    return NULL;
}   // end function: InetMailboxArray_build2822MailboxList
