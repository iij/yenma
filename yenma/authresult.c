/*
 * Copyright (c) 2007-2014 Internet Initiative Japan Inc. All rights reserved.
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

#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

#include "loghandler.h"
#include "ptrop.h"
#include "stdaux.h"
#include "xbuffer.h"
#include "foldstring.h"
#include "xskip.h"
#include "inetmailbox.h"
#include "authresult.h"

#define AUTHRES_WIDTH   78
#define AUTHRES_DEFAULT_BUFLEN 256

/*
 * [RFC5451] 2.2.
 * authres-header = "Authentication-Results:" [CFWS] authserv-id
 *          [ CFWS version ]
 *          ( [CFWS] ";" [CFWS] "none" / 1*resinfo ) [CFWS] CRLF
 * authserv-id = dot-atom
 * version = 1*DIGIT [CFWS]
 * resinfo = [CFWS] ";" methodspec [ CFWS reasonspec ]
 *           *( CFWS propspec )
 * methodspec = [CFWS] method [CFWS] "=" [CFWS] result
 * reasonspec = "reason" [CFWS] "=" [CFWS] value
 * propspec = ptype [CFWS] "." [CFWS] property [CFWS] "=" pvalue
 * method = dot-atom [ [CFWS] "/" [CFWS] version ]
 * result = dot-atom
 * ptype = "smtp" / "header" / "body" / "policy"
 * property = dot-atom
 * pvalue = [CFWS] ( value / [ [ local-part ] "@" ] domain-name )
 *          [CFWS]
 * [RFC5322] 3.2.4.
 * qtext           =   %d33 /             ; Printable US-ASCII
 *                    %d35-91 /          ;  characters not including
 *                    %d93-126 /         ;  "\" or the quote character
 *                    obs-qtext
 * qcontent        =   qtext / quoted-pair
 * quoted-string   =   [CFWS]
 *                    DQUOTE *([FWS] qcontent) [FWS] DQUOTE
 *                    [CFWS]
 * [RFC2045] 5.1.
 * token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
 *          or tspecials>
 */

const char *
AuthResult_getFieldName(void)
{
    return AUTHRESULTSHDR;
}   // end function: AuthResult_getFieldName

AuthResult *
AuthResult_new(void)
{
    AuthResult *self = FoldString_new(AUTHRES_WIDTH);
    if (NULL == self) {
        return NULL;
    }   // end if

    // 1 行あたり 78 byte を越えないように頑張る
    FoldString_setLineLengthLimits(self, AUTHRES_WIDTH);
    // folding の際に CR は使用しない
    FoldString_setFoldingCR(self, false);
    // "Authentication-Results: " の分のスペースを確保
    FoldString_consumeLineSpace(self, strlen(AUTHRESULTSHDR ": "));

    return self;
}   // end function: AuthResult_new

bool
AuthResult_appendAuthServId(AuthResult *self, const char *servid)
{
    // authserv-id
    return bool_cast(0 == FoldString_appendBlock(self, true, servid));
}   // end function: AuthResult_appendAuthServId

bool
AuthResult_appendMethodSpec(AuthResult *self, const char *method, const char *result)
{
    // methodspec
    (void) FoldString_appendChar(self, false, ';');
    (void) FoldString_appendFormatBlock(self, true, " %s=%s", method, result);
    return bool_cast(0 == FoldString_status(self));
}   // end function: AuthResult_appendMethodSpec

bool
AuthResult_appendReasonSpec(AuthResult *self, const char *reason)
{
    // check if "reason" needs to be quoted
    bool quoted_string = false;
    const char *p = '\0';
    for (p = reason; '\0' != *p; ++p) {
        if (!IS_MIMETOKEN(*p)) {
            quoted_string = true;
            break;
        }   // end if
    }   // end for

    // reasonspec
    (void) FoldString_appendBlock(self, true, " reason=");
    if (quoted_string) {
        (void) FoldString_appendChar(self, false, '\"');
        for (p = reason; '\0' != *p; ++p) {
            if (!IS_CHAR(*p)) {
                continue;
            }   // end if
            if (!IS_QTEXT(*p)) {
                // quoted-pair
                (void) FoldString_appendChar(self, false, '\\');
            }   // end if
            (void) FoldString_appendChar(self, false, *p);
        }   // end for
        (void) FoldString_appendChar(self, false, '\"');
    } else {
        (void) FoldString_appendBlock(self, true, reason);
    }   // end if
    return bool_cast(0 == FoldString_status(self));
}   // end function: AuthResult_appendReasonSpec

bool
AuthResult_appendComment(AuthResult *self, const char *comment)
{
    return bool_cast(0 == FoldString_appendFormatBlock(self, true, " (%s)", comment));
}   // end function: AuthResult_appendComment

bool
AuthResult_appendComments(AuthResult *self, ...)
{
    va_list ap;
    va_start(ap, self);
    (void) FoldString_appendBlock(self, true, " (");
    const char *comment = NULL;
    bool comma = false;
    while (NULL != (comment = va_arg(ap, const char *))) {
        if (comma) {
            FoldString_appendBlock(self, true, ", ");
        }   // end if
        FoldString_appendBlock(self, true, comment);
        comma = true;
    }   // end while
    (void) FoldString_appendChar(self, false, ')');
    va_end(ap);
    return bool_cast(0 == FoldString_status(self));
}   // end function: AuthResult_appendComments

bool
AuthResult_appendPropSpecWithToken(AuthResult *self, const char *ptype, const char *property,
                                   const char *value)
{
    // propspec
    return bool_cast(0 == FoldString_appendFormatBlock(self, true, " %s.%s=%s", ptype, property, value));
}   // end function: AuthResult_appendPropSpecWithToken

bool
AuthResult_appendPropSpecWithAddrSpec(AuthResult *self, const char *ptype, const char *property,
                                      const InetMailbox *mailbox)
{
    assert(NULL != mailbox);

    XBuffer *buf = XBuffer_new(AUTHRES_DEFAULT_BUFLEN);
    if (NULL == buf) {
        return false;
    }   // end if
    int write_stat = InetMailbox_writeMailbox(mailbox, buf);
    if (0 != write_stat) {
        goto cleanup;
    }   // end if

    bool append_stat =
        AuthResult_appendPropSpecWithToken(self, ptype, property, XBuffer_getString(buf));
    XBuffer_free(buf);
    return append_stat;

  cleanup:
    XBuffer_free(buf);
    return false;
}   // end function: AuthResult_appendPropSpecWithMailbox

/**
 * Authentication-Results ヘッダのフィールド値に含まれる authserv-id が servid に一致するか調べる.
 * @param field Authentication-Results ヘッダの値部分
 * @param servid 削除対象の条件とするホスト名
 * @return ホスト名が一致した場合は真, 一致しなかった場合は偽
 */
bool
AuthResult_compareAuthservId(const char *field, const char *servid)
{
    // Authentication-Results 全体の終端
    const char *field_tail = STRTAIL(field);

    // Authentication-Results ヘッダから authserv-id を抜き出す
    const char *servid_head, *servid_tail;
    (void) XSkip_cfws(field, field_tail, &servid_head);
    if (0 >= XSkip_dotAtomText(servid_head, field_tail, &servid_tail)) {
        // authserv-id が dot-atom-text ではない
        LogDebug("authserv-id doesn't seem to be dot-atom-text: field=%s", field);
        return false;
    }   // end if

    // dot-atom-text の後で単語が切れていることを確認する.
    // 古い Authentication-Results のヘッダの仕様では authserv_id の後は CFWS だったので,
    // authserv_id の後に CFWS がある場合は ';' がなくても authserv_id であると見なす.
    const char *tail;
    if (servid_tail == field_tail || 0 < XSkip_cfws(servid_tail, field_tail, &tail)
        || 0 < XSkip_char(tail, field_tail, ';', &tail)) {
        // Authentication-Results ヘッダから抜き出した authserv-id と servid を比較する.
        const char *nextp;
        XSkip_casestring(servid_head, servid_tail, servid, &nextp);
        return bool_cast(servid_tail == nextp);
    }   // end if

    LogDebug("authserv-id doesn't seem to be dot-atom-text: field=%s", field);
    return false;
}   // end function: AuthResult_compareAuthservId
