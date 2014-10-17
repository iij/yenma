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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <stdbool.h>

#include "loghandler.h"
#include "dkimlogger.h"
#include "xskip.h"
#include "ptrop.h"
#include "dkim.h"
#include "dkimenum.h"
#include "dkimcanonicalizer.h"

struct DkimCanonicalizer {
    unsigned char *buf;
    size_t canonlen;            // size of content stored at "buf"
    size_t capacity;            // memory size assigned to "buf"

    unsigned int body_crlf_count;
    unsigned int body_wsp_count;    // this field is used only for "relaxed" body canonicalization
    unsigned char body_last_char;

    unsigned long total_body_input_len;
    unsigned long total_body_canonicalized_output_len;

    DkimC14nAlgorithm headeralg;
    DkimC14nAlgorithm bodyalg;

    DkimStatus (*canonHeader) (DkimCanonicalizer *, const char *, const char *, bool, bool);
    DkimStatus (*canonBody) (DkimCanonicalizer *, const unsigned char *, size_t);
};

/**
 * count the number of charactor 'c' in 's'
 */
static size_t
strccount(const char *s, char c)
{
    int n = 0;
    for (; '\0' != *s; ++s) {
        if (*s == c) {
            ++n;
        }   // end if
    }   // end for
    return n;
}   // end function: strccount

/**
 * reset state of DkimCanonicalizer object.
 * allocated memory and canonicalization algorithm are maintained.
 * @param self DkimCanonicalizer object to be reset
 */
void
DkimCanonicalizer_reset(DkimCanonicalizer *self)
{
    assert(self);
    self->canonlen = 0;
    self->body_crlf_count = 0;
    self->body_wsp_count = 0;
    self->body_last_char = '\0';
    self->total_body_input_len = 0;
    self->total_body_canonicalized_output_len = 0;
}   // end function: DkimCanonicalizer_reset

/**
 * extend internal buffer to specified size.
 * no action occurs if buffer size is larger than specified.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
static DkimStatus
DkimCanonicalizer_assureBuffer(DkimCanonicalizer *self, size_t newsize)
{
    if (self->capacity < newsize) {
        unsigned char *newbuf = (unsigned char *) realloc(self->buf, newsize);
        if (NULL == newbuf) {
            self->capacity = 0;
            LogNoResource();
            return DSTAT_SYSERR_NORESOURCE;
        }   // end if
        self->buf = newbuf;
        self->capacity = newsize;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimCanonicalizer_assureBuffer

/**
 * canonicalize a header with "simple" algorithm.
 * @param headerf header field name
 * @param headerv header field value
 * @param append_crlf true to append CRLF to the tail of header field value after canonicalization, false to append nothing.
 * @param keep_leading_header_space true to keep a space character at the head of header field value
 *                                      (useful for libmilter supplied with sendmail 8.12 or 8.13),
 *                                      false to keep nothing.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 */
static DkimStatus
DkimCanonicalizer_headerWithSimple(DkimCanonicalizer *self, const char *headerf,
                                   const char *headerv, bool append_crlf,
                                   bool keep_leading_header_space)
{
    /*
     * [RFC6376] 3.4.1.
     * The "simple" header canonicalization algorithm does not change header
     * fields in any way.  Header fields MUST be presented to the signing or
     * verification algorithm exactly as they are in the message being
     * signed or verified.  In particular, header field names MUST NOT be
     * case folded and whitespace MUST NOT be changed.
     */

    // memory allocation
    // 5 bytes for ": ", trailing CRLF and NULL terminator.
    size_t buflen = strlen(headerf) + strlen(headerv) + strccount(headerv, '\n') + 5;
    DkimStatus assure_stat = DkimCanonicalizer_assureBuffer(self, buflen);
    if (DSTAT_OK != assure_stat) {
        self->canonlen = 0;
        return assure_stat;
    }   // end if

    // write out header field name without any modifications
    size_t headerflen = 0;
    if (keep_leading_header_space) {
        // sendmail 8.14 or higher with SMFIP_HDR_LEADSPC
        headerflen = snprintf((char *) self->buf, self->capacity, "%s:", headerf);
    } else {
        // otherwise
        headerflen = snprintf((char *) self->buf, self->capacity, "%s: ", headerf);
    }   // end if
    if (self->capacity <= headerflen) {
        self->canonlen = 0;
        DkimLogImplError("temporary buffer too small");
        return DSTAT_SYSERR_IMPLERROR;
    }   // end if

    // write out header field value.
    // replace line terminator with CRLF if LF is used for it.
    const char *p;
    unsigned char *q;
    char last = '\0';
    for (p = headerv, q = self->buf + headerflen; *p != '\0'; ++p) {
        if (*p == '\n' && last != '\r') {
            // replace LF with CRLF
            *(q++) = '\r';
        }   // end if
        *(q++) = *p;
        last = *p;
    }   // end for

    if (append_crlf) {
        *(q++) = '\r';
        *(q++) = '\n';
    }   // end if
    *q = '\0';

    assert(q <= self->buf + buflen);
    self->canonlen = q - self->buf;

    return DSTAT_OK;
}   // end function: DkimCanonicalizer_headerWithSimple

/**
 * canonicalize a header with "relaxed" algorithm.
 * @param headerf header field name
 * @param headerv header field value
 * @param append_crlf true to append CRLF to the tail of header field value after canonicalization, false to append nothing.
 * @param keep_leading_header_space true to keep space character(s) at the head of header field value
 *                                      (useful for libmilter supplied with sendmail 8.12 or 8.13),
 *                                      false to keep nothing.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 */
static DkimStatus
DkimCanonicalizer_headerWithRelaxed(DkimCanonicalizer *self, const char *headerf,
                                    const char *headerv, bool append_crlf,
                                    bool keep_leading_header_space __attribute__((unused)))
{
    /*
     * [RFC6376] 3.4.2.
     * The "relaxed" header canonicalization algorithm MUST apply the
     * following steps in order:
     *
     * o  Convert all header field names (not the header field values) to
     *    lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".
     *
     * o  Unfold all header field continuation lines as described in
     *    [RFC5322]; in particular, lines with terminators embedded in
     *    continued header field values (that is, CRLF sequences followed by
     *    WSP) MUST be interpreted without the CRLF.  Implementations MUST
     *    NOT remove the CRLF at the end of the header field value.
     *
     * o  Convert all sequences of one or more WSP characters to a single SP
     *    character.  WSP characters here include those before and after a
     *    line folding boundary.
     *
     * o  Delete all WSP characters at the end of each unfolded header field
     *    value.
     *
     * o  Delete any WSP characters remaining before and after the colon
     *    separating the header field name from the header field value.  The
     *    colon separator MUST be retained.
     */

    // memory allocation
    // 4 bytes for ":", trailing CRLF and NULL terminator.
    size_t buflen = strlen(headerf) + strlen(headerv) + 4;
    DkimStatus assure_stat = DkimCanonicalizer_assureBuffer(self, buflen);
    if (DSTAT_OK != assure_stat) {
        self->canonlen = 0;
        return assure_stat;
    }   // end if

    // write out header field name.
    const char *p;
    unsigned char *q;
    bool store_wsp = false;
    for (p = headerf, q = self->buf; *p != '\0'; ++p) {
        if (IS_WSP(*p)) {
            // WSP should not be included in header field name actually.
            store_wsp = true;
        } else {
            if (store_wsp) {
                *(q++) = 0x20;  // skip this line for "nowsp" canonicalization
                store_wsp = false;
            }   // end if
            *(q++) = tolower(*p);
        }   // end if
    }   // end for
    // Discard WSP characters remaining before the colon separating the header field name
    // from the header field value.
    *(q++) = ':';

    // Discard WSP characters remaining after the colon separating the header field name
    // from the header field value.
    for (p = headerv; IS_WSP(*p); ++p);

    // write out header field value.
    store_wsp = false;
    for (; *p != '\0'; ++p) {
        if (*p == '\r' || *p == '\n') {
            // header の場合 folding 以外の CR/LF は存在しないはずなので読み飛ばす
        } else if (IS_WSP(*p)) {
            store_wsp = true;
        } else {
            if (store_wsp) {
                // replace a sequence of WSP with single SP
                *(q++) = 0x20;  // skip this line for "nowsp" canonicalization
                store_wsp = false;
            }   // end if
            *(q++) = *p;
        }   // end if
    }   // end for

    if (append_crlf) {
        *(q++) = '\r';
        *(q++) = '\n';
    }   // end if
    *q = '\0';

    assert(q <= self->buf + buflen);
    self->canonlen = q - self->buf;

    return DSTAT_OK;
}   // end function: DkimCanonicalizer_headerWithRelaxed

/**
 * canonicalize a header
 * @param headerf header field name
 * @param headerv header field value
 * @param append_crlf true to append CRLF to the tail of header field value after canonicalization, false to append nothing.
 * @param keep_leading_header_space true to keep a space character at the head of header field value
 *                                      (useful for libmilter supplied with sendmail 8.12 or 8.13),
 *                                      false to keep nothing.
 * @param canonbuf a pointer to a variable to receive the canonicalized message body chunk.
 *                 buffer is allocated inside the DkimCanonicalizer object
 *                 and is available until next operation to the DkimCanonicalizer object.
 * @param canonsize a pointer to a variable to receive the length of canonicalized message body chunk
 * @note headerf, headerv は milter から渡されたものをそのまま渡すといいようになっている.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 */
DkimStatus
DkimCanonicalizer_header(DkimCanonicalizer *self, const char *headerf, const char *headerv,
                         bool append_crlf, bool keep_leading_header_space,
                         const unsigned char **canonbuf, size_t *canonsize)
{
    DkimStatus canon_stat =
        self->canonHeader(self, headerf, headerv, append_crlf, keep_leading_header_space);

    if (DSTAT_OK == canon_stat) {
        SETDEREF(canonbuf, self->buf);
        SETDEREF(canonsize, self->canonlen);
    }   // end if

    return canon_stat;
}   // end function: DkimCanonicalizer_header

/**
 * canonicalize a DKIM-Signature header
 * @param headerf header field name
 * @param headerv header field value
 * @param keep_leading_header_space true to keep a space character at the head of header field value
 * @param b_tag_value_head
 * @param b_tag_value_tail
 * @param canonbuf a pointer to a variable to receive the canonicalized message body chunk.
 *                 buffer is allocated inside the DkimCanonicalizer object
 *                 and is available until next operation to the DkimCanonicalizer object.
 * @param canonsize a pointer to a variable to receive the length of canonicalized message body chunk
 * @attention DKIM-Signature ヘッダの正当性についての検証はおこなわず，
 *            正当な DKIM-Signature であるとして処理をおこなう
 * @note headerf, headerv は milter から渡されたものをそのまま渡すといいようになっている.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 */
DkimStatus
DkimCanonicalizer_signheader(DkimCanonicalizer *self, const char *headerf, const char *headerv,
                             bool keep_leading_header_space, const char *b_tag_value_head,
                             const char *b_tag_value_tail, const unsigned char **canonbuf,
                             size_t *canonsize)
{
    assert(b_tag_value_head != NULL);
    assert(b_tag_value_tail != NULL);

    const char *sign_tail = headerv + strlen(headerv);
    char *buf = (char *) malloc(sign_tail - headerv + 1);
    if (NULL == buf) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    /*
     * copy except the value of the sig-b-tag
     *
     * [RFC6376] 3.5.
     * The DKIM-Signature header field being created or verified is always
     * included in the signature calculation, after the rest of the header
     * fields being signed; however, when calculating or verifying the
     * signature, the value of the "b=" tag (signature value) of that DKIM-
     * Signature header field MUST be treated as though it were an empty
     * string.
     *
     * [RFC6376] 3.7.
     * 2.  The DKIM-Signature header field that exists (verifying) or will
     *     be inserted (signing) in the message, with the value of the "b="
     *     tag (including all surrounding whitespace) deleted (i.e., treated
     *     as the empty string), canonicalized using the header
     *     canonicalization algorithm specified in the "c=" tag, and without
     *     a trailing CRLF.
     */

    // copy until just before sig-b-tag
    char *q = buf;
    size_t len = b_tag_value_head - headerv;
    memcpy(q, headerv, len);
    q += len;

    // copy rest of the signature including NULL terminator,
    // supposing that only one sig-b-tag exists in the signature.
    len = sign_tail - b_tag_value_tail + 1;
    memcpy(q, b_tag_value_tail, len);

    // DKIM-Signature ヘッダの末尾には CRLF を付加しない.
    DkimStatus canon_stat =
        DkimCanonicalizer_header(self, headerf, buf, false, keep_leading_header_space, canonbuf,
                                 canonsize);

    free(buf);
    return canon_stat;
}   // end function: DkimCanonicalizer_signheader

/// flushes saved CRLF(s)
#define FLUSH_CRLF(__writep, __crlfnum) \
    do { \
        if (0 < (__crlfnum)) { \
            for (unsigned int __i = 0; __i < (__crlfnum); ++__i) { \
                *((__writep)++) = '\r'; \
                *((__writep)++) = '\n'; \
            } \
            (__crlfnum) = 0; \
        } \
    } while (0)

/// saves CRLF
#define CATCH_CRLF(__prevchar, __readp, __writep, __crlfnum) \
    do { \
        if ((__prevchar) == '\n') { \
            ++(__crlfnum); \
            ++(__readp); \
        } else { \
            FLUSH_CRLF(__writep, __crlfnum); \
            *((__writep)++) = '\r'; \
        } \
    } while (0)

/**
 * canonicalize message body chunk with "simple" algorithm.
 * @param bodyp message body chunk to canonicalize
 * @param bodylen length of "bodyp"
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
static DkimStatus
DkimCanonicalizer_bodyWithSimple(DkimCanonicalizer *self, const unsigned char *bodyp,
                                 size_t bodylen)
{
    /*
     * [RFC6376] 3.4.3.
     * The "simple" body canonicalization algorithm ignores all empty lines
     * at the end of the message body.  An empty line is a line of zero
     * length after removal of the line terminator.  If there is no body or
     * no trailing CRLF on the message body, a CRLF is added.  It makes no
     * other changes to the message body.  In more formal terms, the
     * "simple" body canonicalization algorithm converts "*CRLF" at the end
     * of the body to a single "CRLF".
     *
     * Note that a completely empty or missing body is canonicalized as a
     * single "CRLF"; that is, the canonicalized length will be 2 octets.
     */

    // 溜め込んでいる CRLF, CR だけ溜め込んでいる場合に備えた 1, 末尾の NULL に 1
    size_t buflen = bodylen + self->body_crlf_count * 2 + 2;
    DkimStatus assure_stat = DkimCanonicalizer_assureBuffer(self, buflen);
    if (DSTAT_OK != assure_stat) {
        self->canonlen = 0;
        return assure_stat;
    }   // end if

    // initialize pointers
    const unsigned char *p = bodyp;
    unsigned char *q = self->buf;
    const unsigned char *tail = bodyp + bodylen;

    // 前回の body の最後の文字が CR だった場合
    if (self->body_last_char == '\r') {
        CATCH_CRLF(*p, p, q, self->body_crlf_count);
    }   // end if

    for (; p < tail; ++p) {
        if (*p == '\r') {
            if (tail <= p + 1) {
                break;
            }   // end if
            CATCH_CRLF(*(p + 1), p, q, self->body_crlf_count);
        } else {
            FLUSH_CRLF(q, self->body_crlf_count);
            *(q++) = *p;
        }   // end if
    }   // end for
    *q = '\0';

    assert(q <= self->buf + buflen);
    self->canonlen = q - self->buf;
    self->body_last_char = *(tail - 1); // bodylen が 1 以上であることを確認しているので問題ない
    self->total_body_input_len += bodylen;
    self->total_body_canonicalized_output_len += self->canonlen;

    return DSTAT_OK;
}   // end function: DkimCanonicalizer_bodyWithSimple

/// flushes saved CRLF(s) and WSP
#define FLUSH_CRLFWSP(__writep, __crlfnum, __wspnum) \
    do { \
        if (0 < (__crlfnum)) { \
            for (unsigned int __i = 0; __i < (__crlfnum); ++__i) { \
                *((__writep)++) = '\r'; \
                *((__writep)++) = '\n'; \
            } \
            (__crlfnum) = 0; \
        } \
        if (0 < (__wspnum)) { \
            *((__writep)++) = ' '; /* skip this line for "nowsp" canonicalization */ \
            (__wspnum) = 0; \
        } \
    } while (0)

/// saves CRLF
#define CATCH_CRLFWSP(__prevchar, __readp, __writep, __crlfnum, __wspnum) \
    do { \
        if ((__prevchar) == '\n') { \
            ++(__crlfnum); \
            (__wspnum) = 0; \
            ++(__readp); \
        } else { \
            FLUSH_CRLFWSP(__writep, __crlfnum, __wspnum); \
            *((__writep)++) = '\r'; \
        } \
    } while (0)

/**
 * canonicalize message body chunk with "relaxed" algorithm.
 * @param bodyp message body chunk to canonicalize
 * @param bodylen length of "bodyp"
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
static DkimStatus
DkimCanonicalizer_bodyWithRelaxed(DkimCanonicalizer *self, const unsigned char *bodyp,
                                  size_t bodylen)
{
    /*
     * [RFC6376] 3.4.4.
     * The "relaxed" body canonicalization algorithm MUST apply the
     * following steps (a) and (b) in order:
     *
     * a.  Reduce whitespace:
     *
     *     *  Ignore all whitespace at the end of lines.  Implementations
     *        MUST NOT remove the CRLF at the end of the line.
     *
     *     *  Reduce all sequences of WSP within a line to a single SP
     *        character.
     *
     * b.  Ignore all empty lines at the end of the message body.  "Empty
     *     line" is defined in Section 3.4.3.  If the body is non-empty but
     *     does not end with a CRLF, a CRLF is added.  (For email, this is
     *     only possible when using extensions to SMTP or non-SMTP transport
     *     mechanisms.)
     */

    // 溜め込んでいる CRLF, CR だけ溜め込んでいる場合に備えた 1,
    // WSP だけ溜め込んでいる場合に備えた 1, 末尾の NULL に 1
    size_t buflen = bodylen + self->body_crlf_count * 2 + 3;
    DkimStatus assure_stat = DkimCanonicalizer_assureBuffer(self, buflen);
    if (DSTAT_OK != assure_stat) {
        self->canonlen = 0;
        return assure_stat;
    }   // end if

    // initialize pointers
    const unsigned char *p = bodyp;
    unsigned char *q = self->buf;
    const unsigned char *tail = bodyp + bodylen;

    // 前回の body の最後の文字が CR だった場合
    if (self->body_last_char == '\r') {
        CATCH_CRLFWSP(*p, p, q, self->body_crlf_count, self->body_wsp_count);
    }   // end if

    for (; p < tail; ++p) {
        if (IS_WSP(*p)) {
            self->body_wsp_count = 1;
        } else if (*p == '\r') {
            if (tail <= p + 1) {
                break;
            }   // end if
            CATCH_CRLFWSP(*(p + 1), p, q, self->body_crlf_count, self->body_wsp_count);
        } else {
            FLUSH_CRLFWSP(q, self->body_crlf_count, self->body_wsp_count);
            *(q++) = *p;
        }   // end if
    }   // end for
    *q = '\0';

    assert(q <= self->buf + buflen);
    self->canonlen = q - self->buf;
    self->body_last_char = *(tail - 1); // bodylen が 1 以上であることを確認しているので問題ない
    self->total_body_input_len += bodylen;
    self->total_body_canonicalized_output_len += self->canonlen;

    return DSTAT_OK;
}   // end function: DkimCanonicalizer_bodyWithRelaxed

/**
 * canonicalize message body chunk
 * @param bodyp message body chunk to canonicalize
 * @param bodylen length of "bodyp"
 * @param canonbuf a pointer to a variable to receive the canonicalized message body chunk.
 *                 buffer is allocated inside the DkimCanonicalizer object
 *                 and is available until next operation to the DkimCanonicalizer object.
 * @param canonsize a pointer to a variable to receive the length of canonicalized message body chunk
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimCanonicalizer_body(DkimCanonicalizer *self, const unsigned char *bodyp, size_t bodylen,
                       const unsigned char **canonbuf, size_t *canonsize)
{
    if (bodylen == 0) {
        DkimStatus assure_stat = DkimCanonicalizer_assureBuffer(self, 1);
        if (DSTAT_OK != assure_stat) {
            self->canonlen = 0;
            return assure_stat;
        }   // end if
        self->buf[0] = '\0';
        SETDEREF(canonbuf, self->buf);
        SETDEREF(canonsize, 0);
        return DSTAT_OK;
    }   // end if

    DkimStatus canon_stat = self->canonBody(self, bodyp, bodylen);

    if (canon_stat == DSTAT_OK) {
        SETDEREF(canonbuf, self->buf);
        SETDEREF(canonsize, self->canonlen);
    }   // end if

    return canon_stat;
}   // end function: DkimCanonicalizer_body

/**
 * メッセージ本文に対する canonicalization を終了する.
 * 溜め込んでいた空白や改行を必要に応じてはき出す.
 * @param canonbuf canonicalization 済みの文字列を受け取るポインタ.
 *                 バッファは DkimCanonicalizer オブジェクト内部に確保され,
 *                 次に DkimCanonicalizer オブジェクトに対して操作をおこなうまで有効.
 * @param canonsize canonbuf が保持するデータのサイズを受け取る変数へのポインタ
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimCanonicalizer_finalizeBody(DkimCanonicalizer *self, const unsigned char **canonbuf,
                               size_t *canonsize)
{
    // 溜め込んでいる CRLF/WSP, CR だけ溜め込んでいる場合に備えた 1, 末尾の NULL に 1
    size_t buflen = (self->body_crlf_count + 1) * 2 + self->body_wsp_count + 2;
    DkimStatus assure_stat = DkimCanonicalizer_assureBuffer(self, buflen);
    if (DSTAT_OK != assure_stat) {
        self->canonlen = 0;
        return assure_stat;
    }   // end if

    unsigned char *q = self->buf;
    if (self->body_last_char == '\r') { // if a CR is saved
        switch (self->bodyalg) {
        case DKIM_C14N_ALGORITHM_SIMPLE:
            FLUSH_CRLF(q, self->body_crlf_count);
            break;
        case DKIM_C14N_ALGORITHM_RELAXED:
            FLUSH_CRLFWSP(q, self->body_crlf_count, self->body_wsp_count);
            break;
        default:
            abort();
        }   // end switch
        *(q++) = '\r';
    }   // end if

    /*
     * [RFC6376] 3.4.3.
     * Note that a completely empty or missing body is canonicalized as a
     * single "CRLF"; that is, the canonicalized length will be 2 octets.
     * [RFC6376] 3.4.4.
     * If the body is non-empty but does not end with a CRLF, a CRLF is added.
     */
    if ((DKIM_C14N_ALGORITHM_SIMPLE == self->bodyalg
         && (0 == self->total_body_input_len || 0 < self->body_crlf_count))
        || (DKIM_C14N_ALGORITHM_RELAXED == self->bodyalg
            && 0 < self->total_body_canonicalized_output_len)) {
        /*
         * "simple" canonicalization: consecutive CRLFs or completely empty message body are replaced with a single CRLF.
         * "relaxed" canonicalization: appends single CRLF regardless of the number of CRLF saved unless message body is empty.
         */
        *(q++) = '\r';
        *(q++) = '\n';
    }   // end if
    // この時点で溜め込まれている WSP は必ず行末のものなので, 無視すればよい

    assert(q <= self->buf + buflen);
    self->canonlen = q - self->buf;
    self->total_body_canonicalized_output_len += self->canonlen;
    *q = '\0';
    self->body_crlf_count = 0;
    self->body_wsp_count = 0;
    self->body_last_char = '\0';

    SETDEREF(canonbuf, self->buf);
    SETDEREF(canonsize, self->canonlen);

    return DSTAT_OK;
}   // end function: DkimCanonicalizer_finalizeBody

/**
 * create DkimCanonicalizer object
 * @param headeralg canonicalization algorithm for message headers
 * @param bodyalg canonicalization algorithm for message body
 * @param dstat a pointer to a variable to receive the status code if an error occurred.
 *              possible value of status codes are listed with error tags below.
 * @return initialized DkimCanonicalizer object, or NULL if memory allocation failed.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_PERMFAIL_UNSUPPORTED_C14N_ALGORITHM unsupported canonicalization algorithm
 */
DkimStatus
DkimCanonicalizer_new(DkimC14nAlgorithm headeralg,
                      DkimC14nAlgorithm bodyalg, DkimCanonicalizer **canon)
{
    DkimCanonicalizer *self = (DkimCanonicalizer *) malloc(sizeof(DkimCanonicalizer));
    if (NULL == self) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    memset(self, 0, sizeof(DkimCanonicalizer));

    switch (headeralg) {
    case DKIM_C14N_ALGORITHM_SIMPLE:
        self->canonHeader = DkimCanonicalizer_headerWithSimple;
        break;
    case DKIM_C14N_ALGORITHM_RELAXED:
        self->canonHeader = DkimCanonicalizer_headerWithRelaxed;
        break;
    default:
        DkimLogPermFail("unsupported header canonicalization method specified: headercanon=0x%x",
                        headeralg);
        DkimCanonicalizer_free(self);
        return DSTAT_PERMFAIL_UNSUPPORTED_C14N_ALGORITHM;
    }   // end switch

    switch (bodyalg) {
    case DKIM_C14N_ALGORITHM_SIMPLE:
        self->canonBody = DkimCanonicalizer_bodyWithSimple;
        break;
    case DKIM_C14N_ALGORITHM_RELAXED:
        self->canonBody = DkimCanonicalizer_bodyWithRelaxed;
        break;
    default:
        DkimLogPermFail("unsupported body canonicalization method specified: bodycanon=0x%x",
                        bodyalg);
        DkimCanonicalizer_free(self);
        return DSTAT_PERMFAIL_UNSUPPORTED_C14N_ALGORITHM;
    }   // end switch

    self->headeralg = headeralg;
    self->bodyalg = bodyalg;
    self->total_body_input_len = 0;
    self->total_body_canonicalized_output_len = 0;

    *canon = self;
    return DSTAT_OK;
}   // end function: DkimCanonicalizer_new

/**
 * release DkimCanonicalizer object
 * @param self DkimCanonicalizer object to be released
 */
void
DkimCanonicalizer_free(DkimCanonicalizer *self)
{
    if (NULL == self) {
        return;
    }   // end if

    free(self->buf);
    free(self);
}   // end function: DkimCanonicalizer_free
