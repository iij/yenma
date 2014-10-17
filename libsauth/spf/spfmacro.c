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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/nameser.h>

#include "loghandler.h"
#include "spflogger.h"
#include "stdaux.h"
#include "ptrop.h"
#include "pstring.h"
#include "xbuffer.h"
#include "xskip.h"
#include "xparse.h"
#include "inetdomain.h"
#include "inetmailbox.h"
#include "spf.h"
#include "spfrecord.h"
#include "spfevaluator.h"
#include "spfmacro.h"

#define SPF_MACRO_DOTTED_INET6ADDRLEN (sizeof("0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f."))

#define IS_MACRO_LITERAL(c) ((0x21 <= (c) && (c) <= 0x7e) && '%' != (c))
#define IS_MACRO_DELIMITER(c) ((c) == '.' || (c) == '-' || (c) == '+' || (c) == ',' || (c) == '/' || (c) == '_' || (c) == '=')

#define SPF_MACRO_DOMAIN_VALIDATION_PTRRR_MAXNUM 10
#define SPF_MACRO_ALL_DELIMITERS ".-+,/_="
#define SPF_MACRO_DEFAULT_DELIMITER '.'
#define SPF_MACRO_DEFAULT_P_MACRO_VALUE "unknown"
#define SPF_MACRO_DEFAULT_R_MACRO_VALUE "unknown"

typedef struct SpfMacro {
    SpfMacroLetter letter;
    char delims[sizeof(SPF_MACRO_ALL_DELIMITERS)];
    // 0 は無制限 (transformer に 0 を指定するのは文法エラーなので, SPF レコード中で 0 が指定されることはない)
    size_t transformer;
    bool reverse;
    bool url_escape;
} SpfMacro;

struct SpfMacroLetterMap {
    const char letter;
    SpfMacroLetter macro;
    bool exp_only;              // "exp" modifier のみで使用可能なマクロの場合は true
};

static const struct SpfMacroLetterMap spf_macro_letter_table[] = {
    {'s', SPF_MACRO_S_SENDER, false},
    {'l', SPF_MACRO_L_SENDER_LOCALPART, false},
    {'o', SPF_MACRO_O_SENDER_DOMAIN, false},
    {'d', SPF_MACRO_D_DOMAIN, false},
    {'i', SPF_MACRO_I_DOTTED_IPADDR, false},
    {'p', SPF_MACRO_P_IPADDR_VALID_DOMAIN, false},
    {'v', SPF_MACRO_V_REVADDR_SUFFIX, false},
    {'h', SPF_MACRO_H_HELO_DOMAIN, false},
    {'c', SPF_MACRO_C_TEXT_IPADDR, true},
    {'r', SPF_MACRO_R_CHECKING_DOMAIN, true},
    {'t', SPF_MACRO_T_TIMESTAMP, true},
    {'\0', SPF_MACRO_NULL, false},
};

static void
SpfMacro_init(SpfMacro *self)
{
    memset(self, 0, sizeof(SpfMacro));
    self->reverse = false;
    self->url_escape = false;
    self->transformer = 0;
}   // end function: SpfMacro_init

/**
 * @attention The returned string should be released with free() when no longer needed.
 */
static char *
SpfMacro_dupMailboxAsString(const InetMailbox *mailbox)
{
    const char *localpart = InetMailbox_getLocalPart(mailbox);
    const char *domainpart = InetMailbox_getDomain(mailbox);
    size_t localpart_len = strlen(localpart);
    size_t domainpart_len = strlen(domainpart);
    char *mailaddr = (char *) malloc(localpart_len + domainpart_len + 2);   // 2 は '@' と終端文字
    if (NULL == mailaddr) {
        return NULL;
    }   // end if
    memcpy(mailaddr, localpart, localpart_len);
    mailaddr[localpart_len] = '@';
    memcpy(mailaddr + localpart_len + 1, domainpart, domainpart_len);
    mailaddr[localpart_len + domainpart_len + 1] = '\0';
    return mailaddr;
}   // end function: SpfMacro_dupMailboxAsString

/**
 * @attention The returned string should be released with free() when no longer needed.
 */
static char *
SpfMacro_dupValidatedDomainName(const SpfEvaluator *evaluator, const char *domain)
{
    /*
     * [RFC4408] 8.1.
     * The "p" macro expands to the validated domain name of <ip>.  The
     * procedure for finding the validated domain name is defined in Section
     * 5.5.  If the <domain> is present in the list of validated domains, it
     * SHOULD be used.  Otherwise, if a subdomain of the <domain> is
     * present, it SHOULD be used.  Otherwise, any name from the list may be
     * used.  If there are no validated domain names or if a DNS error
     * occurs, the string "unknown" is used.
     */

    DnsPtrResponse *respptr;
    dns_stat_t ptrquery_stat =
        DnsResolver_lookupPtr(evaluator->resolver, evaluator->sa_family, &(evaluator->ipaddr),
                              &respptr);
    if (DNS_STAT_NOERROR != ptrquery_stat) {
        return strdup(SPF_MACRO_DEFAULT_P_MACRO_VALUE);
    }   // end if

    // TODO: stable sort をする代わりにリストを3回なめている. stable sort をする方がエレガント.
    size_t resp_num_limit = MIN(respptr->num, SPF_MACRO_DOMAIN_VALIDATION_PTRRR_MAXNUM);
    char *expand = NULL;

    /*
     * [RFC4408] 8.1.
     * If the <domain> is present in the list of validated domains, it SHOULD be used.
     */
    for (size_t n = 0; n < resp_num_limit; ++n) {
        const char *revdomain = respptr->domain[n];
        if (InetDomain_equals(domain, revdomain)) {
            switch (SpfEvaluator_isValidatedDomainName(evaluator, revdomain)) {
            case 1:
                expand = strdup(revdomain);
                goto finally;
            case 0:
                // do nothing
                break;
            case -1:
                goto use_default_macro_value;
            default:
                abort();
            }   // end switch
        }   // end if
    }   // end for

    /*
     * [RFC4408] 8.1.
     * Otherwise, if a subdomain of the <domain> is present, it SHOULD be used.
     */
    for (size_t n = 0; n < resp_num_limit; ++n) {
        const char *revdomain = respptr->domain[n];
        if (InetDomain_isParent(domain, revdomain) && !InetDomain_equals(domain, revdomain)) {
            switch (SpfEvaluator_isValidatedDomainName(evaluator, revdomain)) {
            case 1:
                expand = strdup(revdomain);
                goto finally;
            case 0:
                // do nothing
                break;
            case -1:
                goto use_default_macro_value;
            default:
                abort();
            }   // end switch
        }   // end if
    }   // end for

    /*
     * [RFC4408] 8.1.
     * Otherwise, any name from the list may be used.
     */
    for (size_t n = 0; n < resp_num_limit; ++n) {
        const char *revdomain = respptr->domain[n];
        if (!InetDomain_isParent(domain, revdomain)) {
            switch (SpfEvaluator_isValidatedDomainName(evaluator, revdomain)) {
            case 1:
                expand = strdup(revdomain);
                goto finally;
            case 0:
                // do nothing
                break;
            case -1:
                goto use_default_macro_value;
            default:
                abort();
            }   // end switch
        }   // end if
    }   // end for

  use_default_macro_value:
    /*
     * [RFC4408] 8.1.
     * If there are no validated domain names or if a DNS error occurs, the string "unknown" is used.
     */
    expand = strdup(SPF_MACRO_DEFAULT_P_MACRO_VALUE);

  finally:
    DnsPtrResponse_free(respptr);
    return expand;
}   // end function: SpfMacro_dupValidatedDomainName

/*
 * The argument must be in the range 0-15, otherwise the behavior is undefined.
 */
static char
xtoa(unsigned char p)
{
    return p < 0xa ? p + '0' : p + 'a' - 0xa;
}   // end function: xtoa

/**
 * @attention The returned string should be released with free() when no longer needed.
 */
static char *
SpfMacro_dupDottedIpAddr(const SpfEvaluator *evaluator)
{
    switch (evaluator->sa_family) {
    case AF_INET:;
        char addrbuf4[INET_ADDRSTRLEN];
        (void) inet_ntop(AF_INET, &(evaluator->ipaddr), addrbuf4, sizeof(addrbuf4));
        return strdup(addrbuf4);
    case AF_INET6:;
        char addrbuf6[SPF_MACRO_DOTTED_INET6ADDRLEN];
        const unsigned char *rawaddr = (const unsigned char *) &(evaluator->ipaddr.addr6);
        const unsigned char *rawaddr_tail = rawaddr + NS_IN6ADDRSZ;
        char *bufp = addrbuf6;
        for (; rawaddr < rawaddr_tail; ++rawaddr) {
            *(bufp++) = xtoa((*(rawaddr++) & 0xf0) >> 4);
            *(bufp++) = '.';
            *(bufp++) = xtoa(*(rawaddr++) & 0x0f);
            *(bufp++) = '.';
        }   // end for
        return strpdup(addrbuf6, bufp - 1);
    default:
        abort();
    }   // end switch
}   // end function: SpfMacro_dupDottedIpAddr

/**
 * @attention The returned string should be released with free() when no longer needed.
 */
static char *
SpfMacro_dupMacroSource(const SpfEvaluator *evaluator, SpfMacroLetter macro_letter)
{
    switch (macro_letter) {
    case SPF_MACRO_S_SENDER:
        return SpfMacro_dupMailboxAsString(evaluator->sender);
    case SPF_MACRO_L_SENDER_LOCALPART:
        return strdup(InetMailbox_getLocalPart(evaluator->sender));
    case SPF_MACRO_O_SENDER_DOMAIN:
        return strdup(InetMailbox_getDomain(evaluator->sender));
    case SPF_MACRO_D_DOMAIN:
        return strdup(SpfEvaluator_getDomain(evaluator));
    case SPF_MACRO_I_DOTTED_IPADDR:
        return SpfMacro_dupDottedIpAddr(evaluator);
    case SPF_MACRO_P_IPADDR_VALID_DOMAIN:
        return SpfMacro_dupValidatedDomainName(evaluator, SpfEvaluator_getDomain(evaluator));
    case SPF_MACRO_V_REVADDR_SUFFIX:
        return strdup(AF_INET == evaluator->sa_family ? "in-addr" : "ip6");
    case SPF_MACRO_H_HELO_DOMAIN:
        return strdup(evaluator->helo_domain);
    case SPF_MACRO_C_TEXT_IPADDR:;
        char addrbuf[INET6_ADDRSTRLEN];
        (void) inet_ntop(evaluator->sa_family, &(evaluator->ipaddr), addrbuf, sizeof(addrbuf));
        return strdup(addrbuf);
    case SPF_MACRO_R_CHECKING_DOMAIN:
        // 受信した MTA (= SPF の検証をしたホスト) の名前
        return strdup(PTROR(evaluator->policy->checking_domain, SPF_MACRO_DEFAULT_R_MACRO_VALUE));
    case SPF_MACRO_T_TIMESTAMP:;
        char timebuf[20];
        snprintf(timebuf, sizeof(timebuf), "%ld", (long) time(NULL));
        return strdup(timebuf);
    default:
        abort();
    }   // end switch
}   // end function: SpfMacro_dupMacroSource

/**
 * 与えられた文字列の領域をセパレーターで区切り, 2次元配列を構築する.
 * s 内の delimstr を NULL で置き換え, 各要素の先頭を示すポインタからなる配列を返す.
 * @param s 区切りたい文字列
 * @param delimstr デリミタとして使う文字を繋げたNULL終端文字列
 * @param num 要素の数を受け取る変数へのポインタ
 * @attention s will be overwritten
 * @attention The returned string should be released with free() when no longer needed.
 */
static char **
SpfMacro_splitMacroSource(char *s, const char *delimstr, size_t *num)
{
    // 必要な配列のサイズを見積もる
    size_t n;
    char *q;
    for (n = 0, q = s; NULL != (q = strpbrk(q, delimstr)); ++n, ++q);
    // メモリの確保
    char **r = (char **) malloc((n + 2) * sizeof(char *));
    if (NULL == r) {
        return NULL;
    }   // end if

    char *token_tail;
    int idx = 0;
    r[idx] = s;
    while (NULL != (token_tail = strpbrk(r[idx], delimstr))) {
        *token_tail = '\0';
        r[++idx] = token_tail + 1;
    }   // end while
    r[++idx] = NULL;
    *num = idx;
    return r;
}   // end function: SpfMacro_splitMacroSource

static SpfStat
SpfMacro_expandMacro(const SpfMacro *macro, const SpfEvaluator *evaluator, XBuffer *xbuf)
{
    char *macro_source = SpfMacro_dupMacroSource(evaluator, macro->letter);
    if (NULL == macro_source) {
        LogNoResource();
        return SPF_STAT_NO_RESOURCE;
    }   // end if
    size_t num;
    char **macro_parts = SpfMacro_splitMacroSource(macro_source, macro->delims, &num);
    if (NULL == macro_parts) {
        free(macro_source);
        LogNoResource();
        return SPF_STAT_NO_RESOURCE;
    }   // end if

    // reverse が指定されている場合は反転する
    if (macro->reverse) {
        for (size_t n = 0; n < num / 2; ++n) {
            size_t pos = num - n - 1;
            char *tmp = macro_parts[pos];
            macro_parts[pos] = macro_parts[n];
            macro_parts[n] = tmp;
        }   // end for
    }   // end if

    size_t idx = (0 == macro->transformer || num <= macro->transformer)
        ? 0 : num - macro->transformer;
    // TODO: 大文字のマクロは対応する小文字のマクロと同様に展開し, URLエスケープすること
    // NOTE: URL エスケープは explanation レコードのみを対象とすべきではないのか?
    XBuffer_appendString(xbuf, macro_parts[idx]);
    for (++idx; NULL != macro_parts[idx]; ++idx) {
        XBuffer_appendChar(xbuf, '.');
        XBuffer_appendString(xbuf, macro_parts[idx]);
    }   // end for

    free(macro_parts);
    free(macro_source);
    return SPF_STAT_OK;
}   // end function: SpfMacro_expandMacro

/*
 * [RFC4408]
 * delimiter        = "." / "-" / "+" / "," / "/" / "_" / "="
 */
static SpfStat
SpfMacro_parseDelimiterBlock(SpfMacro *macro, const char *head,
                             const char *tail, const char **nextp)
{
    const char *p;
    char *delims_tail = macro->delims;
    for (p = head; p < tail; ++p) {
        const char *delim = strchr(SPF_MACRO_ALL_DELIMITERS, *p);
        if (NULL == delim) {
            break;
        }   // end if
        // macro->delims に *delim を連結する
        for (char *q = macro->delims; q < delims_tail; ++q) {
            if (*q == *delim) {
                // delimiter が重複指定されている
                SpfLogPermFail("delimiter specified repeatedly in macro-expand: delimiter=%c",
                               (int) *q);
                return SPF_STAT_RECORD_DELIMITER_DUPLICATED;
            }   // end if
        }   // end if
        *(delims_tail++) = *delim;
    }   // end for

    // delimiter が指定されていない場合はデフォルト値をセット
    if (head == p) {
        *(delims_tail++) = SPF_MACRO_DEFAULT_DELIMITER;
    }   // end if

    // macro->delims を NULL 終端させる
    *delims_tail = '\0';
    *nextp = p;
    return SPF_STAT_OK;
}   // end function: SpfMacro_parseDelimiterBlock

/*
 * [RFC4408]
 * macro-letter     = "s" / "l" / "o" / "d" / "i" / "p" / "h" /
 *                    "c" / "r" / "t" / "v"
 */
static SpfStat
SpfMacro_parseMacroLetter(SpfMacro *macro, const char *head,
                          const char *tail, bool exp_record, const char **nextp)
{
    if (head < tail) {
        int lowletter = tolower(*head);
        const struct SpfMacroLetterMap *p;
        for (p = spf_macro_letter_table; '\0' != p->letter; ++p) {
            if (lowletter == p->letter) {
                if (!exp_record && p->exp_only) {
                    // "exp=" のみで使えるマクロをはじく
                    SpfLogPermFail("macro-letter only for explanation record specified: letter=%c",
                                   (int) *head);
                    *nextp = head;
                    return SPF_STAT_RECORD_UNSUPPORTED_MACRO;
                }   // end if
                macro->letter = p->macro;
                /*
                 * [RFC4408] 8.1.
                 * Uppercased macros expand exactly as their lowercased equivalents, and
                 * are then URL escaped.  URL escaping must be performed for characters
                 * not in the "uric" set, which is defined in [RFC3986].
                 */
                macro->url_escape = bool_cast(isupper(*head));
                *nextp = head + 1;
                return SPF_STAT_OK;
            }   // end if
        }   // end for
        SpfLogPermFail("undefined macro-letter: letter=%c", (int) *head);
        *nextp = head;
        return SPF_STAT_RECORD_UNSUPPORTED_MACRO;
    }   // end if
    SpfLogPermFail("macro-letter not specified");
    *nextp = head;
    return SPF_STAT_RECORD_SYNTAX_VIOLATION;
}   // end function: SpfMacro_parseMacroLetter

/*
 * [RFC4408]
 * transformers     = *DIGIT [ "r" ]
 */
static int
SpfMacro_parseTransformers(SpfMacro *macro, const char *head, const char *tail, const char **nextp)
{
    const char *p = head;
    /*
     * [RFC4408] 8.1.
     * The DIGIT transformer indicates the number of right-hand parts to
     * use, after optional reversal.  If a DIGIT is specified, the value
     * MUST be nonzero.
     */
    // 数字を含まない場合 strptoul は 0 を返す.
    // transformer は 0 の場合無制限を表すので数字を含まない場合のハンドルは (たまたま) 必要ない.
    macro->transformer = strptoul(p, tail, &p);
    macro->reverse = bool_cast(0 < XSkip_char(p, tail, 'r', &p));
    *nextp = p;
    return p - head;
}   // end function: SpfMacro_parseTransformers

/*
 * @return SPF_STAT_OK: 1文字以上マッチ
 *         SPF_STAT_RECORD_NOT_MATCH: エラーではないがマッチしなかった
 *         SPF_STAT_RECORD_SYNTAX_VIOLATION: 構文違反
 *         SPF_STAT_NO_RESOURCE: リソース不足
 *
 * [RFC4408]
 * macro-expand     = ( "%{" macro-letter transformers *delimiter "}" )
 *                    / "%%" / "%_" / "%-"
 */
static SpfStat
SpfMacro_parseMacroExpand(const SpfEvaluator *evaluator, const char *head, const char *tail,
                          bool exp_record, const char **nextp, XBuffer *xbuf)
{
    const char *p = head;
    if (head + 1 < tail && '%' == *p) {
        switch (*(++p)) {
        case '{':;
            // マクロのパース結果を格納するための用構造体を準備
            SpfMacro macro;
            SpfMacro_init(&macro);
            ++p;

            SpfStat parse_stat = SpfMacro_parseMacroLetter(&macro, p, tail, exp_record, &p);
            if (SPF_STAT_OK != parse_stat) {
                return parse_stat;
            }   // end if

            SpfMacro_parseTransformers(&macro, p, tail, &p);

            SpfStat delim_stat = SpfMacro_parseDelimiterBlock(&macro, p, tail, &p);
            if (SPF_STAT_OK != delim_stat) {
                *nextp = head;
                return delim_stat;
            }   // end if

            if (0 < XSkip_char(p, tail, '}', &p)) {
                // ここでやっとマクロとして確定したので展開する
                SpfStat expand_stat = SpfMacro_expandMacro(&macro, evaluator, xbuf);
                if (SPF_STAT_OK != expand_stat) {
                    *nextp = head;
                    return expand_stat;
                }   // end if
                if (evaluator->policy->macro_expansion_limit < XBuffer_getSize(xbuf)) {
                    SpfLogPermFail("expanded macro too long: limit=%u, length=%u",
                                   evaluator->policy->macro_expansion_limit,
                                   (unsigned int) XBuffer_getSize(xbuf));
                    *nextp = head;
                    return SPF_STAT_MALICIOUS_MACRO_EXPANSION;
                }   // end if
                *nextp = p;
                return SPF_STAT_OK;
            } else {
                SpfLogPermFail("closed parenthesis not found for macro");
                *nextp = head;
                return SPF_STAT_RECORD_SYNTAX_VIOLATION;
            }   // end if

        case '%':
            /*
             * [RFC4408] 8.1.
             * A literal "%" is expressed by "%%".
             */
            XBuffer_appendChar(xbuf, '%');
            *nextp = head + 2;
            return SPF_STAT_OK;

        case '_':
            /*
             * [RFC4408] 8.1.
             * "%_" expands to a single " " space.
             */
            XBuffer_appendChar(xbuf, 0x20);
            *nextp = head + 2;
            return SPF_STAT_OK;

        case '-':
            /*
             * [RFC4408] 8.1.
             * "%-" expands to a URL-encoded space, viz., "%20".
             */
            XBuffer_appendString(xbuf, "%20");
            *nextp = head + 2;
            return SPF_STAT_OK;

        default:
            // [RFC4408] 8.1.
            //  A '%' character not followed by a '{', '%', '-', or '_' character is
            //  a syntax error.
            SpfLogPermFail("'%%' character not followed by spec-defined character: char=%c",
                           (int) *p);
            *nextp = head;
            return SPF_STAT_RECORD_SYNTAX_VIOLATION;
        }   // end switch
    }   // end if
    *nextp = head;
    return SPF_STAT_RECORD_NOT_MATCH;
}   // end function: SpfMacro_parseMacroExpand

/*
 * [RFC4408]
 * macro-literal    = %x21-24 / %x26-7E
 *                    ; visible characters except "%"
 */
static int
SpfMacro_parseMacroLiteralBlock(const char *head, const char *tail, const char **nextp,
                                XBuffer *xbuf)
{
    const char *p;
    for (p = head; p < tail && IS_MACRO_LITERAL(*p); ++p);
    *nextp = p;
    int matchlen = *nextp - head;
    if (0 < matchlen) {
        XBuffer_appendStringN(xbuf, head, matchlen);
    }   // end if
    return matchlen;
}   // end function: SpfMacro_parseMacroLiteralBlock

/*
 * [RFC4408]
 * macro-string     = *( macro-expand / macro-literal )
 */
static SpfStat
SpfMacro_parseMacroString(const SpfEvaluator *evaluator, const char *head, const char *tail,
                          bool exp_record, const char **nextp, bool *literal_terminated,
                          XBuffer *xbuf)
{
    const char *p = head;
    while (true) {
        int literal_len = SpfMacro_parseMacroLiteralBlock(p, tail, &p, xbuf);
        SpfStat macro_stat = SpfMacro_parseMacroExpand(evaluator, p, tail, exp_record, &p, xbuf);
        switch (macro_stat) {
        case SPF_STAT_OK:
            break;
        case SPF_STAT_RECORD_NOT_MATCH:
            *nextp = p;
            SETDEREF(literal_terminated, (0 < literal_len) ? true : false);
            return (0 < p - head) ? SPF_STAT_OK : SPF_STAT_RECORD_NOT_MATCH;
        default:
            *nextp = head;
            return macro_stat;
        }   // end switch
    }   // end while
}   // end function: SpfMacro_parseMacroString

/*
 * [RFC4408]
 * explain-string   = *( macro-string / SP )
 */
SpfStat
SpfMacro_parseExplainString(const SpfEvaluator *evaluator, const char *head, const char *tail,
                            const char **nextp, XBuffer *xbuf)
{
    const char *p = head;
    while (true) {
        int sp_match = XParse_char(p, tail, ' ', &p, xbuf);
        SpfStat parse_stat = SpfMacro_parseMacroString(evaluator, p, tail, true, &p, NULL, xbuf);
        switch (parse_stat) {
        case SPF_STAT_OK:
            break;
        case SPF_STAT_RECORD_NOT_MATCH:
            if (0 == sp_match) {
                *nextp = p;
                return 0 < *nextp - head ? SPF_STAT_OK : SPF_STAT_RECORD_NOT_MATCH;
            }   // end if
            break;
        default:
            *nextp = head;
            return parse_stat;
        }   // end switch
    }   // end while
}   // end function: SpfMacro_parseExplainString

/*
 * [RFC4408]
 * domain-end       = ( "." toplabel [ "." ] ) / macro-expand
 * toplabel         = ( *alphanum ALPHA *alphanum ) /
 *                    ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
 *                    ; LDH rule plus additional TLD restrictions
 *                    ; (see [RFC3696], Section 2)
 */
static int
SpfMacro_skipbackTopLabel(const char *head, const char *tail, const char **prevp)
{
    const char *q = tail - 1;
    *prevp = tail;
    if (head <= q && '.' == *q) {
        --q;
    }   // end if

    if (q < head || !IS_LET_DIG(*q)) {
        return 0;
    }   // end if

    for (--q; head <= q; --q) {
        if (IS_LET_DIG(*q) || '-' == *q) {
            continue;
        } else if ('.' == *q && '-' != *(q + 1)) {
            *prevp = q;
            return tail - q;
        }   // end if
        return 0;
    }   // end for

    // never reach here
    return 0;
}   // end function: SpfMacro_skipbackTopLabel

/*
 * [RFC4408]
 * domain-spec      = macro-string domain-end
 * domain-end       = ( "." toplabel [ "." ] ) / macro-expand
 * (toplabel is equal to sub-domain of RFC5321)
 *
 * we obtain the following:
 * domain-spec      = *( macro-expand / macro-literal ) ( ( "." sub-domain [ "." ] ) / macro-expand )
 */
SpfStat
SpfMacro_parseDomainSpec(const SpfEvaluator *evaluator, const char *head, const char *tail,
                         const char **nextp, XBuffer *xbuf)
// NOTE: macro-string 中の macro-literal がなんでも食っちゃう. domain-end を判別できないのが一番ツライ
// NOTE: 少なくとも "/", "=", ":" は macro-string から抜くべき.
// label = alphanum / "-" / "_" くらいでいいと思う
// あるいは '.' を目印に sub-domain を先に評価するとか
// [RFC4408] 4.6.1
// Modifiers always contain an equals ('=') character immediately after
// the name, and before any ":" or "/" characters that may be part of
// the macro-string.
//
// Terms that do not contain any of "=", ":", or "/" are mechanisms, as
// defined in Section 5.
{
    const char *p = head;
    bool literal_terminated;
    SpfStat parse_stat =
        SpfMacro_parseMacroString(evaluator, p, tail, false, &p, &literal_terminated, xbuf);
    if (SPF_STAT_OK != parse_stat) {
        *nextp = head;
        return parse_stat;
    }   // end if

    // 前からパースすると macro-string が domain-end を喰っちゃうので,
    // macro-string が macro-literal で終端している場合のみ,
    // domain-end が toplabel で終端しているか確認する.
    const char *q;
    if (literal_terminated && 0 == SpfMacro_skipbackTopLabel(head, tail, &q)) {
        SpfLogPermFail("domain-spec does not terminate with domain-end: domain-spec=%.*s",
                       (int) (tail - head), head);

        *nextp = head;
        return SPF_STAT_RECORD_NOT_MATCH;
    }   // end if

    *nextp = p;
    return SPF_STAT_OK;
}   // end function: SpfMacro_parseDomainSpec
