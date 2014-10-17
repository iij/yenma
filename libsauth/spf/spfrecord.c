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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "ptrop.h"
#include "inet_ppton.h"
#include "loghandler.h"
#include "spflogger.h"
#include "pstring.h"
#include "keywordmap.h"
#include "xskip.h"
#include "inetdomain.h"
#include "spf.h"
#include "spfmacro.h"
#include "spfrecord.h"

#define SPF_RECORD_SPF1_PREFIX "v=spf1"
#define SPF_RECORD_SIDF20_PREFIX "spf2.0"

// maximum value of ip4-cidr-length
#define SPF_IP4_MAX_CIDR_LENGTH 32
// maximum value of ip6-cidr-length
#define SPF_IP6_MAX_CIDR_LENGTH 128
// the number of digits to represent cidr-length decimally
// 128 が最大値なので3桁あれば十分
#define SPF_RECORD_CIDRLEN_MAX_WIDTH 3
#define SPF_MACRO_EXPANSION_MAX_LENGTH 253

/*
 * [RFC7208] 12.
 * record           = version terms *SP
 * version          = "v=spf1"
 * terms            = *( 1*SP ( directive / modifier ) )
 * directive        = [ qualifier ] mechanism
 * qualifier        = "+" / "-" / "?" / "~"
 * mechanism        = ( all / include
 *                    / a / mx / ptr / ip4 / ip6 / exists )
 * all              = "all"
 * include          = "include"  ":" domain-spec
 * a                = "a"      [ ":" domain-spec ] [ dual-cidr-length ]
 * mx               = "mx"     [ ":" domain-spec ] [ dual-cidr-length ]
 * ptr              = "ptr"    [ ":" domain-spec ]
 * ip4              = "ip4"      ":" ip4-network   [ ip4-cidr-length ]
 * ip6              = "ip6"      ":" ip6-network   [ ip6-cidr-length ]
 * exists           = "exists"   ":" domain-spec
 * modifier         = redirect / explanation / unknown-modifier
 * redirect         = "redirect" "=" domain-spec
 * explanation      = "exp" "=" domain-spec
 * unknown-modifier = name "=" macro-string
 *                    ; where name is not any known modifier
 * ip4-cidr-length  = "/" ("0" / %x31-39 0*1DIGIT) ; value range 0-32
 * ip6-cidr-length  = "/" ("0" / %x31-39 0*2DIGIT) ; value range 0-128
 * dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]
 *
 * domain-spec      = macro-string domain-end
 * domain-end       = ( "." toplabel [ "." ] ) / macro-expand
 * toplabel         = ( *alphanum ALPHA *alphanum ) /
 *                    ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
 *                    ; LDH rule plus additional TLD restrictions
 *                    ; (see Section 2 of [RFC3696] for background)
 * alphanum         = ALPHA / DIGIT
 * explain-string   = *( macro-string / SP )
 * macro-string     = *( macro-expand / macro-literal )
 * macro-expand     = ( "%{" macro-letter transformers *delimiter "}" )
 *                    / "%%" / "%_" / "%-"
 * macro-literal    = %x21-24 / %x26-7E
 *                    ; visible characters except "%"
 * macro-letter     = "s" / "l" / "o" / "d" / "i" / "p" / "h" /
 *                    "c" / "r" / "t" / "v"
 * transformers     = *DIGIT [ "r" ]
 * delimiter        = "." / "-" / "+" / "," / "/" / "_" / "="
 * name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
 */

static const SpfTermAttribute spf_mech_attr_table[] = {
    {"all", SPF_TERM_MECH_ALL, true, SPF_TERM_PARAM_NONE,
     false, '\0', false, SPF_TERM_CIDR_OPTION_NONE},
    {"include", SPF_TERM_MECH_INCLUDE, true, SPF_TERM_PARAM_DOMAINSPEC,
     true, ':', true, SPF_TERM_CIDR_OPTION_NONE},
    // first match なので "a" は "all" より後になければならない
    {"a", SPF_TERM_MECH_A, true, SPF_TERM_PARAM_DOMAINSPEC,
     true, ':', false, SPF_TERM_CIDR_OPTION_DUAL},
    {"mx", SPF_TERM_MECH_MX, true, SPF_TERM_PARAM_DOMAINSPEC,
     true, ':', false, SPF_TERM_CIDR_OPTION_DUAL},
    {"ptr", SPF_TERM_MECH_PTR, true, SPF_TERM_PARAM_DOMAINSPEC,
     true, ':', false, SPF_TERM_CIDR_OPTION_NONE},
    {"ip4", SPF_TERM_MECH_IP4, true, SPF_TERM_PARAM_IP4,
     false, ':', true, SPF_TERM_CIDR_OPTION_IP4},
    {"ip6", SPF_TERM_MECH_IP6, true, SPF_TERM_PARAM_IP6,
     false, ':', true, SPF_TERM_CIDR_OPTION_IP6},
    {"exists", SPF_TERM_MECH_EXISTS, true, SPF_TERM_PARAM_DOMAINSPEC,
     true, ':', true, SPF_TERM_CIDR_OPTION_NONE},
    // sentinel
    {NULL, SPF_TERM_MECH_NULL, false, SPF_TERM_PARAM_NONE,
     false, '\0', false, SPF_TERM_CIDR_OPTION_NONE},
};

static const SpfTermAttribute spf_mod_attr_table[] = {
    {"redirect", SPF_TERM_MOD_REDIRECT, false, SPF_TERM_PARAM_DOMAINSPEC,
     true, '=', true, SPF_TERM_CIDR_OPTION_NONE},
    {"exp", SPF_TERM_MOD_EXPLANATION, false, SPF_TERM_PARAM_DOMAINSPEC,
     false, '=', true, SPF_TERM_CIDR_OPTION_NONE},
    // sentinel
    {NULL, SPF_TERM_MECH_NULL, false, SPF_TERM_PARAM_NONE,
     false, '\0', false, SPF_TERM_CIDR_OPTION_NONE},
};

typedef struct SpfQualifierMap {
    const char symbol;
    SpfQualifier qualifier;
} SpfQualifierMap;

static const SpfQualifierMap spf_qualifier_table[] = {
    {'+', SPF_QUALIFIER_PLUS},
    {'-', SPF_QUALIFIER_MINUS},
    {'?', SPF_QUALIFIER_QUESTION},
    {'~', SPF_QUALIFIER_TILDE},
    {'\0', SPF_QUALIFIER_NULL}, // sentinel
};

/*
 * SIDF レコードのスコープ文字列から列挙体の値をひく.
 * @return RFC4406 で定義されているスコープの場合は SPF_RECORD_SCOPE_SPF2_* を,
 *         未定義のスコープの場合は SPF_RECORD_SCOPE_UNKNOWN を,
 *         長さが0の場合やスコープ名として認識できない場合は SPF_RECORD_SCOPE_NULL を返す.
 *
 * [RFC4406]
 * scope-id    = "mfrom" / "pra" / name
 * [RFC4408]
 * name        = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
 */
static SpfRecordScope
SpfRecord_lookupSpfScope(const char *head, const char *tail, const char **nextp)
{
    static const KeywordMap spf_scope_table[] = {
        {"mfrom", SPF_RECORD_SCOPE_SPF2_MFROM},
        {"pra", SPF_RECORD_SCOPE_SPF2_PRA},
        {NULL, SPF_RECORD_SCOPE_UNKNOWN},   // sentinel
    };

    if (0 < XSkip_spfName(head, tail, nextp)) {
        return KeywordMap_lookupByCaseStringSlice(spf_scope_table, head, *nextp);
    } else {
        *nextp = head;
        return SPF_RECORD_SCOPE_NULL;
    }   // end if
}   // end function: SpfRecord_lookupSpfScope

/*
 * [RFC4406]
 * record      = version terms *SP
 * version     = "v=spf1" | ( "spf2." ver-minor scope)
 * ver-minor   = 1*DIGIT
 * scope       = "/" scope-id *( "," scope-id )
 * scope-id    = "mfrom" / "pra" / name
 */
static SpfStat
SpfRecord_parseVersion(const char *head, const char *tail,
                       const char **nextp, SpfRecordScope *scope)
{
    // SPF レコードかチェック
    if (0 < XSkip_casestring(head, tail, SPF_RECORD_SPF1_PREFIX, nextp)) {
        *scope = SPF_RECORD_SCOPE_SPF1;
        return SPF_STAT_OK;
    }   // end if

    // SIDF レコードかチェック
    const char *p;
    if (0 < XSkip_casestring(head, tail, SPF_RECORD_SIDF20_PREFIX, &p)
        && 0 < XSkip_char(p, tail, '/', &p)) {
        SpfRecordScope record_scope = 0;
        const char *scope_tail;
        do {
            SpfRecordScope current_scope = SpfRecord_lookupSpfScope(p, tail, &scope_tail);
            switch (current_scope) {
            case SPF_RECORD_SCOPE_NULL:
                SpfLogPermFail("invalid record for scope format: scope=%.*s",
                               (int) (tail - head), head);
                goto parsefail;
            case SPF_RECORD_SCOPE_UNKNOWN:
                // 無効なスコープは無視する
                LogInfo("unsupported scope specified (ignored): scope=%.*s",
                        (int) (scope_tail - p), p);
                // fall through
            default:
                // もしスコープが重複指定されていても, RFC4408 で明示的に禁止されていないので許容する.
                record_scope |= current_scope;
                break;
            }   // end switch
        } while (0 < XSkip_char(scope_tail, tail, ',', &p));
        *nextp = p;
        *scope = record_scope;
        return SPF_STAT_OK;
    }   // end if

    // fall through

  parsefail:
    *nextp = head;
    *scope = SPF_RECORD_SCOPE_NULL;
    return SPF_STAT_RECORD_SYNTAX_VIOLATION;
}   // end function: SpfRecord_parseVersion

static SpfQualifier
SpfRecord_parseQualifier(const char *head, const char *tail, const char **nextp)
{
    if (tail <= head) {
        *nextp = head;
        return SPF_QUALIFIER_NULL;
    }   // end if

    const SpfQualifierMap *p;
    for (p = spf_qualifier_table; '\0' != p->symbol; ++p) {
        if (*head == p->symbol) {
            *nextp = head + 1;
            return p->qualifier;
        }   // end if
    }   // end if

    *nextp = head;
    return p->qualifier;
}   // end function: SpfRecord_parseQualifier

static SpfStat
SpfRecord_parseDomainSpec(SpfRecord *self, const char *head, const char *tail, SpfTerm *term,
                          const char **nextp)
{
    XBuffer_reset(self->evaluator->xbuf);
    SpfStat parse_stat =
        SpfMacro_parseDomainSpec(self->evaluator, head, tail, nextp, self->evaluator->xbuf);
    if (SPF_STAT_OK == parse_stat) {
        SpfLogParseTrace("    domainspec: %.*s as [%s]\n",
                         *nextp - head, head, XBuffer_getString(self->evaluator->xbuf));
        if (0 != XBuffer_status(self->evaluator->xbuf)) {
            LogNoResource();
            return SPF_STAT_NO_RESOURCE;
        }   // end if
        term->param.domain = XBuffer_dupString(self->evaluator->xbuf);
        if (NULL == term->param.domain) {
            LogNoResource();
            return SPF_STAT_NO_RESOURCE;
        }   // end if

        /*
         * 展開結果が253文字を越える場合はそれ以下に丸める.
         * クエリを引く直前に丸める選択もあったが, domain-spec を引数にとる mechanism は
         * 全てそれに基づいてクエリを引くので domain-spec を解釈する時点で丸めることにした.
         *
         * [RFC4408] 8.1.
         * When the result of macro expansion is used in a domain name query, if
         * the expanded domain name exceeds 253 characters (the maximum length
         * of a domain name), the left side is truncated to fit, by removing
         * successive domain labels until the total length does not exceed 253
         * characters.
         */
        term->querydomain = term->param.domain;
        while (SPF_MACRO_EXPANSION_MAX_LENGTH < strlen(term->querydomain)) {
            term->querydomain = InetDomain_upward(term->querydomain);
            if (NULL == term->querydomain) {
                // サブドメインなしで 253 文字を突破していた場合
                SpfLogPermFail
                    ("macro expansion exceeds limits of its length: domain=%s, domain-spec=[%.*s]",
                     self->domain, (int) (*nextp - head), head);
                return SPF_STAT_MALICIOUS_MACRO_EXPANSION;
            }   // end if
        }   // end while
        if (term->querydomain != term->param.domain) {
            LogInfo("domain-spec truncated: domain=%s, %s=%s, domain-spec=%s", self->domain,
                    term->attr->is_mechanism ? "mech" : "mod", term->attr->name, term->querydomain);
        }   // end if
    }   // end if
    return parse_stat;
}   // end function: SpfRecord_parseDomainSpec

static SpfStat
SpfRecord_parseIp4Addr(const char *head, const char *tail, SpfTerm *term, const char **nextp)
{
    const char *p = head;
    for (++p; p < tail && (isdigit(*p) || '.' == *p); ++p);
    if (head < p && 1 == inet_ppton(AF_INET, head, p, &(term->param.addr4))) {
        *nextp = p;
        SpfLogParseTrace("    ip4addr: %.*s\n", *nextp - head, head);
        return SPF_STAT_OK;
    } else {
        *nextp = head;
        return SPF_STAT_RECORD_SYNTAX_VIOLATION;
    }   // end if
}   // end function: SpfRecord_parseIp4Addr

static SpfStat
SpfRecord_parseIp6Addr(const char *head, const char *tail, SpfTerm *term, const char **nextp)
{
    const char *p = head;
    for (++p; p < tail && (isxdigit(*p) || ':' == *p || '.' == *p); ++p);
    if (head < p && 1 == inet_ppton(AF_INET6, head, p, &(term->param.addr6))) {
        *nextp = p;
        SpfLogParseTrace("    ip6addr: %.*s\n", *nextp - head, head);
        return SPF_STAT_OK;
    } else {
        *nextp = head;
        return SPF_STAT_RECORD_SYNTAX_VIOLATION;
    }   // end if
}   // end function: SpfRecord_parseIp6Addr

static SpfStat
SpfRecord_parsebackCidrLength(const char *head, const char *tail,
                              const char **prevp, unsigned short *cidrlength)
{
    // cidr-length は 3桁を越えることはないので, 3桁以上はパースしない.
    const char *cidr_head =
        (head < tail - SPF_RECORD_CIDRLEN_MAX_WIDTH) ? tail - SPF_RECORD_CIDRLEN_MAX_WIDTH : head;
    const char *p = tail - 1;
    unsigned short cidr_value = 0;
    for (unsigned short base = 1; cidr_head <= p && isdigit(*p); --p, base *= 10) {
        cidr_value += (*p - '0') * base;
    }   // end for
    if (p < tail - 1 && head <= p && '/' == *p) {
        *prevp = p;
        *cidrlength = cidr_value;
        return SPF_STAT_OK;
    } else {
        *prevp = tail;
        *cidrlength = 0;
        return SPF_STAT_RECORD_NOT_MATCH;
    }   // end if
}   // end function: SpfRecord_parsebackCidrLength

/**
 * @return SPF_STAT_OK: maxcidrlen 以下の cidr-length を取得した.
 *         SPF_STAT_RECORD_INVALID_CIDR_LENGTH: cidr-length が指定されていたが値が不正だった.
 *         SPF_STAT_RECORD_SYNTAX_VIOLATION: cidr-length の文法にマッチするものは見つからなかった.
 */
static SpfStat
SpfRecord_parsebackSingleCidrLength(const char *head, const char *tail,
                                    const char *mechname, unsigned short maxcidrlen,
                                    const char **prevp, unsigned short *cidrlength)
{
    SpfStat parse_stat = SpfRecord_parsebackCidrLength(head, tail, prevp, cidrlength);
    switch (parse_stat) {
    case SPF_STAT_OK:
        SpfLogParseTrace("    %scidr: %.*s\n", mechname, tail - *prevp, *prevp);
        if (0 == *cidrlength || maxcidrlen < *cidrlength) {
            SpfLogPermFail("invalid cidr-length specified: mech=%s, cidr-length=%hu",
                           mechname, *cidrlength);
            return SPF_STAT_RECORD_INVALID_CIDR_LENGTH;
        }   // end if
        return SPF_STAT_OK;
    case SPF_STAT_RECORD_NOT_MATCH:
        return SPF_STAT_RECORD_NOT_MATCH;
    default:
        abort();
    }   // end switch
}   // end function: SpfRecord_parsebackSingleCidrLength

/**
 * @return SPF_STAT_OK: maxcidrlen 以下の cidr-length を取得した.
 *         SPF_STAT_RECORD_INVALID_CIDR_LENGTH: cidr-length が指定されていたが値が不正だった.
 *         SPF_STAT_RECORD_SYNTAX_VIOLATION: cidr-length の文法にマッチするものは見つからなかった.
 */
static SpfStat
SpfRecord_parsebackIp4CidrLength(const char *head, const char *tail,
                                 SpfTerm *term, const char **prevp)
{
    unsigned short cidrlength;
    SpfStat parse_stat = SpfRecord_parsebackSingleCidrLength(head, tail, term->attr->name,
                                                             SPF_IP4_MAX_CIDR_LENGTH,
                                                             prevp,
                                                             &cidrlength);
    term->ip4cidr = (SPF_STAT_OK == parse_stat) ? cidrlength : SPF_IP4_MAX_CIDR_LENGTH;
    return parse_stat;
}   // end function: SpfRecord_parsebackIp4CidrLength

/**
 * @return SPF_STAT_OK: maxcidrlen 以下の cidr-length を取得した.
 *         SPF_STAT_RECORD_INVALID_CIDR_LENGTH: cidr-length が指定されていたが値が不正だった.
 *         SPF_STAT_RECORD_SYNTAX_VIOLATION: cidr-length の文法にマッチするものは見つからなかった.
 */
static SpfStat
SpfRecord_parsebackIp6CidrLength(const char *head, const char *tail,
                                 SpfTerm *term, const char **prevp)
{
    unsigned short cidrlength;
    SpfStat parse_stat =
        SpfRecord_parsebackSingleCidrLength(head, tail, term->attr->name, SPF_IP6_MAX_CIDR_LENGTH,
                                            prevp, &cidrlength);
    term->ip6cidr = (SPF_STAT_OK == parse_stat) ? cidrlength : SPF_IP6_MAX_CIDR_LENGTH;
    return parse_stat;
}   // end function: SpfRecord_parsebackIp6CidrLength

/**
 * @return SPF_STAT_OK: maxcidrlen 以下の cidr-length を取得した.
 *         SPF_STAT_RECORD_INVALID_CIDR_LENGTH: cidr-length が指定されていたが値が不正だった.
 *         SPF_STAT_RECORD_SYNTAX_VIOLATION: cidr-length の文法にマッチするものは見つからなかった.
 */
static SpfStat
SpfRecord_parsebackDualCidrLength(const char *head, const char *tail,
                                  SpfTerm *term, const char **prevp)
{
    const char *p;
    unsigned short cidrlength;
    SpfStat parse_stat = SpfRecord_parsebackCidrLength(head, tail, &p, &cidrlength);
    switch (parse_stat) {
    case SPF_STAT_OK:
        if (head <= p - 1 && '/' == *(p - 1)) {
            // ip6-cidr-length
            SpfLogParseTrace("    ip6cidr: %.*s\n", tail - p, p);
            if (0 == cidrlength || SPF_IP6_MAX_CIDR_LENGTH < cidrlength) {
                SpfLogPermFail("invalid ip6-cidr-length specified: mech=%s, cidr-length=%hu",
                               term->attr->name, cidrlength);
                return SPF_STAT_RECORD_INVALID_CIDR_LENGTH;
            }   // end if
            term->ip6cidr = cidrlength;
            return SpfRecord_parsebackIp4CidrLength(head, p - 1, term, prevp);
        } else {
            // ip4-cidr-length
            SpfLogParseTrace("    ip4cidr: %.*s\n", tail - p, p);
            if (0 == cidrlength || SPF_IP4_MAX_CIDR_LENGTH < cidrlength) {
                SpfLogPermFail("invalid ip4-cidr-length specified: mech=%s, cidr-length=%hu",
                               term->attr->name, cidrlength);
                return SPF_STAT_RECORD_INVALID_CIDR_LENGTH;
            }   // end if
            term->ip4cidr = cidrlength;
            term->ip6cidr = SPF_IP6_MAX_CIDR_LENGTH;
            *prevp = p;
        }   // end if
        break;
    case SPF_STAT_RECORD_NOT_MATCH:
        // ip4, ip6 ともデフォルト値を使用する
        term->ip4cidr = SPF_IP4_MAX_CIDR_LENGTH;
        term->ip6cidr = SPF_IP6_MAX_CIDR_LENGTH;
        *prevp = p;
        break;
    default:
        abort();
    }   // end switch
    return parse_stat;
}   // end function: SpfRecord_parsebackDualCidrLength

/**
 * @return SPF_STAT_OK: maxcidrlen 以下の cidr-length を取得した.
 *         SPF_STAT_RECORD_INVALID_CIDR_LENGTH: cidr-length が指定されていたが値が不正だった.
 *         SPF_STAT_RECORD_SYNTAX_VIOLATION: cidr-length の文法にマッチするものは見つからなかった.
 */
static SpfStat
SpfRecord_parseCidrLength(SpfTermCidrOption cidr_type, const char *head,
                          const char *tail, SpfTerm *term, const char **prevp)
{
    switch (cidr_type) {
    case SPF_TERM_CIDR_OPTION_NONE:
        *prevp = tail;
        return SPF_STAT_OK;
    case SPF_TERM_CIDR_OPTION_DUAL:
        return SpfRecord_parsebackDualCidrLength(head, tail, term, prevp);
    case SPF_TERM_CIDR_OPTION_IP4:
        return SpfRecord_parsebackIp4CidrLength(head, tail, term, prevp);
    case SPF_TERM_CIDR_OPTION_IP6:
        return SpfRecord_parsebackIp6CidrLength(head, tail, term, prevp);
    default:
        abort();
    }   // end switch
}   // end function: SpfRecord_parseCidrLength

static SpfStat
SpfRecord_parseTermTargetName(SpfRecord *self, SpfTermParamType param_type, const char *head,
                              const char *tail, SpfTerm *term, const char **nextp)
{
    switch (param_type) {
    case SPF_TERM_PARAM_NONE:
        *nextp = tail;
        return SPF_STAT_OK;
    case SPF_TERM_PARAM_DOMAINSPEC:
        return SpfRecord_parseDomainSpec(self, head, tail, term, nextp);
    case SPF_TERM_PARAM_IP4:
        return SpfRecord_parseIp4Addr(head, tail, term, nextp);
    case SPF_TERM_PARAM_IP6:
        return SpfRecord_parseIp6Addr(head, tail, term, nextp);
    default:
        abort();
    }   // end switch
}   // end function: SpfRecord_parseTermTargetName

static SpfTerm *
SpfTerm_new(SpfTermParamType param_type)
{
    size_t contentsize;
    switch (param_type) {
    case SPF_TERM_PARAM_NONE:
        contentsize = 0;
        break;
    case SPF_TERM_PARAM_DOMAINSPEC:
        contentsize = 0;
        break;
    case SPF_TERM_PARAM_IP4:
        contentsize = sizeof(struct in_addr);
        break;
    case SPF_TERM_PARAM_IP6:
        contentsize = sizeof(struct in6_addr);
        break;
    default:
        abort();
    }   // end switch
    SpfTerm *self = (SpfTerm *) malloc(sizeof(SpfTerm) + contentsize);
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(SpfTerm) + contentsize);
    return self;
}   // end function: SpfTerm_new

static void
SpfTerm_free(SpfTerm *self)
{
    if (NULL == self) {
        return;
    }   // end if

    if (SPF_TERM_PARAM_DOMAINSPEC == self->attr->param_type && NULL != self->param.domain) {
        free(self->param.domain);
    }   // end if
    free(self);
}   // end function: SpfTerm_free

static const SpfTermAttribute *
SpfRecord_lookupMechanismAttribute(const char *head, const char *tail)
{
    const struct SpfTermAttribute *q;
    for (q = spf_mech_attr_table; NULL != q->name; ++q) {
        /*
         * [RFC4408] 4.6.1.
         * As per the definition of the ABNF notation in [RFC4234], mechanism
         * and modifier names are case-insensitive.
         */
        const char *mech_tail;
        if (0 < XSkip_casestring(head, tail, q->name, &mech_tail) && mech_tail == tail) {
            return q;
        }   // end if
    }   // end for
    return NULL;
}   // end function: SpfRecord_lookupMechanismAttribute

static const SpfTermAttribute *
SpfRecord_lookupModifierAttribute(const char *head, const char *tail)
{
    const struct SpfTermAttribute *q;
    for (q = spf_mod_attr_table; NULL != q->name; ++q) {
        /*
         * [RFC4408] 4.6.1.
         * As per the definition of the ABNF notation in [RFC4234], mechanism
         * and modifier names are case-insensitive.
         */
        const char *mod_tail;
        if (0 < XSkip_casestring(head, tail, q->name, &mod_tail) && mod_tail == tail) {
            return q;
        }   // end if
    }   // end for
    return NULL;
}   // end function: SpfRecord_lookupModifierAttribute

/**
 * @param head メカニズムの直後を指すポインタ
 */
static SpfStat
SpfRecord_buildTerm(SpfRecord *self, const char *head, const char *tail,
                    const SpfTermAttribute *termattr, SpfQualifier qualifier)
{
    SpfTerm *term = SpfTerm_new(termattr->param_type);
    if (NULL == term) {
        LogNoResource();
        return SPF_STAT_NO_RESOURCE;
    }   // end if
    term->attr = termattr;
    const char *param_tail;

    // parse cidr-length
    SpfStat cidr_stat = SpfRecord_parseCidrLength(termattr->cidr, head, tail, term, &param_tail);
    switch (cidr_stat) {
    case SPF_STAT_RECORD_INVALID_CIDR_LENGTH:
        SpfTerm_free(term);
        return cidr_stat;
    case SPF_STAT_OK:
    case SPF_STAT_RECORD_NOT_MATCH:    // cidr-length は全てオプショナルなので失敗してもパースは続行する.
        break;
    default:
        abort();
    }   // end switch

    // parse target-name
    const char *param_head = head;
    if ('\0' != termattr->parameter_delimiter && SPF_TERM_PARAM_NONE != termattr->param_type) {
        if (0 < XSkip_char(param_head, param_tail, termattr->parameter_delimiter, &param_head)) {
            // パラメーターが指定されている場合
            SpfStat parse_stat =
                SpfRecord_parseTermTargetName(self, termattr->param_type, param_head, param_tail,
                                              term, &param_head);
            if (SPF_STAT_OK != parse_stat) {
                SpfTerm_free(term);
                return parse_stat;
            }   // end if
        } else {
            // no parameter is specified
            if (termattr->required_parameter) {
                // 必須のパラメーターが指定されていない
                SpfLogPermFail("parameter missing: domain=%s, %s=%s, near=[%.*s]", self->domain,
                               termattr->is_mechanism ? "mech" : "mod", termattr->name,
                               (int) (tail - head), head);
                SpfTerm_free(term);
                return SPF_STAT_RECORD_SYNTAX_VIOLATION;
            }   // end if
        }   // end if
    }   // end if

    // mechanism に余りがないか確認
    if (param_head != param_tail) {
        SpfLogParseTrace("  => parse failed: [%.*s]\n", tail - head, head);
        SpfLogPermFail("unparsable term: domain=%s, %s=%s, near=[%.*s]",
                       self->domain, termattr->is_mechanism ? "mech" : "mod", termattr->name,
                       (int) (tail - param_head), param_head);
        SpfTerm_free(term);
        return SPF_STAT_RECORD_SYNTAX_VIOLATION;
    }   // end if

    if (termattr->is_mechanism) {
        SpfLogParseTrace("    type: mechanism\n");
        term->qualifier = (SPF_QUALIFIER_NULL != qualifier) ? qualifier : SPF_QUALIFIER_PLUS;
        SpfLogParseTrace("    qualifier: %d\n", qualifier);
        if (0 > PtrArray_append(self->directives, term)) {
            LogNoResource();
            SpfTerm_free(term);
            return SPF_STAT_NO_RESOURCE;
        }   // end if
    } else {
        SpfLogParseTrace("    type: modifier\n");
        /*
         * "redirect", "exp" が同一レコード中で複数回指定されている場合は
         * SPF, SID 共に PermError.
         *
         * [RFC4408] 6.
         * The modifiers defined in this document ("redirect" and "exp") MAY
         * appear anywhere in the record, but SHOULD appear at the end, after
         * all mechanisms.  Ordering of these two modifiers does not matter.
         * These two modifiers MUST NOT appear in a record more than once each.
         * If they do, then check_host() exits with a result of "PermError".
         *
         * [RFC4406] 3.3.
         * The modifiers "redirect" and "exp" described in Section 6 of
         * [RFC4408] are global and singular.
         */
        term->qualifier = SPF_QUALIFIER_NULL;
        switch (termattr->type) {
        case SPF_TERM_MOD_REDIRECT:
            if (NULL != self->modifiers.rediect) {
                SpfLogPermFail("redirect modifier specified repeatedly: domain=%s, near=[%.*s]",
                               self->domain, (int) (tail - head), head);
                SpfTerm_free(term);
                return SPF_STAT_RECORD_SYNTAX_VIOLATION;
            }   // end if
            self->modifiers.rediect = term;
            break;
        case SPF_TERM_MOD_EXPLANATION:
            if (NULL != self->modifiers.exp) {
                SpfLogPermFail("exp modifier specified repeatedly: domain=%s, near=[%.*s]",
                               self->domain, (int) (tail - head), head);
                SpfTerm_free(term);
                return SPF_STAT_RECORD_SYNTAX_VIOLATION;
            }   // end if
            self->modifiers.exp = term;
            break;
        case SPF_TERM_MOD_UNKNOWN:
            // SpfRecord_parseTerms() 内で処理されるのでここは通らないハズ
            SpfTerm_free(term);
            break;
        default:
            abort();
        }   // end switch
    }   // end if

    return SPF_STAT_OK;
}   // end function: SpfRecord_parseTermParam

static SpfStat
SpfRecord_parse(SpfRecord *self, const char *head, const char *tail)
{
    const char *term_head = head;
    const char *term_tail = NULL;
    while (true) {
        // SP (0x20) を目標に directive の切れ目を探す
        term_tail = strpchr(term_head, tail, ' ');
        if (NULL == term_tail) {
            term_tail = tail;
        }   // end if

        const char *mech_head, *mech_tail, *dummy;
        SpfQualifier qualifier = SpfRecord_parseQualifier(term_head, term_tail, &mech_head);
        XSkip_spfName(mech_head, term_tail, &mech_tail);
        const SpfTermAttribute *termattr;
        if (0 == XSkip_char(mech_tail, term_tail, '=', &dummy)) {
            // '=' が続かない場合は mechanism
            termattr = SpfRecord_lookupMechanismAttribute(mech_head, mech_tail);
            if (NULL == termattr) {
                SpfLogPermFail("unsupported mechanism: domain=%s, near=[%.*s]", self->domain,
                               (int) (term_tail - term_head), term_head);
                return SPF_STAT_RECORD_UNSUPPORTED_MECHANISM;
            }   // end if
        } else if (SPF_QUALIFIER_NULL == qualifier) {
            // qualifier が付いていない場合は modifer
            termattr = SpfRecord_lookupModifierAttribute(mech_head, mech_tail);
            if (NULL == termattr) {
                /*
                 * ignore unrecognized modifiers
                 * [RFC4408] 6.
                 * Unrecognized modifiers MUST be ignored no matter where in a record,
                 * or how often.  This allows implementations of this document to
                 * gracefully handle records with modifiers that are defined in other
                 * specifications.
                 */
                LogDebug("unknown modifier (ignored): domain=%s, near=[%.*s]", self->domain,
                         (int) (term_tail - term_head), term_head);
            }   // end if
        } else {
            // qualifier が付いていて, '=' が続かない場合は構文違反
            SpfLogPermFail("invalid term: domain=%s, near=[%.*s]",
                           self->domain, (int) (term_tail - term_head), term_head);
            return SPF_STAT_RECORD_SYNTAX_VIOLATION;
        }   // end if

        if (NULL != termattr) {
            SpfLogParseTrace("  term: %.*s\n", mech_tail - term_head, term_head);
            SpfStat parse_stat =
                SpfRecord_buildTerm(self, mech_tail, term_tail, termattr, qualifier);
            if (SPF_STAT_OK != parse_stat) {
                return parse_stat;
            }   // end if
        } else {
            // termattr が NULL になるのは unknown modifier に遭遇した場合のみ.
            // unknown modifier は無視する仕様なので何もしない
        }   // end if

        if (0 >= XSkip_spBlock(term_tail, tail, &term_head) || term_head == tail) {
            // レコードの終端に達したか予期しない文字に遭遇
            break;
        }   // end if
    }   // end while

    // 余りがないか確認する
    if (term_head == tail) {
        return SPF_STAT_OK;
    } else {
        // abort parsing the record
        SpfLogPermFail("unparsable term: domain=%s, near=[%.*s]",
                       self->domain, (int) (tail - term_head), term_head);
        return SPF_STAT_RECORD_SYNTAX_VIOLATION;
    }   // end if
}   // end function: SpfRecord_parseTerms

/**
 * release SpfRecord object
 * @param self SpfRecord object to release
 */
void
SpfRecord_free(SpfRecord *self)
{
    if (NULL == self) {
        return;
    }   // end if

    PtrArray_free(self->directives);
    SpfTerm_free(self->modifiers.rediect);
    SpfTerm_free(self->modifiers.exp);
    free(self);
}   // end function: SpfRecord_free

/**
 * create SpfRecord object
 * @return initialized SpfRecord object, or NULL if memory allocation failed.
 */
static SpfRecord *
SpfRecord_new(const SpfEvaluator *evaluator)
{
    SpfRecord *self = (SpfRecord *) malloc(sizeof(SpfRecord));
    if (NULL == self) {
        LogNoResource();
        return NULL;
    }   // end if
    memset(self, 0, sizeof(SpfRecord));
    self->directives = PtrArray_new(0, (void (*)(void *)) SpfTerm_free);
    if (NULL == self->directives) {
        LogNoResource();
        goto cleanup;
    }   // end if
    self->evaluator = evaluator;

    return self;

  cleanup:
    SpfRecord_free(self);
    return NULL;
}   // end function: SpfRecord_new

/**
 * SPFレコードのスコープを除いた部分をパースして, SpfRecord オブジェクトを構築する.
 * @param scope 構築する SpfRecord オブジェクトに設定するスコープ.
 *              ここで指定するスコープとレコードの実際のスコープとの一貫性は呼び出し側が保証する必要がある.
 */
SpfStat
SpfRecord_build(const SpfEvaluator *evaluator, SpfRecordScope scope, const char *record_head,
                const char *record_tail, SpfRecord **recordobj)
{
    assert(NULL != evaluator);
    assert(NULL != record_head);
    assert(NULL != record_tail);
    assert(NULL != recordobj);

    LogDebug("Record: %s [%.*s]",
             NULL != evaluator ? SpfEvaluator_getDomain(evaluator) : "(null)",
             (int) (record_tail - record_head), record_head);

    SpfRecord *self = SpfRecord_new(evaluator);
    if (NULL == self) {
        LogNoResource();
        return SPF_STAT_NO_RESOURCE;
    }   // end if
    self->domain = SpfEvaluator_getDomain(evaluator);
    self->scope = scope;

    SpfStat build_stat = SpfRecord_parse(self, record_head, record_tail);
    if (SPF_STAT_OK == build_stat) {
        *recordobj = self;
    } else {
        SpfRecord_free(self);
    }   // end if
    return build_stat;
}   // end function: SpfRecord_build

/**
 * 指定した SPF/SIDF レコードのスコープを取得する.
 * スコープを取得できた場合はそのスコープを, 取得できなかった場合は
 * SPF_RECORD_SCOPE_NULL を scope にセットする.
 */
SpfStat
SpfRecord_getSpfScope(const char *record_head,
                      const char *record_tail, SpfRecordScope *scope, const char **scope_tail)
{
    SpfStat parse_stat = SpfRecord_parseVersion(record_head, record_tail, scope_tail, scope);
    if (SPF_STAT_OK != parse_stat) {
        return parse_stat;
    }   // end if

    // version の次の文字が SP かレコードの終端であることを確認
    if (*scope_tail == record_tail || 0 < XSkip_spBlock(*scope_tail, record_tail, scope_tail)) {
        return SPF_STAT_OK;
    } else {
        *scope = SPF_RECORD_SCOPE_NULL;
        return SPF_STAT_RECORD_SYNTAX_VIOLATION;
    }   //end if
}   // end function: SpfRecord_getSpfScope
