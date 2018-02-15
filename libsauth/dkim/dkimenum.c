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

#include <stdio.h>
#include <string.h>

#include "xskip.h"
#include "keywordmap.h"
#include "dkim.h"
#include "dkimtaglistobject.h"
#include "dkimenum.h"

typedef struct DkimStatusMap {
    DkimStatus code;
    const char *string;
} DkimStatusMap;

static const KeywordMap dkim_c14n_algorithm_table[] = {
    {"simple", DKIM_C14N_ALGORITHM_SIMPLE},
    {"relaxed", DKIM_C14N_ALGORITHM_RELAXED},
    {"nowsp", DKIM_C14N_ALGORITHM_NOWSP},   // obsolete
    {NULL, DKIM_C14N_ALGORITHM_NULL},
};

static const KeywordMap dkim_key_type_table[] = {
    {"rsa", DKIM_KEY_TYPE_RSA},
    // [draft-ietf-dcrup-dkim-crypto-08] 4.1.
    // sig-a-tag-k =/ "ed25519"
    {"ed25519", DKIM_KEY_TYPE_ED25519},
    {NULL, DKIM_KEY_TYPE_NULL},
};

static const KeywordMap dkim_hash_algorithm_table[] = {
    {"sha1", DKIM_HASH_ALGORITHM_SHA1},
    {"sha256", DKIM_HASH_ALGORITHM_SHA256},
    {NULL, DKIM_HASH_ALGORITHM_NULL},
};

static const KeywordMap dkim_atps_hash_algorithm_table[] = {
    {"none", DKIM_HASH_ALGORITHM_NONE},
    {"sha1", DKIM_HASH_ALGORITHM_SHA1},
    {"sha256", DKIM_HASH_ALGORITHM_SHA256},
    {NULL, DKIM_HASH_ALGORITHM_NULL},
};

static const KeywordMap dkim_service_type_table[] = {
    {"*", DKIM_SERVICE_TYPE_ANY},
    {"email", DKIM_SERVICE_TYPE_EMAIL},
    {NULL, DKIM_SERVICE_TYPE_NULL},
};

static const KeywordMap dkim_selector_flag_table[] = {
    {"y", DKIM_SELECTOR_FLAG_TESTING},
    {"s", DKIM_SELECTOR_FLAG_PROHIBIT_SUBDOMAIN},
    {NULL, DKIM_SELECTOR_FLAG_NULL},
};

static const KeywordMap dkim_query_method_table[] = {
    {"dns/txt", DKIM_QUERY_METHOD_DNS_TXT},
    // {"dns/dkk", DKIM_QUERYMETHOD_DNS_DKK},
    {"dns", DKIM_QUERY_METHOD_DNS_TXT}, // for backward compatibility
    {NULL, DKIM_QUERY_METHOD_NULL},
};

static const KeywordMap dkim_practice_table[] = {
    {"unknown", DKIM_ADSP_PRACTICE_UNKNOWN},
    {"all", DKIM_ADSP_PRACTICE_ALL},
    {"discardable", DKIM_ADSP_PRACTICE_DISCARDABLE},
    {NULL, DKIM_ADSP_PRACTICE_NULL},
};

static const KeywordMap dkim_score_table[] = {
    {"none", DKIM_BASE_SCORE_NONE},
    {"pass", DKIM_BASE_SCORE_PASS},
    {"fail", DKIM_BASE_SCORE_FAIL},
    {"policy", DKIM_BASE_SCORE_POLICY},
    {"neutral", DKIM_BASE_SCORE_NEUTRAL},
    {"temperror", DKIM_BASE_SCORE_TEMPERROR},
    {"permerror", DKIM_BASE_SCORE_PERMERROR},
    {NULL, DKIM_BASE_SCORE_NULL},
};

static const KeywordMap dkim_adsp_score_table[] = {
    {"none", DKIM_ADSP_SCORE_NONE},
    {"pass", DKIM_ADSP_SCORE_PASS},
    {"unknown", DKIM_ADSP_SCORE_UNKNOWN},
    {"fail", DKIM_ADSP_SCORE_FAIL},
    {"discard", DKIM_ADSP_SCORE_DISCARD},
    {"nxdomain", DKIM_ADSP_SCORE_NXDOMAIN},
    {"temperror", DKIM_ADSP_SCORE_TEMPERROR},
    {"permerror", DKIM_ADSP_SCORE_PERMERROR},
    {NULL, DKIM_ADSP_SCORE_NULL},
};

static const KeywordMap dkim_atps_score_table[] = {
    {"none", DKIM_ATPS_SCORE_NONE},
    {"pass", DKIM_ATPS_SCORE_PASS},
    {"fail", DKIM_ATPS_SCORE_FAIL},
    {"temperror", DKIM_ATPS_SCORE_TEMPERROR},
    {"permerror", DKIM_ATPS_SCORE_PERMERROR},
    {NULL, DKIM_ATPS_SCORE_NULL},
};

static const DkimStatusMap dstat_description_table[] = {
    {DSTAT_TMPERR_DNS_ERROR_RESPONSE, "key unavailable"},
    {DSTAT_PERMFAIL_SIGNATURE_DID_NOT_VERIFY, "signature did not verify"},
    {DSTAT_PERMFAIL_BODY_HASH_DID_NOT_VERIFY, "body hash did not verify"},
    {DSTAT_PERMFAIL_SIGNATURE_SYNTAX_VIOLATION, "signature syntax error"},
    {DSTAT_PERMFAIL_KEY_SYNTAX_VIOLATION, "key syntax error"},
    {DSTAT_PERMFAIL_MISSING_REQUIRED_TAG, "signature missing required tag"},
    {DSTAT_PERMFAIL_SIGNATURE_INCOMPATIBLE_VERSION, "incompatible version"},
    {DSTAT_PERMFAIL_DOMAIN_MISMATCH, "domain mismatch"},
    {DSTAT_PERMFAIL_FROM_FIELD_NOT_SIGNED, "From field not signed"},
    {DSTAT_PERMFAIL_SIGNATURE_EXPIRED, "signature expired"},
    {DSTAT_PERMFAIL_NO_KEY_FOR_SIGNATURE, "no key for signature"},
    {DSTAT_PERMFAIL_KEY_REVOKED, "key revoked"},
    {DSTAT_PERMFAIL_INAPPROPRIATE_HASH_ALGORITHM, "inappropriate hash algorithm"},
    {DSTAT_PERMFAIL_INAPPROPRIATE_KEY_ALGORITHM, "inappropriate key algorithm"},
    {0, NULL},
};

/*
 * [RFC6376] 3.2.
 * Tags MUST be interpreted in a case-sensitive manner.  Values MUST be
 * processed as case sensitive unless the specific tag description of
 * semantics specifies case insensitivity.
 */

////////////////////////////////////////////////////////////

DkimC14nAlgorithm
DkimEnum_lookupC14nAlgorithmByName(const char *keyword)
{
    return (DkimC14nAlgorithm) KeywordMap_lookupByCaseString(dkim_c14n_algorithm_table, keyword);
}   // end function: DkimEnum_lookupC14nAlgorithmByName

DkimC14nAlgorithm
DkimEnum_lookupC14nAlgorithmByNameSlice(const char *head, const char *tail)
{
    return (DkimC14nAlgorithm) KeywordMap_lookupByCaseStringSlice(dkim_c14n_algorithm_table, head,
                                                                  tail);
}   // end function: DkimEnum_lookupC14nAlgorithmByNameSlice

const char *
DkimEnum_lookupC14nAlgorithmByValue(DkimC14nAlgorithm value)
{
    return KeywordMap_lookupByValue(dkim_c14n_algorithm_table, value);
}   // end function: DkimEnum_lookupC14nAlgorithmByValue

////////////////////////////////////////////////////////////

DkimKeyType
DkimEnum_lookupKeyTypeByName(const char *keyword)
{
    return (DkimKeyType) KeywordMap_lookupByCaseString(dkim_key_type_table, keyword);
}   // end function: DkimEnum_lookupKeyTypeByName

DkimKeyType
DkimEnum_lookupKeyTypeByNameSlice(const char *head, const char *tail)
{
    return (DkimKeyType) KeywordMap_lookupByCaseStringSlice(dkim_key_type_table, head, tail);
}   // end function: DkimEnum_lookupKeyTypeByNameSlice

const char *
DkimEnum_lookupKeyTypeByValue(DkimKeyType value)
{
    return KeywordMap_lookupByValue(dkim_key_type_table, value);
}   // end function: DkimEnum_lookupKeyTypeByValue

////////////////////////////////////////////////////////////

DkimHashAlgorithm
DkimEnum_lookupHashAlgorithmByName(const char *keyword)
{
    return (DkimHashAlgorithm) KeywordMap_lookupByCaseString(dkim_hash_algorithm_table, keyword);
}   // end function: DkimEnum_lookupHashAlgorithmByName

DkimHashAlgorithm
DkimEnum_lookupHashAlgorithmByNameSlice(const char *head, const char *tail)
{
    return (DkimHashAlgorithm) KeywordMap_lookupByCaseStringSlice(dkim_hash_algorithm_table, head,
                                                                  tail);
}   // end function: DkimEnum_lookupHashAlgorithmByNameSlice

const char *
DkimEnum_lookupHashAlgorithmByValue(DkimHashAlgorithm value)
{
    return KeywordMap_lookupByValue(dkim_hash_algorithm_table, value);
}   // end function: DkimEnum_lookupHashAlgorithmByValue

////////////////////////////////////////////////////////////

DkimHashAlgorithm
DkimEnum_lookupAtpsHashAlgorithmByName(const char *keyword)
{
    return (DkimHashAlgorithm) KeywordMap_lookupByCaseString(dkim_atps_hash_algorithm_table,
                                                             keyword);
}   // end function: DkimEnum_lookupAtpsHashAlgorithmByName

DkimHashAlgorithm
DkimEnum_lookupAtpsHashAlgorithmByNameSlice(const char *head, const char *tail)
{
    return (DkimHashAlgorithm) KeywordMap_lookupByCaseStringSlice(dkim_atps_hash_algorithm_table,
                                                                  head, tail);
}   // end function: DkimEnum_lookupAtpsHashAlgorithmByNameSlice

const char *
DkimEnum_lookupAtpsHashAlgorithmByValue(DkimHashAlgorithm value)
{
    return KeywordMap_lookupByValue(dkim_atps_hash_algorithm_table, value);
}   // end function: DkimEnum_lookupAtpsHashAlgorithmByValue

////////////////////////////////////////////////////////////

DkimServiceType
DkimEnum_lookupServiceTypeByName(const char *keyword)
{
    return (DkimServiceType) KeywordMap_lookupByCaseString(dkim_service_type_table, keyword);
}   // end function: DkimEnum_lookupServiceTypeByName

DkimServiceType
DkimEnum_lookupServiceTypeByNameSlice(const char *head, const char *tail)
{
    return (DkimServiceType) KeywordMap_lookupByCaseStringSlice(dkim_service_type_table, head,
                                                                tail);
}   // end function: DkimEnum_lookupServiceTypeByNameSlice

const char *
DkimEnum_lookupServiceTypeByValue(DkimServiceType value)
{
    return KeywordMap_lookupByValue(dkim_service_type_table, value);
}   // end function: DkimEnum_lookupServiceTypeByValue

////////////////////////////////////////////////////////////

DkimSelectorFlag
DkimEnum_lookupSelectorFlagByName(const char *keyword)
{
    return (DkimSelectorFlag) KeywordMap_lookupByCaseString(dkim_selector_flag_table, keyword);
}   // end function: DkimEnum_lookupSelectorFlagByName

DkimSelectorFlag
DkimEnum_lookupSelectorFlagByNameSlice(const char *head, const char *tail)
{
    return (DkimSelectorFlag) KeywordMap_lookupByCaseStringSlice(dkim_selector_flag_table, head,
                                                                 tail);
}   // end function: DkimEnum_lookupSelectorFlagByNameSlice

const char *
DkimEnum_lookupSelectorFlagByValue(DkimSelectorFlag value)
{
    return KeywordMap_lookupByValue(dkim_selector_flag_table, value);
}   // end function: DkimEnum_lookupSelectorFlagByValue

////////////////////////////////////////////////////////////

DkimQueryMethod
DkimEnum_lookupQueryMethodByName(const char *keyword)
{
    return (DkimQueryMethod) KeywordMap_lookupByCaseString(dkim_query_method_table, keyword);
}   // end function: DkimEnum_lookupQueryMethodByName

DkimQueryMethod
DkimEnum_lookupQueryMethodByNameSlice(const char *head, const char *tail)
{
    return (DkimQueryMethod) KeywordMap_lookupByCaseStringSlice(dkim_query_method_table, head,
                                                                tail);
}   // end function: DkimEnum_lookupQueryMethodByNameSlice

const char *
DkimEnum_lookupQueryMethodByValue(DkimQueryMethod value)
{
    return KeywordMap_lookupByValue(dkim_query_method_table, value);
}   // end function: DkimEnum_lookupQueryMethodByValue

////////////////////////////////////////////////////////////

DkimAdspPractice
DkimEnum_lookupPracticeByName(const char *keyword)
{
    return (DkimAdspPractice) KeywordMap_lookupByCaseString(dkim_practice_table, keyword);
}   // end function: DkimEnum_lookupPracticeByName

DkimAdspPractice
DkimEnum_lookupPracticeByNameSlice(const char *head, const char *tail)
{
    return (DkimAdspPractice) KeywordMap_lookupByCaseStringSlice(dkim_practice_table, head, tail);
}   // end function: DkimEnum_lookupPracticeByNameSlice

const char *
DkimEnum_lookupPracticeByValue(DkimAdspPractice value)
{
    return KeywordMap_lookupByValue(dkim_practice_table, value);
}   // end function: DkimEnum_lookupPracticeByValue

////////////////////////////////////////////////////////////

DkimBaseScore
DkimEnum_lookupScoreByName(const char *keyword)
{
    return (DkimBaseScore) KeywordMap_lookupByCaseString(dkim_score_table, keyword);
}   // end function: DkimEnum_lookupScoreByName

DkimBaseScore
DkimEnum_lookupScoreByNameSlice(const char *head, const char *tail)
{
    return (DkimBaseScore) KeywordMap_lookupByCaseStringSlice(dkim_score_table, head, tail);
}   // end function: DkimEnum_lookupScoreByNameSlice

const char *
DkimEnum_lookupScoreByValue(DkimBaseScore value)
{
    return KeywordMap_lookupByValue(dkim_score_table, value);
}   // end function: DkimEnum_lookupScoreByValue

////////////////////////////////////////////////////////////

DkimAdspScore
DkimEnum_lookupAdspScoreByName(const char *keyword)
{
    return (DkimAdspScore) KeywordMap_lookupByCaseString(dkim_adsp_score_table, keyword);
}   // end function: DkimEnum_lookupAdspScoreByName

DkimAdspScore
DkimEnum_lookupAdspScoreByNameSlice(const char *head, const char *tail)
{
    return (DkimAdspScore) KeywordMap_lookupByCaseStringSlice(dkim_adsp_score_table, head, tail);
}   // end function: DkimEnum_lookupAdspScoreByNameSlice

const char *
DkimEnum_lookupAdspScoreByValue(DkimAdspScore value)
{
    return KeywordMap_lookupByValue(dkim_adsp_score_table, value);
}   // end function: DkimEnum_lookupAdspScoreByValue

////////////////////////////////////////////////////////////

DkimAtpsScore
DkimEnum_lookupAtpsScoreByName(const char *keyword)
{
    return (DkimAtpsScore) KeywordMap_lookupByCaseString(dkim_atps_score_table, keyword);
}   // end function: DkimEnum_lookupAdspScoreByName

DkimAtpsScore
DkimEnum_lookupAtpsScoreByNameSlice(const char *head, const char *tail)
{
    return (DkimAtpsScore) KeywordMap_lookupByCaseStringSlice(dkim_atps_score_table, head, tail);
}   // end function: DkimEnum_lookupAtpsScoreByNameSlice

const char *
DkimEnum_lookupAtpsScoreByValue(DkimAtpsScore value)
{
    return KeywordMap_lookupByValue(dkim_atps_score_table, value);
}   // end function: DkimEnum_lookupAtpsScoreByValue

////////////////////////////////////////////////////////////

#define CODE2STRMAP(s) {s, #s}

static const DkimStatusMap dstat_code_name_table[] = {
#include "dstat.map"
    {0, NULL},
};

static const char *
DkimEnum_lookupDkimStatByValue(const DkimStatusMap *table, DkimStatus value)
{
    const DkimStatusMap *p;
    for (p = table; NULL != p->string; ++p) {
        if (p->code == value) {
            return p->string;
        }   // end if
    }   // end for
    return NULL;
}   // end function: DkimEnum_lookupDkimStatByValue

extern const char *
DkimStatus_getSymbol(DkimStatus code)
{
    const char *errstr = DkimEnum_lookupDkimStatByValue(dstat_code_name_table, code);
    return NULL != errstr ? errstr : "unexpected dkim status";
}   // end function: DkimStatus_getSymbol

////////////////////////////////////////////////////////////

extern const char *
DkimStatus_strerror(DkimStatus code)
{
    return DkimEnum_lookupDkimStatByValue(dstat_description_table, code);
}   // end function: DkimStatus_strerror
