/*
 * Copyright (c) 2007-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __SPF_RECORD_H__
#define __SPF_RECORD_H__

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ptrarray.h"
#include "xbuffer.h"
#include "spf.h"
#include "spfenum.h"
#include "spfevaluator.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum SpfTermCidrOption {
    SPF_TERM_CIDR_OPTION_NONE,
    SPF_TERM_CIDR_OPTION_IP4,
    SPF_TERM_CIDR_OPTION_IP6,
    SPF_TERM_CIDR_OPTION_DUAL
} SpfTermCidrOption;

typedef struct SpfTermAttribute {
    const char *name;
    SpfTermType type;
    bool is_mechanism;
    SpfTermParamType param_type;
    bool involve_dnslookup;
    const char parameter_delimiter;
    bool required_parameter;
    SpfTermCidrOption cidr;
} SpfTermAttribute;

typedef struct SpfTerm {
    SpfQualifier qualifier;
    const SpfTermAttribute *attr;
    unsigned short ip4cidr;
    unsigned short ip6cidr;
    union {
        struct in_addr addr4;
        struct in6_addr addr6;
        char *domain;
    } param;
    // DNS query を投げるための 253 文字以下に丸めたドメイン.
    // param.domain 内のどこかへの参照を保持し, 通常は先頭を指す.
    // RFC4408 (8.1.) defines this as 253.
    const char *querydomain;
} SpfTerm;

typedef struct SpfRecord {
    // マクロを展開してから保持する選択をしたので, リクエストに依存するのは避けられない
    const SpfEvaluator *evaluator;
    SpfRecordScope scope;
    const char *domain;
    PtrArray *directives;
    struct spf_modifiers {
        SpfTerm *rediect;
        SpfTerm *exp;
    } modifiers;
    // PtrArray *modifiers;
} SpfRecord;

extern SpfStat SpfRecord_build(const SpfEvaluator *evaluator, SpfRecordScope scope,
                               const char *record_head, const char *record_tail,
                               SpfRecord **recordobj);
extern void SpfRecord_free(SpfRecord *self);
extern SpfStat SpfRecord_getSpfScope(const char *record_head,
                                     const char *record_tail, SpfRecordScope *scope,
                                     const char **scope_tail);

#ifdef __cplusplus
}
#endif

#endif /* __SPF_RECORD_H__ */
