/*
 * Copyright (c) 2008-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __SPF_EVAL_POLICY_H__
#define __SPF_EVAL_POLICY_H__

#include <stdbool.h>
#include "spf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct SpfEvalPolicy {
    // whether to lookup SPF RR (type 99).
    // This feature was obsoleted by RFC7208
    bool lookup_spf_rr;
    // whether to lookup explanation
    bool lookup_exp;
    // domain name of host performing the check (to expand "r" macro)
    char *checking_domain;
    // マクロ展開の際, 展開過程を中断する長さの閾値
    unsigned int macro_expansion_limit;
    // SPFレコード中のどのメカニズムにもマッチしなかった場合, Neutral を返す前にこのレコードの評価を挟む
    // 評価されるタイミングは redirect modifier が存在しなかった場合
    char *local_policy;
    // local_policy によって "Fail" になった場合に使用する explanation を設定する. マクロ使用可.
    char *local_policy_explanation;
    // the maximum limit of mechanisms which involves DNS lookups per an evaluation.
    // RFC4408 defines this as 10.
    // Do not modify this unless you know exactly what you're doing.
    unsigned int max_dns_mech;
    // check_host() 関数の <domain> 引数に含まれる label の最大長, RFC4408 defines this as 63.
    unsigned int max_label_len;
    // mx メカニズム評価中に1回のMXレコードのルックアップに対するレスポンスとして受け取るRRの最大数
    // RFC4408 defines this as 10.
    // Do not modify this unless you know exactly what you're doing.
    unsigned int max_mxrr_per_mxmech;
    // ptr メカニズム評価中に1回のPTRレコードのルックアップに対するレスポンスとして受け取るRRの最大数
    // RFC4408 defines this as 10.
    // Do not modify this unless you know exactly what you're doing.
    unsigned int max_ptrrr_per_ptrmech;
    // the number of permitted "void lookups".
    // A negative value means unlimited.
    // RFC7208 recommends this as 2.
    // Do not modify this unless you know exactly what you're doing.
    int void_lookup_limit;
    // "all" メカニズムにどんな qualifier が付いていようとスコアを上書きする.
    // SPF_SCORE_NULL の場合は通常動作 (レコードに書かれている qualifier を使用)
    SpfScore overwrite_all_directive_score;
    // action on encountering "+all" directives
    SpfCustomAction action_on_plus_all_directive;
    // action on encountering malicious "ip4-cidr-length"
    SpfCustomAction action_on_malicious_ip4_cidr_length;
    // action on encountering malicious "ip6-cidr-length"
    SpfCustomAction action_on_malicious_ip6_cidr_length;
    // threshold of handling "ip4-cidr-length" as malicious
    unsigned char malicious_ip4_cidr_length;
    // threshold of handling "ip6-cidr-length" as malicious
    unsigned char malicious_ip6_cidr_length;
};

#ifdef __cplusplus
}
#endif

#endif /* __SPF_EVAL_POLICY_H__ */
