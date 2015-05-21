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

#ifndef __VALIDATED_RESULT_H__
#define __VALIDATED_RESULT_H__

#include <stdbool.h>

#include "spf.h"
#include "dkim.h"
#include "dmarc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ValidatedResult {
    bool spf_eval_by_sender;    // SPF の検証に EnvFrom を使ったか HELO を使ったか (HELOの場合 false)
    union spf_eval_address {    // SPF の検証に利用したアドレス
        InetMailbox *envfrom;   // EnvFrom
        char *helohost;         // HELO
    } spf_eval_address;
    InetMailbox *dkim_eval_address; // DKIM の検証に利用したアドレス
    SpfScore spf_score;
    SpfScore sidf_score;
    DkimBaseScore dkim_score;   // DKIM のスコア (DKIM は署名が複数存在する可能性があるのでとりあえず先頭のスコアを使用する)
    DkimAdspScore dkim_adsp_score;
    DkimAtpsScore dkim_atps_score;
    DmarcScore dmarc_score;
} ValidatedResult;

extern ValidatedResult *ValidatedResult_new(void);
extern void ValidatedResult_reset(ValidatedResult *self);
extern void ValidatedResult_free(ValidatedResult *self);

#ifdef __cplusplus
}
#endif

#endif /* __VALIDATED_RESULT_H__ */
