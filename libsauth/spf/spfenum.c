/*
 * Copyright (c) 2008-2014 Internet Initiative Japan Inc. All rights reserved.
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

#include "keywordmap.h"
#include "spf.h"
#include "spfenum.h"

static const KeywordMap spf_score_tbl[] = {
    {"none", SPF_SCORE_NONE},
    {"neutral", SPF_SCORE_NEUTRAL},
    {"pass", SPF_SCORE_PASS},
    {"policy", SPF_SCORE_POLICY},
    {"fail", SPF_SCORE_FAIL},
    {"hardfail", SPF_SCORE_FAIL},   // one way from string to value
    {"softfail", SPF_SCORE_SOFTFAIL},
    {"temperror", SPF_SCORE_TEMPERROR},
    {"permerror", SPF_SCORE_PERMERROR},
    {"syserror", SPF_SCORE_SYSERROR},   // logging use only, not as a final score
    {NULL, SPF_SCORE_NULL},
};

static const KeywordMap spf_classic_score_tbl[] = {
    {"none", SPF_SCORE_NONE},
    {"neutral", SPF_SCORE_NEUTRAL},
    {"pass", SPF_SCORE_PASS},
    {"policy", SPF_SCORE_POLICY},
    {"hardfail", SPF_SCORE_FAIL},
    {"fail", SPF_SCORE_FAIL},   // one way from string to value (and nonsense here)
    {"softfail", SPF_SCORE_SOFTFAIL},
    {"temperror", SPF_SCORE_TEMPERROR},
    {"permerror", SPF_SCORE_PERMERROR},
    {"syserror", SPF_SCORE_SYSERROR},   // logging use only, not as a final score
    {NULL, SPF_SCORE_NULL},
};

////////////////////////////////////////////////////////////

SpfScore
SpfEnum_lookupScoreByKeyword(const char *keyword)
{
    return (SpfScore) KeywordMap_lookupByCaseString(spf_score_tbl, keyword);
}   // end function: SpfEnum_lookupScoreByKeyword

SpfScore
SpfEnum_lookupScoreByKeywordSlice(const char *head, const char *tail)
{
    return (SpfScore) KeywordMap_lookupByCaseStringSlice(spf_score_tbl, head, tail);
}   // end function: SpfEnum_lookupScoreByKeywordSlice

const char *
SpfEnum_lookupScoreByValue(SpfScore value)
{
    return KeywordMap_lookupByValue(spf_score_tbl, value);
}   // end function: SpfEnum_lookupScoreByValue

/*
 * almost the same as SpfEnum_lookupScoreByValue except for returning "hardfail"
 * instead of "fail" when value is SPF_SCORE_FAIL (= SPF_SCORE_HARDFAIL)
 */
const char *
SpfEnum_lookupClassicScoreByValue(SpfScore value)
{
    return KeywordMap_lookupByValue(spf_classic_score_tbl, value);
}   // end function: SpfEnum_lookupClassicScoreByValue

////////////////////////////////////////////////////////////
