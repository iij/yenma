/*
 * Copyright (c) 2012-2014 Internet Initiative Japan Inc. All rights reserved.
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
#include "dmarc.h"
#include "dmarcenum.h"

static const KeywordMap dmarc_score_table[] = {
    {"none", DMARC_SCORE_NONE},
    {"pass", DMARC_SCORE_PASS},
    {"bestguesspass", DMARC_SCORE_BESTGUESSPASS},
    {"fail", DMARC_SCORE_FAIL},
    {"policy", DMARC_SCORE_POLICY},
    {"temperror", DMARC_SCORE_TEMPERROR},
    {"permerror", DMARC_SCORE_PERMERROR},
    {NULL, DMARC_SCORE_NULL},
};

static const KeywordMap dmarc_alignment_mode_table[] = {
    {"r", DMARC_ALIGN_MODE_RELAXED},
    {"s", DMARC_ALIGN_MODE_STRICT},
    {NULL, DMARC_ALIGN_MODE_NULL},
};

static const KeywordMap dmarc_receiver_policy_table[] = {
    {"none", DMARC_RECEIVER_POLICY_NONE},
    {"quarantine", DMARC_RECEIVER_POLICY_QUARANTINE},
    {"reject", DMARC_RECEIVER_POLICY_REJECT},
    {NULL, DMARC_RECEIVER_POLICY_NULL},
};

static const KeywordMap dmarc_report_format_table[] = {
    {"afrf", DMARC_REPORT_FORMAT_AFRF},
    {"iodef", DMARC_REPORT_FORMAT_IODEF},
    {NULL, DMARC_REPORT_FORMAT_NULL},
};

static const KeywordMap dmarc_failure_reporting_option_table[] = {
    {"0", DMARC_REPORT_OPTION_ALL},
    {"1", DMARC_REPORT_OPTION_ANY},
    {"d", DMARC_REPORT_OPTION_DKIM},
    {"s", DMARC_REPORT_OPTION_SPF},
    {NULL, DMARC_REPORT_OPTION_NULL},
};

/*
 * [RFC6376] 3.2.
 * Tags MUST be interpreted in a case-sensitive manner.  Values MUST be
 * processed as case sensitive unless the specific tag description of
 * semantics specifies case insensitivity.
 */

////////////////////////////////////////////////////////////

DmarcScore
DmarcEnum_lookupScoreByName(const char *keyword)
{
    return (DmarcScore) KeywordMap_lookupByCaseString(dmarc_score_table, keyword);
}   // end function: DmarcEnum_lookupScoreByName

DmarcScore
DmarcEnum_lookupScoreByNameSlice(const char *head, const char *tail)
{
    return (DmarcScore) KeywordMap_lookupByCaseStringSlice(dmarc_score_table, head, tail);
}   // end function: DmarcEnum_lookupScoreByNameSlice

const char *
DmarcEnum_lookupScoreByValue(DmarcScore value)
{
    return KeywordMap_lookupByValue(dmarc_score_table, value);
}   // end function: DmarcEnum_lookupScoreByValue

////////////////////////////////////////////////////////////

DmarcAlignmentMode
DmarcEnum_lookupAlignmentModeByName(const char *keyword)
{
    return (DmarcAlignmentMode) KeywordMap_lookupByCaseString(dmarc_alignment_mode_table, keyword);
}   // end function: DmarcEnum_lookupAlignmentModeByName

DmarcAlignmentMode
DmarcEnum_lookupAlignmentModeByNameSlice(const char *head, const char *tail)
{
    return (DmarcAlignmentMode) KeywordMap_lookupByCaseStringSlice(dmarc_alignment_mode_table, head,
                                                                   tail);
}   // end function: DmarcEnum_lookupAlignmentModeByNameSlice

const char *
DmarcEnum_lookupAlignmentModeByValue(DmarcAlignmentMode value)
{
    return KeywordMap_lookupByValue(dmarc_alignment_mode_table, value);
}   // end function: DmarcEnum_lookupAlignmentModeByValue

////////////////////////////////////////////////////////////

DmarcReceiverPolicy
DmarcEnum_lookupReceiverPolicyByName(const char *keyword)
{
    return (DmarcReceiverPolicy) KeywordMap_lookupByCaseString(dmarc_receiver_policy_table,
                                                               keyword);
}   // end function: DmarcEnum_lookupReceiverPolicyByName

DmarcReceiverPolicy
DmarcEnum_lookupReceiverPolicyByNameSlice(const char *head, const char *tail)
{
    return (DmarcReceiverPolicy) KeywordMap_lookupByCaseStringSlice(dmarc_receiver_policy_table,
                                                                    head, tail);
}   // end function: DmarcEnum_lookupReceiverPolicyByNameSlice

const char *
DmarcEnum_lookupReceiverPolicyByValue(DmarcReceiverPolicy value)
{
    return KeywordMap_lookupByValue(dmarc_receiver_policy_table, value);
}   // end function: DmarcEnum_lookupReceiverPolicyByValue

////////////////////////////////////////////////////////////

DmarcReportFormat
DmarcEnum_lookupReportFormatByName(const char *keyword)
{
    return (DmarcReportFormat) KeywordMap_lookupByCaseString(dmarc_report_format_table, keyword);
}   // end function: DmarcEnum_lookupReportFormatByName

DmarcReportFormat
DmarcEnum_lookupReportFormatByNameSlice(const char *head, const char *tail)
{
    return (DmarcReportFormat) KeywordMap_lookupByCaseStringSlice(dmarc_report_format_table, head,
                                                                  tail);
}   // end function: DmarcEnum_lookupReportFormatByNameSlice

const char *
DmarcEnum_lookupReportFormatByValue(DmarcReportFormat value)
{
    return KeywordMap_lookupByValue(dmarc_report_format_table, value);
}   // end function: DmarcEnum_lookupReportFormatByValue

////////////////////////////////////////////////////////////

DmarcReportingOption
DmarcEnum_lookupReportingOptionByName(const char *keyword)
{
    return (DmarcReportingOption)
        KeywordMap_lookupByCaseString(dmarc_failure_reporting_option_table, keyword);
}   // end function: DmarcEnum_lookupFailureReportingOptionByName

DmarcReportingOption
DmarcEnum_lookupReportingOptionByNameSlice(const char *head, const char *tail)
{
    return (DmarcReportingOption)
        KeywordMap_lookupByCaseStringSlice(dmarc_failure_reporting_option_table, head, tail);
}   // end function: DmarcEnum_lookupFailureReportingOptionByNameSlice

const char *
DmarcEnum_lookupReportingOptionByValue(DmarcReportingOption value)
{
    return KeywordMap_lookupByValue(dmarc_failure_reporting_option_table, value);
}   // end function: DmarcEnum_lookupFailureReportingOptionByValue

////////////////////////////////////////////////////////////
