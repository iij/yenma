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

#ifndef __DMARC_ENUM_H__
#define __DMARC_ENUM_H__

typedef enum DmarcAlignmentMode {
    DMARC_ALIGN_MODE_NULL = 0,
    DMARC_ALIGN_MODE_RELAXED,
    DMARC_ALIGN_MODE_STRICT,
} DmarcAlignmentMode;

typedef enum DmarcReportFormat {
    DMARC_REPORT_FORMAT_NULL = 0,
    DMARC_REPORT_FORMAT_AFRF,
    DMARC_REPORT_FORMAT_IODEF,
} DmarcReportFormat;

typedef enum DmarcReportingOption {
    DMARC_REPORT_OPTION_NULL = 0,
    DMARC_REPORT_OPTION_ALL = 1 << 0,
    DMARC_REPORT_OPTION_ANY = 1 << 1,
    DMARC_REPORT_OPTION_DKIM = 1 << 2,
    DMARC_REPORT_OPTION_SPF = 1 << 3,
} DmarcReportingOption;

extern DmarcAlignmentMode DmarcEnum_lookupAlignmentModeByName(const char *keyword);
extern DmarcAlignmentMode DmarcEnum_lookupAlignmentModeByNameSlice(const char *head,
                                                                   const char *tail);
extern const char *DmarcEnum_lookupAlignmentModeByValue(DmarcAlignmentMode value);

extern DmarcReceiverPolicy DmarcEnum_lookupReceiverPolicyByName(const char *keyword);
extern DmarcReceiverPolicy DmarcEnum_lookupReceiverPolicyByNameSlice(const char *head,
                                                                     const char *tail);
extern const char *DmarcEnum_lookupReceiverPolicyByValue(DmarcReceiverPolicy value);

extern DmarcReportFormat DmarcEnum_lookupReportFormatByName(const char *keyword);
extern DmarcReportFormat DmarcEnum_lookupReportFormatByNameSlice(const char *head,
                                                                 const char *tail);
extern const char *DmarcEnum_lookupReportFormatByValue(DmarcReportFormat value);

extern DmarcReportingOption DmarcEnum_lookupReportingOptionByName(const char *keyword);
extern DmarcReportingOption DmarcEnum_lookupReportingOptionByNameSlice(const char *head,
                                                                       const char *tail);
extern const char *DmarcEnum_lookupReportingOptionByValue(DmarcReportingOption value);

#endif /* __DMARC_ENUM_H__ */
