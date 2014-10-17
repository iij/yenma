/*
 * Copyright (c) 2012,2013 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __DMARC_SPEC_H__
#define __DMARC_SPEC_H__

// header field name of From header (as Author)
#ifndef FROMHEADER
#define FROMHEADER          "From"
#endif

// DNS namespace literal to look up DMARC records
#define DMARC_RECORD_DNS_PREFIX  "_dmarc"

// version string of DMARC records
#define DMARC1_VERSION_TAG  "DMARC1"

// prefix of DMARC records
#define DMARC1_RECORD_PREFIX    "v=DMARC1"

// max length of dmarc-ainterval value
#define DMARC_REC_RI_TAG_LEN  12
// max length of dmarc-percent value
#define DMARC_REC_PCT_TAG_LEN  3

#endif /* __DMARC_SPEC_H__ */
