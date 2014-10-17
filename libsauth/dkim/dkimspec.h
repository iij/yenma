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

// Constants defined in RFC6376, RFC5617

#ifndef __DKIM_SPEC_H__
#define __DKIM_SPEC_H__

// header field name of DKIM signature header
#define DKIM_SIGNHEADER     "DKIM-Signature"

// DNS namespace literal to look up DKIM public key records
#define DKIM_DNS_NAMESPACE  "_domainkey"

// DNS namespace literal to look up ADSP records
#define DKIM_DNS_ADSP_SELECTOR  "_adsp"

// DNS namespace literal to look up ATPS records
#define DKIM_DNS_ATPS_SELECTOR  "_atps"

// version string of DKIM public key records
#define DKIM1_VERSION_TAG   "DKIM1"

// version string of DKIM ATPS records
#define ATPS1_VERSION_TAG   "ATPS1"

// max length of sig-l-tag value
#define DKIM_SIG_L_TAG_LEN  76
// max length of sig-t-tag value
#define DKIM_SIG_T_TAG_LEN  12
// max length of sig-x-tag value
#define DKIM_SIG_X_TAG_LEN  12

#endif /* __DKIM_SPEC_H__ */
