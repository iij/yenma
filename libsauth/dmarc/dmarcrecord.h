/*
 * Copyright (c) 2012-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __DMARC_RECORD_H__
#define __DMARC_RECORD_H__

#include <stdbool.h>
#include <stdint.h>

#include "dnsresolv.h"
#include "dkim.h"
#include "dmarc.h"
#include "dmarcenum.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DmarcRecord DmarcRecord;

extern DkimStatus DmarcRecord_build(const char *domain, const char *keyval, DmarcRecord **dmarc_record);
extern void DmarcRecord_free(DmarcRecord *self);
extern DkimStatus DmarcRecord_discover(const char *authordomain, const PublicSuffix *public_suffix,
                                       DnsResolver *resolver, DmarcRecord **dmarc_record);
extern const char *DmarcRecord_getDomain(const DmarcRecord *self);
extern DmarcReceiverPolicy DmarcRecord_getReceiverPolicy(const DmarcRecord *self);
extern DmarcReceiverPolicy DmarcRecord_getSubdomainPolicy(const DmarcRecord *self);
extern DmarcAlignmentMode DmarcRecord_getSpfAlignmentMode(const DmarcRecord *self);
extern DmarcAlignmentMode DmarcRecord_getDkimAlignmentMode(const DmarcRecord *self);
extern uint8_t DmarcRecord_getSamplingRate(const DmarcRecord *self);

#ifdef __cplusplus
}
#endif

#endif /* __DMARC_RECORD_H__ */
