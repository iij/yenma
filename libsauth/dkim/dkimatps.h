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

#ifndef __DKIM_ATPS_H__
#define __DKIM_ATPS_H__

#include <stdbool.h>
#include "dnsresolv.h"
#include "dkim.h"

typedef struct DkimAtps DkimAtps;

extern DkimStatus DkimAtps_build(const char *keyval, DkimAtps **atps_record);
extern DkimStatus DkimAtps_lookup(const char *atps_domain,
                                  const char *sdid, DkimHashAlgorithm hashalg,
                                  DnsResolver *resolver, DkimAtps **atps_record);
extern void DkimAtps_free(DkimAtps *self);

#endif /* __DKIM_ATPS_H__ */
