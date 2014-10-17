/*
 * Copyright (c) 2006-2013 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __DKIM_ADSP_H__
#define __DKIM_ADSP_H__

#include <stdbool.h>
#include "dnsresolv.h"
#include "dkim.h"

typedef struct DkimAdsp DkimAdsp;

extern DkimStatus DkimAdsp_build(const char *keyval, DkimAdsp **adsp_record);
extern DkimStatus DkimAdsp_lookup(const char *authordomain, DnsResolver *resolver,
                                  DkimAdsp **adsp_record);
extern void DkimAdsp_free(DkimAdsp *self);
extern DkimAdspPractice DkimAdsp_getPractice(const DkimAdsp *self);

#endif /* __DKIM_ADSP_H__ */
