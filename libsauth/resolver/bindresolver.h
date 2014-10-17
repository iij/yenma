/*
 * Copyright (c) 2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __BIND_RESOLVER_H__
#define __BIND_RESOLVER_H__

#include "dnsresolv.h"

extern DnsResolver *BindResolver_new(const char *initfile);

#endif /* __BIND_RESOLVER_H__ */
