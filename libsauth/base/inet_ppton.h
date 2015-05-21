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

#ifndef __INET_PPTON_H__
#define __INET_PPTON_H__

#ifdef __cplusplus
extern "C" {
#endif

int inet_ppton(int af, const char *src, const char *src_tail, void *dst);

#ifdef __cplusplus
}
#endif

#endif /* __INET_PPTON_H__ */
