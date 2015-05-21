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

#ifndef __MILTER_AUX_H__
#define __MILTER_AUX_H__

#include <stdbool.h>
#include <libmilter/mfapi.h>
#include "xbuffer.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int milter_setup(struct smfiDesc *descr, char *miltersock, int backlog, int timeout,
                        int debuglevel, const char **errstr);
extern _SOCK_ADDR *milter_dupaddr(const _SOCK_ADDR *hostaddr);

#ifdef __cplusplus
}
#endif

#endif /* __MILTER_AUX_H__ */
