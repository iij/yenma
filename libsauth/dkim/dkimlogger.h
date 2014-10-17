/*
 * Copyright (c) 2008-2013 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __DKIM_LOGGER_H__
#define __DKIM_LOGGER_H__

#include "loghandler.h"

#define DkimLogImplError LogError
#define DkimLogSysError LogError
#define DkimLogConfigError LogError
#define DkimLogPermFail LogInfo

#endif /* __DKIM_LOGGER_H__ */
