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

#ifndef __SPF_LOGGER_H__
#define __SPF_LOGGER_H__

#include "loghandler.h"

#define SpfLogImplError LogError
#define SpfLogConfigError LogError
#define SpfLogPermFail LogInfo

#define SpfLogParseTrace(__format, ...) \
    // fprintf(stderr, __format, ##__VA_ARGS__)

#endif /* __SPF_LOGGER_H__ */
