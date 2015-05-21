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

#ifndef __CRYPTO_MUTEX_H__
#define __CRYPTO_MUTEX_H__

#ifdef __cplusplus
extern "C" {
#endif

void Crypto_mutex_init(void);
void Crypto_mutex_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_MUTEX_H__ */
