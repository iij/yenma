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

#ifndef __YENMA_CTRL_H__
#define __YENMA_CTRL_H__

#include "listenerthread.h"

typedef ListenerThread YenmaCtrl;

extern YenmaCtrl *YenmaCtrl_run(const char *control_socket, int backlog);
extern void YenmaCtrl_shutdown(YenmaCtrl *self);
extern void YenmaCtrl_free(YenmaCtrl *self);

#endif /* __YENMA_CTRL_H__ */
