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

#ifndef __LISTENER_THREAD_H__
#define __LISTENER_THREAD_H__

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ListenerThread;
typedef struct ListenerThread ListenerThread;

extern ListenerThread *ListenerThread_create(const char *control_socket, int backlog,
                                             int (*handler) (void *, int, const struct sockaddr *, socklen_t), void *handler_arg);
extern void ListenerThread_shutdown(ListenerThread *self);
extern void ListenerThread_free(ListenerThread *self);

#ifdef __cplusplus
}
#endif

#endif /* __LISTENER_THREAD_H__ */
