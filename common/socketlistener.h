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

#ifndef __SOCKET_LISTENER_H__
#define __SOCKET_LISTENER_H__

extern int SocketListener_listen(const char *sockaddr, int backlog, int *fd);
extern int SocketListener_listenInet(const char *host, const char *service, int backlog, int *fd);
extern int SocketListener_listenInet4(const char *host, const char *service, int backlog, int *fd);
extern int SocketListener_listenInet6(const char *host, const char *service, int backlog, int *fd);
extern int SocketListener_listenUnix(const char *sockpath, int backlog, int *fd);

#endif // __SOCKET_LISTENER_H__
