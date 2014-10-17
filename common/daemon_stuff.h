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

#ifndef __DAEMON_STUFF_H__
#define __DAEMON_STUFF_H__

#include <stdbool.h>

typedef struct PidFile PidFile;

extern int close_tty(void);
extern int daemon_init(const char *user, const char *rootdir, const char **errstr);
extern int setuidgid(const char *username, const char **errstr);
extern int seteuidgid(const char *username, const char **errstr);

extern PidFile *PidFile_create(const char *path, bool with_lock, const char **errstr);
extern bool PidFile_isLocked(const char *path, const char **errstr);
extern void PidFile_close(PidFile *pidfile, bool with_unlink);

#endif /* __DAEMON_STUFF_H__ */
