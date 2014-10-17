/*
 * Copyright (c) 2007-2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <pthread.h>

#include "loghandler.h"

// to exclude calling LogHandler_init()
static pthread_once_t LogHandler_init_once = PTHREAD_ONCE_INIT;

// key of the thread local storage to store the log prefix
static pthread_key_t LogHandler_prefix_key;

static void LogHandler_syslog(int log_level, const char *format, ...);

// default handler is syslog()
void (*LogHandler_emit) (int level, const char *format, ...) = LogHandler_syslog;

// default log mask
int LogHandler_logmask = LOG_UPTO(LOG_INFO);

static void
LogHandler_initImpl(void)
{
    pthread_key_create(&LogHandler_prefix_key, free);
}   // end function: LogHandler_initImpl

void
LogHandler_init(void)
{
    pthread_once(&LogHandler_init_once, LogHandler_initImpl);
}   // end function: LogHandler_init

/**
 * @attention Results are undefined if LogHandler_init() is not called
 */
void
LogHandler_cleanup(void)
{
    pthread_key_delete(LogHandler_prefix_key);
}   // end function: LogHandler_cleanup

int
LogHandler_setLogMask(int mask)
{
    int oldmask = LogHandler_logmask;
    LogHandler_logmask = mask;
    return oldmask;
}   // end function: LogHandler_setLogMask

/**
 * @attention Results are undefined if LogHandler_init() is not called
 */
bool
LogHandler_setPrefix(const char *prefix)
{
    // replace the old prefix with new one
    char *new_prefix;
    if (NULL != prefix) {
        new_prefix = strdup(prefix);
        if (NULL == new_prefix) {
            return false;
        }   // end if
    } else {
        new_prefix = NULL;
    }   // end if

    char *old_prefix = pthread_getspecific(LogHandler_prefix_key);

    if (0 != pthread_setspecific(LogHandler_prefix_key, new_prefix)) {
        free(new_prefix);
    }   // end if

    if (NULL != old_prefix) {
        free(old_prefix);
    }   // end if

    return true;
}   // end function: LogHandler_setPrefix

/**
 * @attention Results are undefined if LogHandler_init() is not called
 */
inline const char *
LogHandler_getPrefix(void)
{
    return (const char *) pthread_getspecific(LogHandler_prefix_key);
}   // end function: LogHandler_getPrefix

static void
LogHandler_null(int priority __attribute__((unused)), const char *format __attribute__((unused)), ...)
{
}   // end function: LogHandler_null

static void
LogHandler_syslog(int priority, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsyslog(priority, format, args);
    va_end(args);
}   // end function: LogHandler_syslog

static void
LogHandler_stdout(int log_level __attribute__((unused)), const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    putc('\n', stdout);
}   // end function: LogHandler_stdout

static void
LogHandler_stderr(int log_level __attribute__((unused)), const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    putc('\n', stderr);
}   // end function: LogHandler_stderr

void
LogHandler_switchToNull(void)
{
    LogHandler_emit = LogHandler_null;
}   // end function: LogHandler_switchToNull

void
LogHandler_switchToSyslog(void)
{
    LogHandler_emit = LogHandler_syslog;
}   // end function: LogHandler_switchToSyslog

void
LogHandler_switchToStdout(void)
{
    LogHandler_emit = LogHandler_stdout;
}   // end function: LogHandler_switchToStdout

void
LogHandler_switchToStderr(void)
{
    LogHandler_emit = LogHandler_stderr;
}   // end function: LogHandler_switchToStderr
