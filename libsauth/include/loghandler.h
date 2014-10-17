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

#ifndef __LOG_HANDLER_H__
#define __LOG_HANDLER_H__

#include <stdbool.h>
#include <syslog.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int LogHandler_logmask;
extern void (*LogHandler_emit)(int level, const char *format, ...) __attribute__ ((format(printf, 2, 3)));

extern void LogHandler_init(void);
extern void LogHandler_cleanup(void);
extern bool LogHandler_setPrefix(const char *prefix);
extern int LogHandler_setLogMask(int mask);
extern const char *LogHandler_getPrefix(void);
extern void LogHandler_switchToNull(void);
extern void LogHandler_switchToSyslog(void);
extern void LogHandler_switchToStdout(void);
extern void LogHandler_switchToStderr(void);

#define LogHandler_emitWithPrefix(_priority, _level, _format, ...) \
    do { \
        if (LogHandler_logmask & LOG_MASK(_priority)) { \
            const char *_prefix = LogHandler_getPrefix(); \
            if (NULL != _prefix) { \
                LogHandler_emit(_priority, _level ": %s: " _format, _prefix, ##__VA_ARGS__); \
            } else { \
                LogHandler_emit(_priority, _level ": " _format, ##__VA_ARGS__); \
            } \
        } \
    } while(0)

#define LogHandler_emitWithLineInfo(_priority, _level, _format, ...) \
    do { \
        if (LogHandler_logmask & LOG_MASK(_priority)) { \
            const char *_prefix = LogHandler_getPrefix(); \
            if (NULL != _prefix) { \
                LogHandler_emit(_priority, _level " (at %s L%d): %s: " _format, __FILE__, __LINE__, _prefix, ##__VA_ARGS__); \
            } else { \
                LogHandler_emit(_priority, _level " (at %s L%d): " _format, __FILE__, __LINE__, ##__VA_ARGS__); \
            } \
        } \
    } while(0)

#define LogDebug(_format, ...) \
    LogHandler_emitWithPrefix(LOG_DEBUG, "debug", _format, ##__VA_ARGS__)

#define LogInfo(_format, ...) \
    LogHandler_emitWithPrefix(LOG_INFO, "info", _format, ##__VA_ARGS__)

#define LogNotice(_format, ...) \
    LogHandler_emitWithPrefix(LOG_NOTICE, "notice", _format, ##__VA_ARGS__)

#define LogWarning(_format, ...) \
    LogHandler_emitWithLineInfo(LOG_WARNING, "warn", _format, ##__VA_ARGS__)

#define LogError(_format, ...) \
    LogHandler_emitWithLineInfo(LOG_ERR, "error", _format, ##__VA_ARGS__)

#define LogEvent(event, _format, ...) \
    LogInfo("[" event "] " _format, ##__VA_ARGS__)

#define LogPlain(_format, ...) LogHandler_emit(LOG_INFO, _format, ##__VA_ARGS__)

#define LogNoResource() \
    LogError("memory allocation failed")

#ifdef __cplusplus
}
#endif

#endif /* __LOG_HANDLER_H__ */
