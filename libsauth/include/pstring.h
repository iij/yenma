/*
 * Copyright (c) 2006-2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __PSTRING_H__
#define __PSTRING_H__

#ifdef __cplusplus
extern "C" {
#endif

extern char *strpdup(const char *head, const char *tail);
extern const char *strpchr(const char *head, const char *tail, char c);
extern const char *strprchr(const char *head, const char *tail, char c);
extern unsigned long long strptoull(const char *head, const char *tail, const char **endptr);
extern unsigned long strptoul(const char *head, const char *tail, const char **endptr);

#ifdef __cplusplus
}
#endif

#endif /* __PSTRING_H__ */
