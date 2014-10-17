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

#ifndef __SPF_MACRO_H__
#define __SPF_MACRO_H__

#include "xbuffer.h"
#include "spf.h"
#include "spfrecord.h"

extern SpfStat SpfMacro_parseDomainSpec(const SpfEvaluator *evaluator, const char *head,
                                        const char *tail, const char **nextp, XBuffer *xbuf);
extern SpfStat SpfMacro_parseExplainString(const SpfEvaluator *evaluator, const char *head,
                                           const char *tail, const char **nextp, XBuffer *xbuf);

#endif /* __SPF_MACRO_H__ */
