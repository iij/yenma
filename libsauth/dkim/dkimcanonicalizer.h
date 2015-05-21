/*
 * Copyright (c) 2006-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __DKIM_CANONICALIZER_H__
#define __DKIM_CANONICALIZER_H__

#include <stdbool.h>
#include "dkim.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DkimCanonicalizer DkimCanonicalizer;

extern DkimStatus DkimCanonicalizer_new(DkimC14nAlgorithm headeralg,
                                        DkimC14nAlgorithm bodyalg, DkimCanonicalizer **canon);
extern void DkimCanonicalizer_free(DkimCanonicalizer *self);
extern void DkimCanonicalizer_reset(DkimCanonicalizer *self);
extern DkimStatus DkimCanonicalizer_header(DkimCanonicalizer *self, const char *headerf,
                                           const char *headerv, bool crlf,
                                           bool keep_leading_header_space,
                                           const unsigned char **canonbuf, size_t *canonsize);
extern DkimStatus DkimCanonicalizer_signheader(DkimCanonicalizer *self, const char *headerf,
                                               const char *headerv,
                                               bool keep_leading_header_space,
                                               const char *b_tag_value_head,
                                               const char *b_tag_value_tail,
                                               const unsigned char **canonbuf, size_t *canonsize);
extern DkimStatus DkimCanonicalizer_body(DkimCanonicalizer *self, const unsigned char *bodyp,
                                         size_t bodylen, const unsigned char **canonbuf,
                                         size_t *canonsize);
extern DkimStatus DkimCanonicalizer_finalizeBody(DkimCanonicalizer *self,
                                                 const unsigned char **canonbuf, size_t *canonsize);

#ifdef __cplusplus
}
#endif

#endif /* __DKIM_CANONICALIZER_H__ */
