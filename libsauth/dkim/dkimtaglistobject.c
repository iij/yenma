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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>

#include "ptrop.h"
#include "dkimlogger.h"
#include "xskip.h"

#include "dkim.h"
#include "dkimtaglistobject.h"

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_TAG_DUPLICATED multiple identical tags are found
 * @error other errors returned by callback functions
 */
static DkimStatus
DkimTagListObject_dispatchParser(DkimTagListObject *self, const DkimTagParseContext *context,
                                 bool ignore_syntax_error, const char **nextp)
{
    const DkimTagListObjectFieldMap *fieldmap;
    for (fieldmap = self->ftbl; NULL != fieldmap->tagname; ++fieldmap) {
        /*
         * compare tag-name case-sensitively
         *
         * [RFC6376] 3.2.
         * Tags MUST be interpreted in a case-sensitive manner.  Values MUST be
         * processed as case sensitive unless the specific tag description of
         * semantics specifies case insensitivity.
         */
        const char *match_tail;
        if (0 >= XSkip_string(context->tag_head, context->tag_tail, fieldmap->tagname, &match_tail)
            || context->tag_tail != match_tail) {
            continue;   // try next tag-name
        }   // end if

        /*
         * tag-name matched.
         * check tag duplication.
         *
         * [RFC6376] 3.2.
         * Tags with duplicate names MUST NOT occur within a single tag-list; if
         * a tag name does occur more than once, the entire tag-list is invalid.
         */
        ptrdiff_t field_no = fieldmap - self->ftbl;
        if (FIELD_ISSET(field_no, &self->parsed_mask)) {
            DkimLogPermFail("tag duplicated: %s", fieldmap->tagname);
            return DSTAT_PERMFAIL_TAG_DUPLICATED;
        }   // end if

        if (NULL != fieldmap->tagparser) {
            // call corresponding tag-parser
            DkimStatus parse_stat = (fieldmap->tagparser) (self, context, nextp);
            if (parse_stat == DSTAT_OK) {
                // mark as parsed to detect tag duplication
                FIELD_SET(field_no, &self->parsed_mask);
            }   // end if
            if (ignore_syntax_error && !(fieldmap->required)
                && DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION == parse_stat) {
                /*
                 * [RFC7489] 6.3.
                 * Syntax errors in the remainder of the record SHOULD be discarded in favor of
                 * default values (if any) or ignored outright.
                 */
                parse_stat = DSTAT_OK;
            }   // end if
            return parse_stat;
        } else {
            /*
             * just ignore unrecognized tag
             *
             * [RFC6376] 3.2.
             * Unrecognized tags MUST be ignored.
             *
             * [RFC6376] 6.1.1.
             * Note, however, that this does not include the existence of unknown
             * tags in a DKIM-Signature header field, which are explicitly
             * permitted.
             *
             * [RFC5617] 4.2.1.
             * Unrecognized tags MUST be ignored.
             *
             * [RFC7489] 6.3.
             * Unknown tags MUST be ignored.
             */
            *nextp = context->value_tail;
            return DSTAT_OK;
        }   // end if
    }   // end for

    *nextp = context->value_tail;
    return DSTAT_OK;
}   // end function: DkimTagListObject_dispatchParser

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_MISSING_REQUIRED_TAG missing required tag
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error other errors returned by callback functions
 */
static DkimStatus
DkimTagListObject_applyDefaultValue(DkimTagListObject *self)
{
    const DkimTagListObjectFieldMap *fieldmap;
    DkimTagParseContext context;
    for (fieldmap = self->ftbl; NULL != fieldmap->tagname; ++fieldmap) {
        ptrdiff_t field_no = fieldmap - self->ftbl;
        if (FIELD_ISSET(field_no, &self->parsed_mask)) {
            continue;   // skip if already set
        }   // end if

        // apply default value if defined by the specification.
        if (NULL != fieldmap->default_value && NULL != fieldmap->tagparser) {
            context.tag_no = DKIM_TAGLISTOBJECT_TAG_NO_AS_DEFAULT_VALUE;
            context.tag_head = fieldmap->tagname;
            context.tag_tail = STRTAIL(context.tag_head);
            context.value_head = fieldmap->default_value;
            context.value_tail = STRTAIL(context.value_head);

            const char *retp;
            DkimStatus parse_stat = (fieldmap->tagparser) (self, &context, &retp);
            if (DSTAT_OK != parse_stat) {
                DkimLogImplError("default value is unable to parse: %s=%s",
                                 fieldmap->tagname, context.value_head);
                return DSTAT_SYSERR_IMPLERROR;
            }   // end if

            continue;   // the default value is applied
        }   // end if

        if (fieldmap->required) {
            // error if this tag is required
            DkimLogPermFail("missing required tag: %s", fieldmap->tagname);
            return DSTAT_PERMFAIL_MISSING_REQUIRED_TAG;
        }   // end if
    }   // end for
    return DSTAT_OK;
}   // end function: DkimTagListObject_applyDefaultValue

/*
 * [RFC6376] 3.2.
 * tag-list  =  tag-spec *( ";" tag-spec ) [ ";" ]
 * tag-spec  =  [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]
 * tag-name  =  ALPHA *ALNUMPUNC
 * tag-value =  [ tval *( 1*(WSP / FWS) tval ) ]
 *                   ; Prohibits WSP and FWS at beginning and end
 * tval      =  1*VALCHAR
 * VALCHAR   =  %x21-3A / %x3C-7E
 *                   ; EXCLAMATION to TILDE except SEMICOLON
 * ALNUMPUNC =  ALPHA / DIGIT / "_"
 *
 * @param ignore_syntax_error ignores syntax errors in favor of default values on optional tags (for parsing DMARC record)
 * @attention the "tag-list" syntax is extended as below to accept trailing FWS (especially CRLF):
 *   tag-list  =  tag-spec 0*( ";" tag-spec ) [ ";" [FWS] ]
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION tag-value syntax violation
 * @error DSTAT_PERMFAIL_MISSING_REQUIRED_TAG missing required tag
 * @error DSTAT_PERMFAIL_TAG_DUPLICATED multiple identical tags are found
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error other errors returned by callback functions
 */
DkimStatus
DkimTagListObject_build(DkimTagListObject *self, const char *record_head, const char *record_tail,
                        bool wsp_restriction, bool ignore_syntax_error)
{
    DkimTagParseContext context;
    context.tag_no = 0;
    FIELD_ZERO(&self->parsed_mask);
    const char *p = record_head;

    /*
     * switch whitespace interpretation according to whether the target is ADSP record or not.
     *
     * [RFC5617] 4.1.
     * .. The "Tag=Value List" syntax described in Section 3.2 of
     * [RFC4871] is used, modified to use whitespace (WSP) rather than
     * folding whitespace (FWS).
     * ...
     * Note:   ADSP changes the "Tag=Value List" syntax from [RFC4871] to
     *         use WSP rather than FWS in its DNS records.
     */
    xskip_funcp sp_skip_func = wsp_restriction ? XSkip_wspBlock : XSkip_fws;

    do {
        // start parsing with "p" pointing the head of tag-spec
        sp_skip_func(p, record_tail, &(context.tag_head));

        // tag-name
        if (0 >= XSkip_tagName(context.tag_head, record_tail, &(context.tag_tail))) {
            DkimLogPermFail("missing tag-name: near %.50s", context.tag_head);
            return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
        }   // end if

        sp_skip_func(context.tag_tail, record_tail, &p);
        if (0 >= XSkip_char(p, record_tail, '=', &p)) {
            DkimLogPermFail("tag-value pair parse error, \'=\' missing: near %.50s",
                            context.tag_head);
            return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
        }   // end if
        sp_skip_func(p, record_tail, &(context.value_head));

        // 0-length tag-value pair is permitted
        XSkip_tagValue(context.value_head, record_tail, &(context.value_tail));

        // dispatch corresponding tag-parser
        DkimStatus parse_stat =
            DkimTagListObject_dispatchParser(self, &context, ignore_syntax_error, &p);
        if (DSTAT_OK != parse_stat) {
            return parse_stat;
        }   // end if
        if (p < context.value_tail) {
            // When tag-parser stopped parsing in the middle of tag-value.
            DkimLogPermFail("tag-value has unused portion: %td bytes, near %.50s",
                            context.value_tail - p, context.tag_head);
            return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
        }   // end if

        // FWS (or WSP) after tag-value
        sp_skip_func(context.value_tail, record_tail, &p);

        // exit loop regarding as the end of tag-list if ';' does not follow
        if (0 >= XSkip_char(p, record_tail, ';', &p)) {
            break;
        }   // end if
        // ';' does not automatically mean the existence of following tag-spec.
        ++context.tag_no;
    } while (p < record_tail);

    // [spec-modification] accept trailing FWS (or WSP)
    sp_skip_func(p, record_tail, &p);

    if (p < record_tail) {
        // When the record violates tag-list syntax.
        DkimLogPermFail("record has unused portion: %td bytes, near %.50s", record_tail - p, p);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    return DkimTagListObject_applyDefaultValue(self);
}   // end function: DkimTagListObject_build
