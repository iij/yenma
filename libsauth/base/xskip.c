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

#include <sys/types.h>
#include <string.h>
#include "xskip.h"

/*
 * [RFC2822]
 * atext = ALPHA / DIGIT / ; Any character except controls,
 *         "!" / "#" /     ;  SP, and specials.
 *         "$" / "%" /     ;  Used for atoms
 *         "&" / "'" /
 *         "*" / "+" /
 *         "-" / "/" /
 *         "=" / "?" /
 *         "^" / "_" /
 *         "`" / "{" /
 *         "|" / "}" /
 *         "~"
 *
 * 0x20 以降では以下の文字を *含まない*
 *   SP / '"' / "(" / ")" / "," / "." /
 *   ":" / ";" / "<" / ">" /
 *   "@" / "[" / "\" / "]" / DEL
 */
unsigned char atextmap[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * [RFC2822]
 * ctext = NO-WS-CTL /     ; Non white space controls
 *         %d33-39 /       ; The rest of the US-ASCII
 *         %d42-91 /       ;  characters not including "(",
 *         %d93-126        ;  ")", or "\"
 */
unsigned char ctextmap[] = {
    0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * [RFC2822]
 * dtext = NO-WS-CTL /     ; Non white space controls
 *         %d33-90 /       ; The rest of the US-ASCII
 *         %d94-126        ;  characters not including "[",
 *                         ;  "]", or "\"
 */
unsigned char dtextmap[] = {
    0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * [RFC2822]
 * ftext = %d33-57 /       ; Any character except
 *         %d59-126        ;  controls, SP, and
 *                         ;  ":".
 */
unsigned char ftextmap[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * [RFC2822]
 * qtext = NO-WS-CTL /     ; Non white space controls
 *         %d33 /          ; The rest of the US-ASCII
 *         %d35-91 /       ;  characters not including "\"
 *         %d93-126        ;  or the quote character
 */
unsigned char qtextmap[] = {
    0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * [RFC5321]
 * qtextSMTP      = %d32-33 / %d35-91 / %d93-126
 *               ; i.e., within a quoted string, any
 *               ; ASCII graphic or space is permitted
 *               ; without blackslash-quoting except
 *               ; double-quote and the backslash itself.
 */
unsigned char qtextsmtpmap[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * univ-qtext     = NO-WS-CTL / qtextSMTP
 *               ; matches both qtext and qtextSMTP
 */
unsigned char univqtextmap[] = {
    0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * [RFC2822]
 * text = %d1-9 /         ; Characters excluding CR and LF
 *        %d11 /
 *        %d12 /
 *        %d14-127 /
 *        obs-text
 */
unsigned char textmap[] = {
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * [RFC2045]
 * token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
 *             or tspecials>
 * tspecials :=  "(" / ")" / "<" / ">" / "@" /
 *               "," / ";" / ":" / "\" / <">
 *               "/" / "[" / "]" / "?" / "="
 *               ; Must be in quoted-string,
 *               ; to use within parameter values
 */
unsigned char mimetokenmap[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * [RFC2822]
 * atext = ALPHA / DIGIT / ; Any character except controls,
 *         "!" / "#" /     ;  SP, and specials.
 *         "$" / "%" /     ;  Used for atoms
 *         "&" / "'" /
 *         "*" / "+" /
 *         "-" / "/" /
 *         "=" / "?" /
 *         "^" / "_" /
 *         "`" / "{" /
 *         "|" / "}" /
 *         "~"
 */
int
XSkip_atextBlock(const char *head, const char *tail, const char **nextp)
{
    const char *p;
    for (p = head; p < tail && IS_ATEXT(*p); ++p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_atextBlock

/*
 * [RFC2822]
 * atom = [CFWS] 1*atext [CFWS]
 */
int
XSkip_atom(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    XSkip_cfws(p, tail, &p);
    if (0 >= XSkip_atextBlock(p, tail, &p)) {
        // atext を1文字も含まない場合は atom にもマッチしない
        *nextp = head;
        return 0;
    }   // end if
    XSkip_cfws(p, tail, &p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_atom

/*
 * [RFC2822]
 * dtext = NO-WS-CTL /     ; Non white space controls
 *         %d33-90 /       ; The rest of the US-ASCII
 *         %d94-126        ;  characters not including "[",
 *                         ;  "]", or "\"
 */
int
XSkip_dtextBlock(const char *head, const char *tail, const char **nextp)
{
    const char *p;
    for (p = head; p < tail && IS_DTEXT(*p); ++p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_dtextBlock

/*
 * [RFC2045] 5.1.
 * token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
 *             or tspecials>
 * tspecials :=  "(" / ")" / "<" / ">" / "@" /
 *               "," / ";" / ":" / "\" / <">
 *               "/" / "[" / "]" / "?" / "="
 *               ; Must be in quoted-string,
 *               ; to use within parameter values
 */
int
XSkip_mimeToken(const char *head, const char *tail, const char **nextp)
{
    const char *p;
    for (p = head; p < tail && IS_MIMETOKEN(*p); ++p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_mimeToken

/*
 * [RFC2045] 5.1.
 * value := token / quoted-string
 */
int
XSkip_mimeValue(const char *head, const char *tail, const char **nextp)
{
    const char *p;
    if (0 < XSkip_mimeToken(head, tail, &p)
        || 0 < XSkip_2822QuotedString(head, tail, &p)) {
        *nextp = p;
    } else {
        *nextp = head;
    }   // end if

    return *nextp - head;
}   // end function: XSkip_mimeValue

/*
 * 指定した任意の 1 文字をスキップする関数
 */
int
XSkip_char(const char *head, const char *tail, char c, const char **nextp)
{
    *nextp = (head < tail && *head == c) ? head + 1 : head;
    return *nextp - head;
}   // end function: XSkip_char

/*
 * 指定した任意の文字列をスキップする関数
 */
int
XSkip_string(const char *head, const char *tail, const char *str, const char **nextp)
{
    const char *p = head;
    size_t len;

    len = strlen(str);
    if (p + len <= tail && 0 == strncmp(p, str, len)) {
        p += len;
    }   // end if
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_string

/*
 * 指定した任意の文字列を case-insensitive にスキップする関数
 */
int
XSkip_casestring(const char *head, const char *tail, const char *str, const char **nextp)
{
    const char *p = head;
    size_t len;

    len = strlen(str);
    if (p + len <= tail && 0 == strncasecmp(p, str, len)) {
        p += len;
    }   // end if
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_casestring

/*
 * [RFC2822]
 * ctext = NO-WS-CTL /     ; Non white space controls
 *         %d33-39 /       ; The rest of the US-ASCII
 *         %d42-91 /       ;  characters not including "(",
 *         %d93-126        ;  ")", or "\"
 */
int
XSkip_ctext(const char *head, const char *tail, const char **nextp)
{
    *nextp = (head < tail && IS_CTEXT(*head)) ? head + 1 : head;
    return *nextp - head;
}   // end function: XSkip_ctext

/*
 * [RFC2822]
 * quoted-pair = ("\" text) / obs-qp
 */
int
XSkip_quotedPair(const char *head, const char *tail, const char **nextp)
{
    *nextp = head;
    if (head + 1 < tail && *head == '\\' && IS_TEXT(*(head + 1))) {
        *nextp += 2;
    }   // end if
    return *nextp - head;
}   // end function: XSkip_quotedPair

/*
 * [RFC2822]
 * qcontent = qtext / quoted-pair
 */
int
XSkip_qcontent(const char *head, const char *tail, const char **nextp)
{
    if (head < tail && IS_QTEXT(*head)) {
        *nextp = head + 1;
        return 1;
    }   // end if

    // *s が qtext でない場合は XSkip_quotedPair() にそのまま委譲
    return XSkip_quotedPair(head, tail, nextp);
}   // end function: XSkip_qcontent

/*
 * [RFC2822]
 * dcontent = dtext / quoted-pair
 */
int
XSkip_dcontent(const char *head, const char *tail, const char **nextp)
{
    if (head < tail && IS_DTEXT(*head)) {
        *nextp = head + 1;
        return 1;
    }   // end if

    // *s が dtext でない場合は XSkip_quotedPair() にそのまま委譲
    return XSkip_quotedPair(head, tail, nextp);
}   // end function: XSkip_dcontent

/*
 * [RFC2822]
 * dot-atom-text = 1*atext *("." 1*atext)
 */
int
XSkip_dotAtomText(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    *nextp = p;
    while (p < tail) {
        if (0 >= XSkip_atextBlock(p, tail, &p)) {
            break;
        }   // end if
        *nextp = p;
        if (0 >= XSkip_char(p, tail, '.', &p)) {
            break;
        }   // end if
    }   // end while

    return *nextp - head;
}   // end function: XSkip_dotAtomText

/*
 * [RFC2822]
 * dot-atom-text = 1*atext *("." 1*atext)
 *
 * loose dot-atom-text hack version
 * dot-atom-text = 1*( atext / "." )
 */
int
XSkip_looseDotAtomText(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    while (0 < XSkip_atextBlock(p, tail, &p) || 0 < XSkip_char(p, tail, '.', &p));
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_looseDotAtomText

/*
 * [RFC2822]
 * dot-atom = [CFWS] dot-atom-text [CFWS]
 */
int
XSkip_dotAtom(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    XSkip_cfws(p, tail, &p);
    if (0 >= XSkip_dotAtomText(p, tail, &p)) {
        // dot-atom-text にマッチしない場合は dot-atom にもマッチしない
        *nextp = head;
        return 0;
    }   // end if
    XSkip_cfws(p, tail, &p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_dotAtom

/*
 * [RFC2822]
 * dot-atom = [CFWS] dot-atom-text [CFWS]
 *
 * loose dot-atom-text hack version
 */
int
XSkip_looseDotAtom(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    XSkip_cfws(p, tail, &p);
    if (0 >= XSkip_looseDotAtomText(p, tail, &p)) {
        // dot-atom-text にマッチしない場合は dot-atom にもマッチしない
        *nextp = head;
        return 0;
    }   // end if
    XSkip_cfws(p, tail, &p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_looseDotAtom

/*
 * [RFC2822]
 * domain-literal = [CFWS] "[" *([FWS] dcontent) [FWS] "]" [CFWS]
 */
static int
XSkip_domainLiteral(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    XSkip_cfws(p, tail, &p);
    if (0 >= XSkip_char(p, tail, '[', &p)) {
        *nextp = head;
        return 0;
    }   // end if
    do {
        XSkip_fws(p, tail, &p);
    } while (0 < XSkip_dcontent(p, tail, &p));
    if (0 >= XSkip_char(p, tail, ']', &p)) {
        *nextp = head;
        return 0;
    }   // end if
    XSkip_cfws(p, tail, &p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_domainLiteral

/*
 * [RFC2822]
 * domain = dot-atom / domain-literal / obs-domain
 */
int
XSkip_2822Domain(const char *head, const char *tail, const char **nextp)
{
    const char *p;

    if (0 < XSkip_dotAtom(head, tail, &p)
        || 0 < XSkip_domainLiteral(head, tail, &p)) {
        // dot-atom / domain-literal のいずれかにマッチした場合
        *nextp = p;
    } else {
        // dot-atom / domain-literal の両方にマッチしなかった場合
        *nextp = head;
    }   // end if

    return *nextp - head;
}   // end function: XSkip_2822Domain

/*
 * [RFC2822]
 * quoted-string = [CFWS]
 *                 DQUOTE *([FWS] qcontent) [FWS] DQUOTE
 *                 [CFWS]
 */
int
XSkip_2822QuotedString(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    XSkip_cfws(p, tail, &p);
    if (0 >= XSkip_char(p, tail, '\"', &p)) {
        *nextp = head;
        return 0;
    }   // end if
    do {
        XSkip_fws(p, tail, &p);
    } while (0 < XSkip_qcontent(p, tail, &p));
    if (0 >= XSkip_char(p, tail, '\"', &p)) {
        *nextp = head;
        return 0;
    }   // end if
    XSkip_cfws(p, tail, &p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_2822QuotedString

/*
 * [RFC2822]
 * word = atom / quoted-string
 */
int
XSkip_word(const char *head, const char *tail, const char **nextp)
{
    const char *p;

    if (0 < XSkip_atom(head, tail, &p)
        || 0 < XSkip_2822QuotedString(head, tail, &p)) {
        // atom / quoted-string のいずれかにマッチした場合
        *nextp = p;
    } else {
        // atom / quoted-string の両方にマッチしなかった場合
        *nextp = head;
    }   // end if

    return *nextp - head;
}   // end function: XSkip_word

/*
 * [RFC2822]
 * phrase = 1*word / obs-phrase
 */
int
XSkip_phrase(const char *head, const char *tail, const char **nextp)
{
    *nextp = head;
    while (0 < XSkip_word(*nextp, tail, nextp));
    return *nextp - head;
}   // end function: XSkip_phrase

/*
 * [RFC2822]
 * local-part = dot-atom / quoted-string / obs-local-part
 */
int
XSkip_2822LocalPart(const char *head, const char *tail, const char **nextp)
{
    const char *retp;

    if (0 < XSkip_looseDotAtom(head, tail, &retp)
        || 0 < XSkip_2822QuotedString(head, tail, &retp)) {
        // dot-atom / quoted-string のいずれかにマッチした場合
        *nextp = retp;
    } else {
        // dot-atom / quoted-string の両方にマッチしなかった場合
        *nextp = head;
    }   // end if

    return *nextp - head;
}   // end function: XSkip_2822LocalPart

/*
 * [RFC2822]
 * addr-spec = local-part "@" domain
 */
int
XSkip_addrSpec(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    if (0 >= XSkip_2822LocalPart(p, tail, &p)
        || 0 >= XSkip_char(p, tail, '@', &p)
        || 0 >= XSkip_2822Domain(p, tail, &p)) {
        *nextp = head;
        return 0;
    }   // end if

    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_addrSpec

/*
 * [RFC2822]
 * ccontent = ctext / quoted-pair / comment
 */
int
XSkip_ccontent(const char *head, const char *tail, const char **nextp)
{
    const char *retp;

    if (0 < XSkip_ctext(head, tail, &retp)
        || 0 < XSkip_quotedPair(head, tail, &retp)
        || 0 < XSkip_comment(head, tail, &retp)) {
        // ctext / quoted-pair / comment のいずれかにマッチした場合
        *nextp = retp;
    } else {
        // ctext / quoted-pair / comment のいずれにもマッチしなかった場合
        *nextp = head;
    }   // end if

    return *nextp - head;
}   // end function: XSkip_ccontent

/*
 * [RFC2822]
 * comment = "(" *([FWS] ccontent) [FWS] ")"
 */
int
XSkip_comment(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    if (0 >= XSkip_char(p, tail, '(', &p)) {
        *nextp = head;
        return 0;
    }   // end if

    do {
        XSkip_fws(p, tail, &p);
    } while (0 < XSkip_ccontent(p, tail, &p));

    if (0 >= XSkip_char(p, tail, ')', &p)) {
        *nextp = head;
        return 0;
    }   // end if

    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_comment

/*
 * [RFC2822]
 * CFWS = *([FWS] comment) (([FWS] comment) / FWS)
 */
int
XSkip_cfws(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    do {
        XSkip_fws(p, tail, &p);
    } while (0 < XSkip_comment(p, tail, &p));

    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_cfws

/*
 * [RFC5234]
 * CR   =  %x0D
 *              ; carriage return
 * LF   =  %x0A
 *              ; linefeed
 * CRLF =  CR LF
 *              ; Internet standard newline
 */
int
XSkip_crlf(const char *head, const char *tail, const char **nextp)
{
    if (head + 1 < tail && IS_CR(*head) && IS_LF(*(head + 1))) {
        *nextp = head + 2;
#ifndef XSKIP_STRICT_CRLF_HANDLING
    } else if (head < tail && IS_LF(*head)) {
        *nextp = head + 1;
#endif
    } else {
        *nextp = head;
    }   // end if

    return *nextp - head;
}   // end function: XSkip_crlf

/*
 * [RFC5234]
 * CR   =  %x0D
 *              ; carriage return
 * LF   =  %x0A
 *              ; linefeed
 * CRLF =  CR LF
 *              ; Internet standard newline
 */
int
XSkip_crlfBlock(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;
    while (0 < XSkip_crlf(p, tail, &p));
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_crlfBlock

/*
 * [RFC2822]
 * field-name = 1*ftext
 * ftext      = %d33-57 /  ; Any character except
 *              %d59-126   ;  controls, SP, and
 *                         ;  ":".
 */
int
XSkip_fieldName(const char *head, const char *tail, const char **nextp)
{
    const char *p;
    for (p = head; p < tail && IS_FTEXT(*p); ++p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_fieldName

/*
 * [RFC5234]
 * LWSP =  *(WSP / CRLF WSP)
 *              ; Use of this linear-white-space rule
 *              ;  permits lines containing only white
 *              ;  space that are no longer legal in
 *              ;  mail headers and have caused
 *              ;  interoperability problems in other
 *              ;  contexts.
 *              ; Do not use when defining mail
 *              ;  headers and use with caution in
 *              ;  other contexts.
 */
int
XSkip_lwsp(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;
    do {
        *nextp = p;
        XSkip_crlf(p, tail, &p);
    } while (0 < XSkip_wsp(p, tail, &p));
    return *nextp - head;
}   // end function: XSkip_lwsp

/*
 * SPBLOCK =  *SP
 */
int
XSkip_spBlock(const char *head, const char *tail, const char **nextp)
{
    const char *p;
    for (p = head; p < tail && IS_SP(*p); ++p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_spBlock

/*
 * [RFC5234]
 * WSP =  SP / HTAB
 *             ; white space
 */
int
XSkip_wsp(const char *head, const char *tail, const char **nextp)
{
    *nextp = (head < tail && IS_WSP(*head)) ? head + 1 : head;
    return *nextp - head;
}   // end function: XSkip_wsp

/*
 * [RFC5234]
 * WSP =  SP / HTAB
 *             ; white space
 */
int
XSkip_wspBlock(const char *head, const char *tail, const char **nextp)
{
    const char *p;
    for (p = head; p < tail && IS_WSP(*p); ++p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_wspBlock

/*
 * [RFC5234]
 * DIGIT =  %x30-39
 *               ; 0-9
 */
int
XSkip_digitBlock(const char *head, const char *tail, const char **nextp)
{
    const char *p;
    for (p = head; p < tail && IS_DIGIT(*p); ++p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_digitBlock

/*
 * [RFC5234]
 * ALPHA =  %x41-5A / %x61-7A   ; A-Z / a-z
 */
int
XSkip_alpha(const char *head, const char *tail, const char **nextp)
{
    *nextp = (head < tail && IS_ALPHA(*head)) ? head + 1 : head;
    return *nextp - head;
}   // end function: XSkip_alpha

/*
 * ALNUM = *(ALPHA / DIGIT)
 */
int
XSkip_alnum(const char *head, const char *tail, const char **nextp)
{
    *nextp = (head < tail && IS_ALNUM(*head)) ? head + 1 : head;
    return *nextp - head;
}   // end function: XSkip_alnum

/*
 * ALNUMBLOCK =  *(ALPHA / DIGIT)
 */
int
XSkip_alnumBlock(const char *head, const char *tail, const char **nextp)
{
    const char *p;
    for (p = head; p < tail && IS_ALNUM(*p); ++p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_alnumBlock

/*
 * [RFC6376]
 * tag-name  =  ALPHA *ALNUMPUNC
 * ALNUMPUNC =  ALPHA / DIGIT / "_"
 */
int
XSkip_tagName(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    // 先頭の文字は ALPHA
    if (tail <= p || !IS_ALPHA(*p)) {
        *nextp = p;
        return *nextp - head;
    }   // end if

    for (++p; p < tail && IS_ALNUMPUNC(*p); ++p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_tagName

/*
 * [RFC6376]
 * tval      =  1*VALCHAR
 * VALCHAR   =  %x21-3A / %x3C-7E
 *                   ; EXCLAMATION to TILDE except SEMICOLON
 */
static int
XSkip_tval(const char *head, const char *tail, const char **nextp)
{
    const char *p;
    for (p = head; p < tail && IS_VALCHAR(*p); ++p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_tval

/*
 * [RFC6376]
 * tag-value =  [ tval *( 1*(WSP / FWS) tval ) ]
 *                   ; Prohibits WSP and FWS at beginning and end
 */
int
XSkip_tagValue(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;
    *nextp = p;
    while (0 < XSkip_tval(p, tail, &p)) {
        *nextp = p;
        while (0 < XSkip_wsp(p, tail, &p) || 0 < XSkip_fws(p, tail, &p));
    }   // end while
    return *nextp - head;
}   // end function: XSkip_tagValue

/*
 * [RFC4408]
 * name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
 */
int
XSkip_spfName(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    // First character must be ALPHA.
    if (tail <= p || !IS_ALPHA(*p)) {
        *nextp = p;
        return *nextp - head;
    }   // end if

    for (++p; p < tail && IS_SPF_NAME(*p); ++p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_spfName

/*
 * [RFC2821]
 * Quoted-string = DQUOTE *qcontent DQUOTE
 */
int
XSkip_2821QuotedString(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    if (0 >= XSkip_char(p, tail, '\"', &p)) {
        *nextp = head;
        return 0;
    }   // end if

    // qcontent に少なくとも1文字はマッチすることを確認する

    if (0 >= XSkip_qcontent(p, tail, &p)) {
        *nextp = head;
        return 0;
    }   // end if

    // 残りの qcontent を読む
    while (0 < XSkip_qcontent(p, tail, &p));

    if (0 >= XSkip_char(p, tail, '\"', &p)) {
        *nextp = head;
        return 0;
    }   // end if

    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_2821QuotedString

/*
 * [RFC2821]
 * Dot-string = Atom *("." Atom)
 * Atom       = 1*atext
 */
int
XSkip_dotString(const char *head, const char *tail, const char **nextp)
{
    // delegate to XSkip_dotAtomText() for equivalence between Dot-string and dot-atom-text
    return XSkip_dotAtomText(head, tail, nextp);
}   // end function: XSkip_dotString

/*
 * [RFC2821]
 * Dot-string = Atom *("." Atom)
 * Atom       = 1*atext
 *
 * loose Dot-String hack version
 * Dot-string = 1*( Atom / "." )
 */
int
XSkip_looseDotString(const char *head, const char *tail, const char **nextp)
{
    // delegate to XSkip_dotAtomText() for equivalence between Dot-string and dot-atom-text
    return XSkip_looseDotAtomText(head, tail, nextp);
}   // end function: XSkip_looseDotString

/* [RFC2821]
 * Local-part = Dot-string / Quoted-string
 *       ; MAY be case-sensitive
 */
int
XSkip_2821LocalPart(const char *head, const char *tail, const char **nextp)
{
    const char *retp;

    if (0 < XSkip_looseDotString(head, tail, &retp)
        || 0 < XSkip_2821QuotedString(head, tail, &retp)) {
        // Dot-string / Quoted-string のいずれかにマッチした場合
        *nextp = retp;
    } else {
        // Dot-string / Quoted-string の両方にマッチしなかった場合
        *nextp = head;
    }   // end if

    return *nextp - head;
}   // end function: XSkip_2821LocalPart

/*
 * [RFC2821]
 * address-literal = "[" IPv4-address-literal /
 *                       IPv6-address-literal /
 *                       General-address-literal "]"
 * IPv4-address-literal = Snum 3("." Snum)
 * IPv6-address-literal = "IPv6:" IPv6-addr
 * General-address-literal = Standardized-tag ":" 1*dcontent
 * Standardized-tag = Ldh-str
 *       ; MUST be specified in a standards-track RFC
 *       ; and registered with IANA
 *
 * Snum = 1*3DIGIT  ; representing a decimal integer
 *       ; value in the range 0 through 255
 * Let-dig = ALPHA / DIGIT
 * Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig
 *
 * IPv6-addr = IPv6-full / IPv6-comp / IPv6v4-full / IPv6v4-comp
 * IPv6-hex  = 1*4HEXDIG
 * IPv6-full = IPv6-hex 7(":" IPv6-hex)
 * IPv6-comp = [IPv6-hex *5(":" IPv6-hex)] "::" [IPv6-hex *5(":"
 *            IPv6-hex)]
 *       ; The "::" represents at least 2 16-bit groups of zeros
 *       ; No more than 6 groups in addition to the "::" may be
 *       ; present
 * IPv6v4-full = IPv6-hex 5(":" IPv6-hex) ":" IPv4-address-literal
 * IPv6v4-comp = [IPv6-hex *3(":" IPv6-hex)] "::"
 *              [IPv6-hex *3(":" IPv6-hex) ":"] IPv4-address-literal
 *       ; The "::" represents at least 2 16-bit groups of zeros
 *       ; No more than 4 groups in addition to the "::" and
 *       ; IPv4-address-literal may be present
 */
static int
XSkip_addressLiteral(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    *nextp = p; // 全体がマッチしない限りマッチしない

    if (tail <= p || *p != '[') {
        return *nextp - head;
    }   // end if

    // NOTE: 文字種のチェックしかおこなっていない
    for (++p; p < tail && (IS_DIGIT(*p) || *p == ':' || *p == '.'); ++p);

    if (tail <= p || *p != ']') {
        return *nextp - head;
    }   // end if

    *nextp = p + 1;
    return *nextp - head;
}   // end function: XSkip_addressLiteral

/*
 * [RFC2821]
 * sub-domain = Let-dig [Ldh-str]
 * Let-dig = ALPHA / DIGIT
 * Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig
 */
int
XSkip_subDomain(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    *nextp = p;
    // 先頭の文字は Let-dig
    if (tail <= p || !IS_LET_DIG(*p)) {
        return *nextp - head;
    }   // end if

    for (++p; p < tail; ++p) {
        if (IS_LET_DIG(*p)) {
            *nextp = p;
            continue;
        }   // end if
        if ('-' == *p)  //  sub-domain doesn't terminate with '-'
            continue;
        break;
    }   // end for

    ++(*nextp);
    return *nextp - head;
}   // end function: XSkip_subDomain

/*
 * [RFC6376]
 * selector =   sub-domain *( "." sub-domain )
 */
int
XSkip_selector(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    *nextp = p;
    while (p < tail) {
        if (0 >= XSkip_subDomain(p, tail, &p)) {
            break;
        }   // end if
        *nextp = p;
        if (0 >= XSkip_char(p, tail, '.', &p)) {
            break;
        }   // end if
    }   // end while

    return *nextp - head;
}   // end function: XSkip_selector

/*
 * [RFC3461]
 * real-domain = sub-domain *("." sub-domain)
 */
int
XSkip_realDomain(const char *head, const char *tail, const char **nextp)
{
    // delegate to XSkip_selector() for equivalence between real-domain and selector of RFC6376
    return XSkip_selector(head, tail, nextp);
}   // end function: XSkip_realDomain

/*
 * [RFC2821]
 * Domain = (sub-domain 1*("." sub-domain)) / address-literal
 * address-literal = "[" IPv4-address-literal /
 *                       IPv6-address-literal /
 *                       General-address-literal "]"
 *       ; See section 4.1.3
 */
int
XSkip_2821Domain(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    if (tail <= p) {
        *nextp = p;
        return 0;
    }   // end if

    if (*p == '[') {    // address-literal
        return XSkip_addressLiteral(p, tail, nextp);
    } else {
        return XSkip_domainName(p, tail, nextp);
    }   // end if
}   // end function: XSkip_2821Domain

/*
 * [RFC2821]
 * Mailbox = Local-part "@" Domain
 */
int
XSkip_2821Mailbox(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    if (0 >= XSkip_2821LocalPart(p, tail, &p)
        || 0 >= XSkip_char(p, tail, '@', &p)
        || 0 >= XSkip_2821Domain(p, tail, &p)) {
        *nextp = head;
        return 0;
    }   // end if

    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_2821Mailbox

/*
 * [RFC6376]
 * domain-name     = sub-domain 1*("." sub-domain)
 *                   ; from [RFC5321] Domain,
 *                   ; excluding address-literal
 */
int
XSkip_domainName(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    *nextp = p; // 何もマッチしていないことを示す
    if (0 >= XSkip_subDomain(p, tail, &p)) {
        return 0;
    }   // end if
    while (p < tail) {
        if (0 >= XSkip_char(p, tail, '.', &p)) {
            return *nextp - head;
        }   // end if
        if (0 >= XSkip_subDomain(p, tail, &p)) {
            return *nextp - head;
        }   // end if
        *nextp = p;
    }   // end while

    return *nextp - head;
}   // end function: XSkip_domainName

static int
XSkip_base64charBlock(const char *head, const char *tail, const char **nextp)
{
    const char *p;
    for (p = head; p < tail && IS_BASE64CHAR(*p); ++p);
    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_base64charBlock

/*
 * [RFC6376]
 * base64string    =  ALPHADIGITPS *([FWS] ALPHADIGITPS)
 *                    [ [FWS] "=" [ [FWS] "=" ] ]
 */
int
XSkip_base64string(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    while (0 < XSkip_base64charBlock(p, tail, &p) || 0 < XSkip_fws(p, tail, &p));
    if (0 < XSkip_char(p, tail, '=', &p)) {
        XSkip_fws(p, tail, &p);
        if (0 < XSkip_char(p, tail, '=', &p)) {
            XSkip_fws(p, tail, &p);
        }   // end if
    }   // end if
    *nextp = p;

    return *nextp - head;
}   // end function: XSkip_base64string

/*
 * [RFC2822]
 * FWS = [*WSP CRLF] 1*WSP  ; Folding white space
 */
int
XSkip_fws(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    *nextp = p; // 何もマッチしていないことを示す
    if (tail <= p) {
        return 0;
    }   // end if

    XSkip_wspBlock(p, tail, &p);
    *nextp = p;
    if (0 < XSkip_crlfBlock(p, tail, &p) && 0 < XSkip_wspBlock(p, tail, &p)) {
        *nextp = p;
    }   // end if
    return *nextp - head;
}   // end function: XSkip_fws

/*
 * [RFC6376]
 * hyphenated-word =  ALPHA [ *(ALPHA / DIGIT / "-") (ALPHA / DIGIT) ]
 */
int
XSkip_hyphenatedWord(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    *nextp = p;
    // 先頭の文字は ALPHA
    if (tail <= p || !IS_ALPHA(*p)) {
        return *nextp - head;
    }   // end if

    for (++p; p < tail; ++p) {
        if (IS_LET_DIG(*p)) {
            *nextp = p;
            continue;
        }   // end if
        if ('-' == *p) {    // hyphenated-word doesn't terminate with '-'
            continue;
        }   // end if
        break;
    }   // end for

    ++(*nextp);
    return *nextp - head;
}   // end function: XSkip_hyphenatedWord

/*
 * [RFC6376]
 * x-sig-a-tag-k   = ALPHA *(ALPHA / DIGIT)
 *                      ; for later extension
 * x-sig-a-tag-h   = ALPHA *(ALPHA / DIGIT)
 *                      ; for later extension
 */
int
XSkip_alphaAlnum(const char *head, const char *tail, const char **nextp)
{
    const char *p = head;

    // First character must be ALPHA.
    if (tail <= p || !IS_ALPHA(*p)) {
        *nextp = p;
        return *nextp - head;
    }   // end if

    for (++p; p < tail && IS_ALNUM(*p); ++p);

    *nextp = p;
    return *nextp - head;
}   // end function: XSkip_alphaAlnum
