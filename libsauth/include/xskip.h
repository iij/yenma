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

#ifndef __XSKIP_H__
#define __XSKIP_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*xskip_funcp) (const char *, const char *, const char **);

extern unsigned char atextmap[];
extern unsigned char ctextmap[];
extern unsigned char dtextmap[];
extern unsigned char ftextmap[];
extern unsigned char qtextmap[];
extern unsigned char qtextsmtpmap[];
extern unsigned char univqtextmap[];
extern unsigned char textmap[];
extern unsigned char mimetokenmap[];

#define XSKIP_MATCH(exp) (0 < (exp))
#define XSKIP_NOTMATCH(exp) (0 == (exp))

// RFC 2822
#define IS_ATEXT(c) (atextmap[(unsigned char)(c)])
#define IS_CTEXT(c) (ctextmap[(unsigned char)(c)])
#define IS_DTEXT(c) (dtextmap[(unsigned char)(c)])
#define IS_FTEXT(c) (ftextmap[(unsigned char)(c)])
#define IS_QTEXT(c) (qtextmap[(unsigned char)(c)])
#define IS_TEXT(c) (textmap[(unsigned char)(c)])

// RFC 2045
#define IS_MIMETOKEN(c) (mimetokenmap[(unsigned char)(c)])

// RFC 5234
#define IS_ALPHA(c) ((0x41 <= (c) && (c) <= 0x5a) || (0x61 <= (c) && (c) <= 0x7a))
#define IS_BIT(c) ((c) == '0' || (c) == '1')
#define IS_CHAR(c) (0x01 <= (c) && (c) <= 0x7f)
#define IS_CR(c) (0x0d == (c))
#define IS_CTL(c) ((0x00 <= (c) && (c) <= 0x1f) || 0x7f == (c))
#define IS_DIGIT(c) (0x30 <= (c) && (c) <= 0x39)
#define IS_DQUOTE(c) (0x22 == (c))
#define IS_HEXDIG(c) (IS_DIGIT(c) || ('A' <= (c) && (c) <= 'F'))
#define IS_HTAB(c) (0x09 == (c))
#define IS_LF(c) (0x0a == (c))
#define IS_OCTET(c) (0x00 <= (c) && (c) <= 0xff)
#define IS_SP(c) ((c) == 0x20)
#define IS_VCHAR(c) (0x21 <= (c) && (c) <= 0x7e)
#define IS_WSP(c) (IS_SP(c) || IS_HTAB(c))

// RFC 2821
#define IS_LET_DIG(c) (IS_ALPHA(c) || IS_DIGIT(c))

// RFC5321
#define IS_QTEXTSMTP(c) (qtextsmtpmap[(unsigned char)(c)])
#define IS_QPAIRSMTP(c) (0x20 <= (c) && (c) <= 0x7e)

// original
#define IS_UNIVQTEXT(c) (univqtextmap[(unsigned char)(c)])

// RFC 4408
#define IS_SPF_NAME(c)	(IS_ALPHA(c) || IS_DIGIT(c) || (c) == '-' || (c) == '_' || (c) == '.')

// RFC 6376
#define IS_ALNUMPUNC(c)	(IS_ALPHA(c) || IS_DIGIT(c) || (c) == '_')
#define IS_BASE64CHAR(c) (IS_ALPHA(c) || IS_DIGIT(c) || (c) == '+' || (c) == '/')
#define IS_ALNUM(c)	(IS_ALPHA(c) || IS_DIGIT(c))
#define IS_VALCHAR(c) ((0x21 <= (c) && (c) <= 0x3a) || (0x3c <= (c) && (c) <= 0x7e))
#define IS_DKIM_SAFE_CHAR(c) ((0x21 <= (c) && (c) <= 0x3a) || (c) == 0x3c || (0x3e <= (c) && (c) <= 0x7e))

// RFC 2554
#define IS_HEXCHAR(c) IS_HEXDIG(c)
#define IS_XCHAR(c)	((0x21 <= (c) && (c) <= 0x7e) && '+' != (c) && '=' != (c))

// given character/string
extern int XSkip_char(const char *head, const char *tail, char c, const char **nextp);
extern int XSkip_string(const char *head, const char *tail, const char *str, const char **nextp);
extern int XSkip_casestring(const char *head, const char *tail, const char *str,
                            const char **nextp);

// RFC 2045
extern int XSkip_mimeToken(const char *head, const char *tail, const char **nextp);
extern int XSkip_mimeValue(const char *head, const char *tail, const char **nextp);

// RFC 2822
extern int XSkip_atextBlock(const char *head, const char *tail, const char **nextp);
extern int XSkip_atom(const char *head, const char *tail, const char **nextp);
extern int XSkip_dtextBlock(const char *head, const char *tail, const char **nextp);
extern int XSkip_ctext(const char *head, const char *tail, const char **nextp);
extern int XSkip_quotedPair(const char *head, const char *tail, const char **nextp);
extern int XSkip_qcontent(const char *head, const char *tail, const char **nextp);
extern int XSkip_dcontent(const char *head, const char *tail, const char **nextp);
extern int XSkip_dotAtomText(const char *head, const char *tail, const char **nextp);
extern int XSkip_dotAtom(const char *head, const char *tail, const char **nextp);
extern int XSkip_2822Domain(const char *head, const char *tail, const char **nextp);
extern int XSkip_2822QuotedString(const char *head, const char *tail, const char **nextp);
extern int XSkip_word(const char *head, const char *tail, const char **nextp);
extern int XSkip_phrase(const char *head, const char *tail, const char **nextp);
extern int XSkip_2822LocalPart(const char *head, const char *tail, const char **nextp);
extern int XSkip_addrSpec(const char *head, const char *tail, const char **nextp);
extern int XSkip_ccontent(const char *head, const char *tail, const char **nextp);
extern int XSkip_comment(const char *head, const char *tail, const char **nextp);
extern int XSkip_cfws(const char *head, const char *tail, const char **nextp);
extern int XSkip_fieldName(const char *head, const char *tail, const char **nextp);
extern int XSkip_fws(const char *head, const char *tail, const char **nextp);

// RFC 5234
extern int XSkip_spBlock(const char *head, const char *tail, const char **nextp);
extern int XSkip_wsp(const char *head, const char *tail, const char **nextp);
extern int XSkip_wspBlock(const char *head, const char *tail, const char **nextp);
extern int XSkip_digitBlock(const char *head, const char *tail, const char **nextp);
extern int XSkip_alpha(const char *head, const char *tail, const char **nextp);
extern int XSkip_crlf(const char *head, const char *tail, const char **nextp);
extern int XSkip_crlfBlock(const char *head, const char *tail, const char **nextp);
extern int XSkip_lwsp(const char *head, const char *tail, const char **nextp);

// RFC 2821
extern int XSkip_2821QuotedString(const char *head, const char *tail, const char **nextp);
extern int XSkip_dotString(const char *head, const char *tail, const char **nextp);
extern int XSkip_2821LocalPart(const char *head, const char *tail, const char **nextp);
extern int XSkip_subDomain(const char *head, const char *tail, const char **nextp);
extern int XSkip_2821Domain(const char *head, const char *tail, const char **nextp);
extern int XSkip_2821Mailbox(const char *head, const char *tail, const char **nextp);

// RFC 3461
extern int XSkip_realDomain(const char *head, const char *tail, const char **nextp);

// RFC 4408
extern int XSkip_spfName(const char *head, const char *tail, const char **nextp);

// RFC 6376
extern int XSkip_selector(const char *head, const char *tail, const char **nextp);
extern int XSkip_domainName(const char *head, const char *tail, const char **nextp);
extern int XSkip_base64string(const char *head, const char *tail, const char **nextp);
extern int XSkip_hyphenatedWord(const char *head, const char *tail, const char **nextp);
extern int XSkip_tagName(const char *head, const char *tail, const char **nextp);
extern int XSkip_tagValue(const char *head, const char *tail, const char **nextp);
extern int XSkip_alphaAlnum(const char *head, const char *tail, const char **nextp);

extern int XSkip_alnum(const char *head, const char *tail, const char **nextp);
extern int XSkip_alnumBlock(const char *head, const char *tail, const char **nextp);

// loose dot-atom-text hack
extern int XSkip_looseDotAtomText(const char *head, const char *tail, const char **nextp);
extern int XSkip_looseDotAtom(const char *head, const char *tail, const char **nextp);
extern int XSkip_looseDotString(const char *head, const char *tail, const char **nextp);

#ifdef __cplusplus
}
#endif

#endif /* __XSKIP_H__ */
