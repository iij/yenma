/*
 * Copyright (c) 2008-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef _FILE_READER_H_
#define _FILE_READER_H_

#include <sys/types.h>
#include "xbuffer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _rfile_stat {
    RFILESTAT_OK = 0,
    RFILESTAT_EOF,
    RFILESTAT_READERR,
    RFILESTAT_NORESOURCE,
} rfilestat_t;

struct FileReader;
typedef struct FileReader FileReader;

extern FileReader *FileReader_new(int fd);
extern void FileReader_free(FileReader *self);
extern rfilestat_t FileReader_read(FileReader *self, void *buf, size_t nbyte, size_t *readlen);
extern rfilestat_t FileReader_readLine(FileReader *self, void *buf, size_t buflen, size_t *readlen);
extern rfilestat_t FileReader_readString(FileReader *self, XBuffer *xbuf, size_t nbyte,
                                         size_t *readlen);
extern rfilestat_t FileReader_readStringLine(FileReader *self, XBuffer *xbuf, size_t limitlen,
                                             size_t *readlen);
extern rfilestat_t FileReader_seek(FileReader *self, off_t offset, int whence);

#ifdef __cplusplus
}
#endif

#endif /* _FILE_READER_H_ */
