/*
 * READ BEFORE DOWNLOADING, COPYING, INSTALLING OR USING.
 *
 * By downloading, copying, installing or using the software you agree
 * to this license. If you do not agree to this license, do not
 * download, install, copy or use the software.
 *
 * University of Minnesota Institute of Technology
 *
 * Computer Science and Engineering – Digital Technology Center –
 * License Agreement
 *
 * Copyright (c) 2005-2007, Regents of the University of Minnesota.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * -Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * -Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * -The name of the University of Minnesota may not be used to endorse
 * or promote products derived from this software without specific
 * prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * UNIVERSITY OF MINNESOTA OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* This defines all the network packets and related information.*/

#ifndef __PROTOCOL_H
#define __PROTOCOL_H

#include <stdio.h>
#include <fuse.h>

#define MAX_COREFS_GIDS 32
#define MAX_COREFS_PATH 4096


/* Packet organization: */
/*                                     _______fileop      */
/*                ______request_______|_______raw         */
/*    payload_____|                   |_______simpleop    */
/*                |                   |_______xattr       */
/*                |                                       */
/*                |                    ________status     */
/*                |_____response______|________raw        */
/*                                    |________attr       */
                                  
typedef struct _corefs_header
{
	unsigned int magic;
	unsigned int type; 
	unsigned int sequence;
	unsigned int payload_size;
} corefs_header;

extern size_t header_size;


/* Read/write style requests */
typedef struct _corefs_fileop
{
    unsigned int type;
    unsigned int offset;
    unsigned int size;
    unsigned int pathlen;
    char path[MAX_COREFS_PATH];
} corefs_fileop;

/* Simple requests e.g., open, link, symlink etc */
typedef struct _corefs_simple
{
    unsigned int type;
    unsigned int offset;
    unsigned int mode1;
    unsigned int path1len;
    unsigned int path2len;   // Second path for commands such as symlink  
    char path1[MAX_COREFS_PATH]; 
    char path2[MAX_COREFS_PATH];
} corefs_simple;

/* Requests to set/get POSIX extended attributes */
typedef struct _corefs_xattr
{
  unsigned int type;
  int flags;
  unsigned int sizeofvalue;
  unsigned int pathlen;
  unsigned int namelen;
  const char params[1]; /* This variable is used to pass path of the
                         * file as well as the attribute name. format:
                         * path || '\0' || attribute name. */
} corefs_xattr;


typedef union _corefs_operations
{
  corefs_fileop fileop;
  corefs_simple simple;
  corefs_xattr xattr;
  char raw[1]; // actually variable size but gcc hates []
}corefs_operation;



/* Structure to hold user information that can be used for access
 * control */
typedef struct _user_info_
{
  uid_t uid; 
  uid_t gid;  /* Primary gid */
  unsigned int num_sgids;  /* num of Supplementary gids. Maximum can
                            * be MAX_COREFS_GIDS. */
  uid_t sgids[MAX_COREFS_GIDS]; /* Supplementary gids */
}user_info;



typedef struct _corefs_request
{
  unsigned int type;  /* Type of request */
  user_info user_ids;
  corefs_operation op;
}corefs_request;


/* Return strucutre from get_attr */
typedef struct _corefs_attr
{
	unsigned int mode;
	unsigned int uid;
	unsigned int gid;
	unsigned int size;
	unsigned int mtime;
  unsigned int atime;
  unsigned int ctime;
  unsigned int nlinks;
} corefs_attr;

/* Used to tell the client the status of its request. If the "type"
 * field in the response packet is COREFS_RESPONSE_ERROR then bits
 * indicates errno. Otherwise of the type is COREFS_RESPONSE_STATUS
 * then bits indicate the status of the request.*/
typedef struct _corefs_status
{
	unsigned int bits;
} corefs_status;

typedef union _corefs_response_op
{
	corefs_status status;
	corefs_attr attr;
  char raw[1]; /* actually variable size data */ 
}corefs_response_op;



typedef struct _corefs_response
{
  unsigned int type;  /* Type of response */
  unsigned int more_offset;  /* This offset is used to tell the client that the
                  * server could not fit in all the data for this
                  * request in one response packet and that the client
                  * should then reissue the same request with the
                  * provided offset. This offset is only used in case
                  * of readdir().*/
  corefs_response_op rop;
}corefs_response;


typedef union _corefs_payload
{
  corefs_request request;
  corefs_response response;
}corefs_payload;

/* Basic corefs network packet */
typedef struct _corefs_packet
{
	corefs_header header;
	corefs_payload payload;
} corefs_packet;

/* corfs_packet magic */
#define COREFS_MAGIC 0xDEADBEEF

/* corefs_header type */
#define COREFS_REQUEST 0xBA
#define COREFS_RESPONSE 0xBB

/* corefs_request type */
#define COREFS_REQUEST_DATA 0xAA
#define COREFS_REQUEST_FILEOP 0xAB
#define COREFS_REQUEST_SIMPLE 0xAC
#define COREFS_REQUEST_XATTR 0xAD

/* corefs_response  type */
#define COREFS_RESPONSE_DATA 0xA
#define COREFS_RESPONSE_STATUS 0xB
#define COREFS_RESPONSE_ATTR 0xC
#define COREFS_RESPONSE_ERROR 0xD
#define COREFS_RESPONSE_MOREDATA 0xE /* Basically the response is
                                      * data. But if the server could
                                      * not fit all of the requested
                                      * data in one response, it
                                      * indicates the client that
                                      * theres more data and then che
                                      * client should reissue the
                                      * request again for the
                                      * remaining data. This type is
                                      * only useful for readdir where
                                      * the contents of the directory
                                      * can be large and so the server
                                      * needs to split the responses
                                      * into incremental parts. */

/* corefs_fileop type i.e., for COREFS_REQUEST_FILEOP */
#define COREFS_REQUEST_READ    27
#define COREFS_REQUEST_WRITE   28
#define COREFS_REQUEST_READDIR 29
#define COREFS_REQUEST_GETATTR 30
#define COREFS_REQUEST_READLINK 85

/* corefs_xattr type */
#define COREFS_XATTR_SETXATTR 226
#define COREFS_XATTR_GETXATTR 229
#define COREFS_XATTR_REMOVEXATTR 232
#define COREFS_XATTR_LISTXATTR 235

/* corefs_simple for COREFS_REQUEST_SIMPLE, the field 'type': */
#define COREFS_SIMPLE_TRUNCATE 90
#define COREFS_SIMPLE_MKNOD    91
#define COREFS_SIMPLE_UNLINK   92
#define COREFS_SIMPLE_MKDIR    93
#define COREFS_SIMPLE_RMDIR    94
#define COREFS_SIMPLE_RENAME   95
#define COREFS_SIMPLE_SYMLINK  96
#define COREFS_SIMPLE_CHMOD    98
#define COREFS_SIMPLE_CHOWN    99
#define COREFS_SIMPLE_UTIME   100
#define COREFS_SIMPLE_OPEN   101
#define COREFS_SIMPLE_RELEASE   102
#define COREFS_SIMPLE_LINK  103
#define COREFS_SIMPLE_ACCESS  104
#endif
