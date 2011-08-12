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
/* This file defines the API between corefs and the uppler layer.*/
#ifndef _COREFS_TYPES_H
#define _COREFS_TYPES_H

#include <fuse.h>
#include "protocol.h"


#define PROCEED 0xABCD
#define STOP -1
#define MAX_OPTS 100  /* Maximum length of the argstr string passed to
                       * up_parse_arguments */



typedef struct _sock_ctx SOCK_CTX;
struct _sock_ctx {
  /* This structure stores the pointer to the send and receive functions
   * that will be called by coreFS to send and receive network
   * messages. The upper layer, should set these appropriately. The
   * sock_ctx contains socket. */
	int sock;
};


typedef struct _commctx COMMCTX;
struct _commctx {
  SOCK_CTX* sock_ctx; /*  context that contains socket */
  void* sec_ctx; /* upper layer can store its context here */
  /*  Function pointers to network functions layer */
  int (*receive)(COMMCTX*, char*, int); 
  int (*send)(COMMCTX*, char*, int);
};



/* The current CoreFS client operations */
typedef struct _corefs_client_ops corefs_client_operations;
struct _corefs_client_ops{
    /* FUSE file system functions */
    int (*open) (const char *, struct fuse_file_info *);
    int (*release) (const char *, struct fuse_file_info *);
    int (*read) (const char *, char *, size_t, off_t, struct fuse_file_info *);
    int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);
    int (*getattr) (const char *, struct stat *);
    int (*write) (const char *, const char *, size_t, off_t, struct fuse_file_info *);
    int (*mknod) (const char *, mode_t, dev_t);
    int (*truncate) (const char *, off_t);
    int (*unlink) (const char *);
    int (*mkdir) (const char *, mode_t);
    int (*rmdir) (const char *);
    int (*rename) (const char *, const char *);
    int (*link) (const char *, const char *);
    int (*symlink) (const char *, const char *);
    int (*readlink) (const char *, char *, size_t);
    int (*chmod) (const char *, mode_t);
    int (*chown) (const char *, uid_t, gid_t);	
    int (*utime) (const char *, struct utimbuf *);
    int (*flush) (const char *, struct fuse_file_info *);
    int (*access) (const char *, int);
    void (*destroy) (void *);
#ifdef HAVE_SETXATTR
    int (*setxattr) (const char *, const char *, const char *, size_t , int );
    int (*getxattr) (const char *, const char *, char *, size_t);
    int (*listxattr) (const char *, char *, size_t);
    int (*removexattr) (const char *, const char *);
#endif
  
    /* Sometimes the upper layer wants to setup its own command line
       arguments. For example, in case of an encrypting file system the
       upper layer may want to user to specify paths to keys used for
       encryption. In this case the parsing of command line option can be
       done in the up_parse_arguments strcutre. Corefs will pass all
       command line arguments to the upper layer. If the upper layer
       returns PROCEED, corefs will proceed to perform its own
       parsing. Otherwise, it will print "its usage" and exit. */
    int (*up_parse_arguments)(char * argstr, int argc, char** argv);
  
    /* The up_new_* functions are called everytime a connection is
       established with the other party. The corefs client will call
       up_new_server after estabilishing connection with a new server,
       whereas the corefs server will call up_new_client. The COMMCTX *
       arugment is a pointer to the context that contains the pointers to
       send, receive, and goodbye functions. These three functions will be
       called when the client/server wants to send some info, receive some
       info, or end connection for that particular socket passed in the ctx
       structure. Sometimes the upper layer may need to trap all outgoing
       and incoming messages. For example, in case of link encryption every
       outgoing message has to be encrypted. By initializing the send and
       receive functions to point to its own send and receive functions the
       upper layer will be able to trap all the messages. The upper layer
       can then do whatever it wants, e.g., just encrypt the message and
       send it over the socket. */
    int (*up_new_server)(char * client, char * server, COMMCTX * ctx);

  
    /* This function is called for each request by the client. The
     * function should set the appropriate uid, gid etc fields. These
     * are transferred to the server and the server can use them to
     * perform access control. In most of the cases the paths maynot
     * seem useful. But one can embed access control information in the
     * paths and associate uid, gid to that information. For example,
     * has of the user's public key can be a part of the path. new_path
     * is meaninful only in case of calls such as symlink, link etc that
     * operate on two paths at the same time.*/
    void (*up_get_user_info)(user_info * u, const char * path, const char * new_path);
    
    /* This function is called when a socket is closed (either on
       purpose or due to some error). */
    void (*up_eof_connection)(COMMCTX * ctx); // TODO: where should I call this from?
};



/* The current CoreFS server API */
typedef struct _corefs_server_ops corefs_server_operations;
struct _corefs_server_ops{
  
  /* All of the following functions should return 0 on success and -1
   * on error. The ctx specifies the socket and send and receive
   * functions to be used for this socket. The cmd is the actual
   * command sent by the coreFS client. */
  int (*handle_read)(COMMCTX* ctx, corefs_packet* cmd);
  int (*handle_write)(COMMCTX* ctx, corefs_packet* cmd);
  int (*handle_setxattr)(COMMCTX* ctx, corefs_packet* cmd);
  int (*handle_getxattr)(COMMCTX* ctx, corefs_packet* cmd);
  int (*handle_listxattr)(COMMCTX* ctx, corefs_packet* cmd);
  int (*handle_removexattr)(COMMCTX* ctx, corefs_packet* cmd);
  int (*handle_readdir)(COMMCTX* ctx, corefs_packet* cmd);
  int (*handle_getattr)(COMMCTX* ctx, corefs_packet* cmd);
  int (*handle_readlink)(COMMCTX* ctx, corefs_packet* cmd);

  /* All of the following should return whatever the corresponding system calls are
   * supposed to return */

  /** File open operation as defined in FUSE:
   *
   * No creation, or truncation flags (O_CREAT, O_EXCL, O_TRUNC)
   * will be passed to open().  Open should check if the operation
   * is permitted for the given flags.  Optionally open may also
   * return an arbitrary filehandle in the fuse_file_info structure,
   * which will be passed to all file operations.
   *
   * Changed in version 2.2
   */
  int (*open) (const char *, int flags);
  
  /** Release an open file as defined in FUSE:
   *
   * Release is called when there are no more references to an open
   * file: all file descriptors are closed and all memory mappings
   * are unmapped.
   *
   * For every open() call there will be exactly one release()
   **/
  int (*release) (const char *, int flags);
  int (*mknod) (const char *, mode_t, dev_t);
	int (*truncate) (const char *, off_t);
	int (*unlink) (const char *);
	int (*mkdir) (const char *, mode_t);
	int (*rmdir) (const char *);
	int (*rename) (const char *, const char *);
	int (*link) (const char *, const char *);
	int (*symlink) (const char *, const char *);
  int (*chmod) (const char *, mode_t);
	int (*chown) (const char *, uid_t, gid_t);	
	int (*utime) (const char *, const struct utimbuf *);
  int (*access) (const char *, int);
  
  /* Sometimes the upper layer wants to setup its own command line
     arguments. For example, in case of an encrypting file system the
     upper layer may want to user to specify paths to keys used for
     encryption. In this case the parsing of command line option can be
     done in the up_parse_arguments strcutre. Corefs will pass all
     command line arguments to the upper layer. If the upper layer
     returns PROCEED, corefs will proceed to perform its own
     parsing. Otherwise, it will print "its usage" and exit. */
  int (*up_parse_arguments)(char * argstr, int argc, char** argv);
  
  /* The up_new_* functions are called everytime a connection is
     established with the other party. The corefs client will call
     up_new_server after estabilishing connection with a new server,
     whereas the corefs server will call up_new_client. The COMMCTX *
     arugment is a pointer to the context that contains the pointers to
     send, receive, and goodbye functions. These three functions will be
     called when the client/server wants to send some info, receive some
     info, or end connection for that particular socket passed in the ctx
     structure. Sometimes the upper layer may need to trap all outgoing
     and incoming messages. For example, in case of link encryption every
     outgoing message has to be encrypted. By initializing the send and
     receive functions to point to its own send and receive functions the
     upper layer will be able to trap all the messages. The upper layer
     can then do whatever it wants, e.g., just encrypt the message and
     send it over the socket. */
  int (*up_new_client)(char * client, char * server, COMMCTX * ctx);
  
  /* This function is called when a socket is closed (either on
     purpose or due to some error). */
  void (*up_eof_connection)(COMMCTX * ctx); // TODO: where should I call this from?

  /* This functions is called by the server before performing any file
   * operations. In success the function should return PROCEED. On
   * failure the function should return STOP with status containing
   * the error number. This error number will be sent to the
   * client.  */
  int (*up_check_access)(COMMCTX * ctx, const user_info * u, int * status, const char * path1, const char * path2, int op);
};



/* The init functions take corefs_operations structures with entries
 * initilaized to the read, write etc functions of corefs. In case,
 * the up layer wants to use its functions to the system calls, then
 * it should change the values of the relevant function pointers in
 * the corefs_operations structure. */
int up_server_init(corefs_server_operations * op);
int up_client_init(corefs_client_operations * op);


/* Helper corefs functions that can be called by the upper layer. */
int cb_log(COMMCTX*, char*);
int phy_send(COMMCTX*, char* buf, int size);
int phy_receive(COMMCTX*, char* buf, int size); /* physical layer
                                                 * network send
                                                 * functions. These
                                                 * simply receive or
                                                 * send size amount of
                                                 * information to or
                                                 * from the buffer */


#ifndef EKEYREVOKED
#define EKEYREVOKED 128
#endif
#ifndef EKEYREJECTED
#define EKEYREJECTED 129
#endif



#endif
