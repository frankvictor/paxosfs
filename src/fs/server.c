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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <utime.h>
#include <fcntl.h>

#include "list.h"
#include "protocol.h"
#include "log.h"

#include "common.h"
#ifdef HAVE_SETXATTR
#include <sys/types.h>
#include <sys/xattr.h>
#endif

#define _GNU_SOURCE
#include <getopt.h>

corefs_server_operations my_ops; /* This should be initialized only
                                  * once. Should not need any
                                  * locking */
int server_port = SERVER_PORT;


#define FDLEN 10

#define MAXCONN 5

char* g_buffer;
char* g_buffer2;

COMMCTX g_ctx;
COMMCTX* ctx=&g_ctx;
SOCK_CTX g_mctx;

/*By default the server will be not be run in background*/
/* 1  to run in the background and disconnect from parent process. */
int become_daemon = 0;
/* 1 to fork for each new client. */
int fork_client = 0;   
void error_reply(COMMCTX* ctx, int seq, int my_errno)
{
  
    int size = build_status((corefs_packet*)g_buffer, my_errno,
                            COREFS_RESPONSE_ERROR);
    int ret = encap_corefs_header(g_buffer2,(corefs_packet*)g_buffer);
    encap_corefs_response(g_buffer2 + ret, (corefs_packet*)g_buffer);
    send_packet(ctx, g_buffer2, size);
}

int handle_open(const char * path, int flags){
    int ret = open(path, flags);
    if(ret > 0)
        close(ret);
    return ret;
}

int handle_release(const char * path, int flags){
    return 0;
}

int handle_access(const char * path, int mode){
    return access(path,mode);
}

int handle_read(COMMCTX* ctx, corefs_packet* cmd)
{

    FILE* f;
    int ret;

  
    /* Check with the security layer if the user should be allowed to
     * access the file */
  

    if(my_ops.up_check_access){
        if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, cmd->payload.request.op.fileop.path, NULL, cmd->payload.request.type) != PROCEED){
            fprintf(stderr, "check_access: access denied\n");
            error_reply(ctx, cmd->header.sequence, ret);
            return -1;
        }
    }
  
  
    const char* path = cmd->payload.request.op.fileop.path;
    unsigned int offset = cmd->payload.request.op.fileop.offset;
    unsigned int size = cmd->payload.request.op.fileop.size;
    unsigned int packet_size = 0;

#ifdef DEBUG
    dprintf(stderr, "READ: file \'%s\'.\n", path);
#endif


  
    f=fopen(path, "r");
    if (!f) {
        dprintf(stderr, "fopen failed.\n");
        error_reply(ctx, cmd->header.sequence, errno);
        return -1;
    }
    ret=fseek(f, offset, SEEK_SET);
    if (ret != 0) {
        dprintf(stderr, "fseek failed.\n");
        error_reply(ctx, cmd->header.sequence, errno);
        fclose(f);
        return -1;
    }

    corefs_packet* reply=(corefs_packet*)g_buffer;  
    ret = fread(reply->payload.response.rop.raw, 1, size, f);

    if (ret < size) {
        if (ferror(f)) {
            dprintf(stderr, "fread failed.\n");
            error_reply(ctx, cmd->header.sequence, errno);
            fclose(f);
            return -1;
        }
        else if (feof(f)) {
            dprintf(stderr, "hit end of file.\n");
        }
        else {
            dprintf(stderr, "read too few bytes, don't know why.\n");
        }
    }
    fclose(f);

    packet_size = build_response_data(reply, reply->payload.response.rop.raw,
                                      ret);
    char reply_buf[packet_size];
  
    /*   Encap response */
    ret = encap_corefs_header(reply_buf, reply);
    encap_corefs_response(reply_buf + header_size, reply);
#ifdef DEBUG_NETWORK
    dprintf(stderr, "Printing response packet\n");
    print_packet(*reply);
#endif  
    send_packet(ctx, reply_buf, packet_size);
    return 0;
	
}

int handle_write(COMMCTX* ctx, corefs_packet* cmd)
{
    corefs_packet* data=(corefs_packet*)g_buffer; // the data

    FILE* f;
    int ret = 0;

    const char* path = cmd->payload.request.op.fileop.path;
    unsigned int offset = cmd->payload.request.op.fileop.offset;
    unsigned int size = cmd->payload.request.op.fileop.size;
#ifdef DEBUG
    dprintf(stderr, "WRTIE: file \'%s\' offset %u size %u \n", path,
            offset, size);
#endif

    /* Check with the security layer if the user should be allowed to
     * access the file */
    if(my_ops.up_check_access){
        if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, cmd->payload.request.op.fileop.path, NULL, cmd->payload.request.type) != PROCEED){
            dprintf(stderr, "check_access: access denied\n");
            error_reply(ctx, cmd->header.sequence, ret);
            return -1;
        }
    }
  
    f=fopen(path, "r+");
    if (!f) {
        dprintf(stderr, "fopen failed.\n");
        error_reply(ctx, cmd->header.sequence, errno);
        return -1;
    }
    ret=fseek(f, offset, SEEK_SET);
    if (ret != 0) {
        dprintf(stderr, "fseek failed.\n");
        error_reply(ctx, cmd->header.sequence, errno);
        fclose(f);
        return -1;
    }
  
    /* Get the request data from the next network packet. */
    if (server_receive_specified(ctx, g_buffer, COREFS_REQUEST_DATA) < 0) {
        error_reply(ctx, cmd->header.sequence, EPROTO );
        return -1;
    }
  

    ret = data->header.payload_size - REQUEST_BASE_SIZE(data->payload.request);
  
  
    if (ret != size) {
        dprintf(stderr, "data packet size (%i) disagrees with size of write (%i).\n",	ret, size);
        error_reply(ctx, cmd->header.sequence, EPROTO);
        return -1;
    }

		//log
		/*log_write(path, offset, size, data->payload.request.op.raw);*/
  
    ret = fwrite(data->payload.request.op.raw, 1, size, f);

    if (ret < size) {
        if (ferror(f)) {
            dprintf(stderr, "fwrite failed.\n");
            error_reply(ctx, cmd->header.sequence, errno);
            fclose(f);
            return -1;
        }
        else {
            dprintf(stderr, "wrote too few bytes, don't know why.\n");
        }
    }
  
    fclose(f);
  
    /* Inform client that the write was succesfull */
    corefs_packet reply;
    unsigned int packet_size = build_status(&reply, 0, COREFS_RESPONSE_STATUS);
    ret = encap_corefs_header(g_buffer, &reply);
    encap_corefs_response(g_buffer + ret, &reply);
#ifdef DEBUG_NETWORK
    dprintf(stderr, "Printing response packet\n");
    print_packet(reply);
#endif  
    send_packet(ctx, g_buffer, packet_size);
    return 0;
}

#ifdef HAVE_SETXATTR

int handle_setxattr(COMMCTX* ctx, corefs_packet* cmd)
{
    int ret = 0;
    corefs_packet* data=(corefs_packet*)g_buffer; // the attribute value
    corefs_packet reply;
    int pathlen = cmd->payload.request.op.xattr.pathlen;
    int namelen = cmd->payload.request.op.xattr.namelen;
  
    char path[pathlen+1];
    char attrname[namelen+1];
    unsigned int sizeofvalue = cmd->payload.request.op.xattr.sizeofvalue;
  
    memset(path, 0, pathlen+1);
    memset(attrname, 0, namelen+1);
    memcpy(path, cmd->payload.request.op.xattr.params, pathlen+1);
    memcpy(attrname, cmd->payload.request.op.xattr.params+pathlen+1, namelen);
  
#ifdef DEBUG
    dprintf(stderr, "SETXATTR: path[%s] attrname [%s].\n", path, attrname);
#endif
  
    // get the "value" from the next network packet.
    if (server_receive_specified(ctx, g_buffer, COREFS_REQUEST_DATA) < 0) {
        error_reply(ctx, cmd->header.sequence, EPROTO);
        return -1;
    }
  

    ret = data->header.payload_size - REQUEST_BASE_SIZE(data->payload.request);
    if (ret != sizeofvalue) {
        dprintf(stderr, "data packet size (%i) disagrees with size of value (%i).\n",
                ret, sizeofvalue);
        error_reply(ctx, cmd->header.sequence, EPROTO);
        return -1;
    }
  
    /* Check with the security layer if the user should be allowed to
     * access the file */
    if(my_ops.up_check_access){
        if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret,  cmd->payload.request.op.fileop.path, NULL, cmd->payload.request.type) != PROCEED){
            dprintf(stderr, "check_access: access denied\n");
            error_reply(ctx, cmd->header.sequence, ret);
            return -1;
        }
    }
  
		//log
		//future will need fault tolerance
    ret = log_setxattr (path, attrname, data->payload.request.op.raw, sizeofvalue,
                    cmd->payload.request.op.xattr.flags);
		
    ret = setxattr (path, attrname, data->payload.request.op.raw, sizeofvalue,
                    cmd->payload.request.op.xattr.flags);

    if (ret < 0) {
        dprintf(stderr, "setxattr failed.\n");
        error_reply(ctx, cmd->header.sequence, errno);
        return -1;
    }
    sizeofvalue = build_status(&reply, 0, COREFS_RESPONSE_STATUS);
    ret = encap_corefs_header(g_buffer, &reply);
    encap_corefs_response(g_buffer + ret, &reply);
  
    send_packet(ctx, g_buffer, sizeofvalue);
    return 0;
}

int handle_getxattr(COMMCTX* ctx, corefs_packet* cmd)
{
    int ret = 0;
    corefs_packet * reply = (corefs_packet*)g_buffer; // the status reply

    int pathlen = cmd->payload.request.op.xattr.pathlen;
    int namelen = cmd->payload.request.op.xattr.namelen;
    unsigned int sizeofvalue =  cmd->payload.request.op.xattr.sizeofvalue;
    char path[pathlen+1];
    char attrname[namelen+1];
    memset(path, 0, pathlen+1);
    memset(attrname, 0, namelen+1);
    memcpy(path, cmd->payload.request.op.xattr.params, pathlen+1);
    memcpy(attrname, cmd->payload.request.op.xattr.params+pathlen+1, namelen);
#ifdef DEBUG
    dprintf(stderr, "GETXATTR: path[%s] attrname [%s].\n", path, attrname);
#endif

    /* Check with the security layer if the user should be allowed to
     * access the file */
    if(my_ops.up_check_access){
        if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret,  cmd->payload.request.op.fileop.path, NULL,  cmd->payload.request.type) != PROCEED){
            dprintf(stderr, "check_access: access denied\n");
            error_reply(ctx, cmd->header.sequence, ret);
            return -1;
        }
    }
	
    ret = getxattr (path, attrname, reply->payload.response.rop.raw,
                    sizeofvalue);
    if (ret < 0) {
        dprintf(stderr, "getxattr failed path[%s] attr. name [%s].\n", path,
                attrname);
        error_reply(ctx, cmd->header.sequence, errno);
        return -1;
    }

    /* client just wants to know the size of the attribute */
    else if (sizeofvalue == 0){
        sizeofvalue = build_status(reply, ret, COREFS_RESPONSE_STATUS);
        char buf[sizeofvalue];
        ret = encap_corefs_header(buf, reply);
        encap_corefs_response(buf + ret, reply);
        send_packet(ctx, buf, sizeofvalue);
        return 0;
    }
    else {  /*  send the attribute value */
        sizeofvalue =
            build_response_data(reply,  reply->payload.response.rop.raw, ret);
        char buf[sizeofvalue];
        ret = encap_corefs_header(buf, reply);
        encap_corefs_response(buf + ret, reply);
        send_packet(ctx, buf, sizeofvalue);
    }
    return 0;
}


int handle_listxattr(COMMCTX* ctx, corefs_packet* cmd)
{
    int ret = 0;
    corefs_packet * reply = (corefs_packet*)g_buffer; // the status reply

    int pathlen = cmd->payload.request.op.xattr.pathlen;
    unsigned int sizeofvalue =  cmd->payload.request.op.xattr.sizeofvalue;
    char path[pathlen+1];
    memset(path, 0, pathlen+1);
    memcpy(path, cmd->payload.request.op.xattr.params, pathlen+1);
#ifdef DEBUG
    dprintf(stderr, "LISTXATTR: path[%s].\n", path);
#endif

    /* Check with the security layer if the user should be allowed to
     * access the file */
    if(my_ops.up_check_access){
        if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret,  cmd->payload.request.op.fileop.path, NULL, cmd->payload.request.type) != PROCEED){
            dprintf(stderr, "check_access: access denied\n");
            error_reply(ctx, cmd->header.sequence, ret);
            return -1;
        }
    }
  
    ret = listxattr (path, reply->payload.response.rop.raw, sizeofvalue);
    if (ret < 0) {
        dprintf(stderr, "listxattr failed path[%s].\n", path);
        error_reply(ctx, cmd->header.sequence, errno);
        return -1;
    }

    /* client just wants to know the size of the list */
    else if (sizeofvalue == 0){
        sizeofvalue = build_status(reply, ret, COREFS_RESPONSE_STATUS);
        char buf[sizeofvalue];
        ret = encap_corefs_header(buf, reply);
        encap_corefs_response(buf + ret, reply);
        send_packet(ctx, buf, sizeofvalue);
        return 0;
    }
    else {  /*  send the attribute value */
        sizeofvalue =
            build_response_data(reply,  reply->payload.response.rop.raw, ret);
        char buf[sizeofvalue];
        ret = encap_corefs_header(buf, reply);
        encap_corefs_response(buf + ret, reply);
        send_packet(ctx, buf, sizeofvalue);
    }
    return 0;
}


int handle_removexattr(COMMCTX* ctx, corefs_packet* cmd)
{
    int ret = 0;
    corefs_packet * reply = (corefs_packet*)g_buffer; // the status reply

    int pathlen = cmd->payload.request.op.xattr.pathlen;
    int namelen = cmd->payload.request.op.xattr.namelen;
    unsigned int sizeofvalue =  cmd->payload.request.op.xattr.sizeofvalue;
    char path[pathlen+1];
    char attrname[namelen+1];
    memset(path, 0, pathlen+1);
    memset(attrname, 0, namelen+1);
    memcpy(path, cmd->payload.request.op.xattr.params, pathlen+1);
    memcpy(attrname, cmd->payload.request.op.xattr.params+pathlen+1, namelen);
#ifdef DEBUG
    dprintf(stderr, "REMOVEXATTR: path[%s] attrname [%s].\n", path, attrname);
#endif
    /* Check with the security layer if the user should be allowed to
     * access the file */
    if(my_ops.up_check_access){
        if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret,  cmd->payload.request.op.fileop.path, NULL,  cmd->payload.request.type) != PROCEED){
            dprintf(stderr, "check_access: access denied\n");
            error_reply(ctx, cmd->header.sequence, ret);
            return -1;
        }
    }
  
		//log
    ret = log_removexattr(path, attrname);

    ret = removexattr(path, attrname);
    if (ret < 0) {
        dprintf(stderr, "removexattr failed path[%s] attr. name [%s].\n",
                path, attrname);
        error_reply(ctx, cmd->header.sequence, errno);
        return -1;
    }
    sizeofvalue = build_status(reply, ret, COREFS_RESPONSE_STATUS);
    char buf[sizeofvalue];
    ret = encap_corefs_header(buf, reply);
    encap_corefs_response(buf + ret, reply);
    send_packet(ctx, buf, sizeofvalue);
    return 0; 
}

#endif  /* HAVE_SETXATTR */

int handle_readdir(COMMCTX* ctx, corefs_packet* cmd)
{
    corefs_packet* reply=(corefs_packet*)g_buffer;
    DIR* d;
    struct dirent* de;
    int count = 0;
    const char * path = cmd->payload.request.op.fileop.path;
    off_t prev_offset = 0;
    int ret = 0;
  
  
#ifdef DEBUG
    dprintf(stderr, "READDIR: directory \'%s\'.\n", path);
#endif
    /* Check with the security layer if the user should be allowed to
     * access the file */
    if(my_ops.up_check_access){
        if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret,  cmd->payload.request.op.fileop.path, NULL,  cmd->payload.request.type) != PROCEED){
            dprintf(stderr, "check_access: access denied\n");
            error_reply(ctx, cmd->header.sequence, ret);
            return -1;
        }
    }
    d = opendir(path);
    if (!d) {
        dprintf(stderr, "opendir failed.\n");
        error_reply(ctx, cmd->header.sequence, errno);
        return -1;
    }
	
    seekdir(d, cmd->payload.request.op.fileop.offset);
  
    reply->payload.response.more_offset = 0;
  
    while((de = readdir(d)) != NULL) {
        /* Make sure that we can fit everyting in this buffer */
        if((strlen(de->d_name)+ 1 + sizeof(de->d_type) + count)  <= BUFFERSIZE + header_size + RESPONSE_BASE_SIZE(reply->payload.response)){
            /* Go ahead and copy the stuff in the buffer */
            reply->payload.response.rop.raw[count++] = de->d_type;
            strcpy(reply->payload.response.rop.raw + count, de->d_name);
            count += strlen(de->d_name)+1; // +1 for terminating null
        }
        else{
            /* Tell the client what offset to start the the next readdir
             * from */
            reply->payload.response.more_offset = prev_offset;
            break;
        }
        prev_offset = telldir(d);
    
    }
  
    closedir(d);

    /* Build the response packet */
    unsigned int packet_size = 0;
    if(reply->payload.response.more_offset != 0)
        packet_size = build_response_with_moredata(reply, reply->payload.response.rop.raw, count, reply->payload.response.more_offset);
    else
        packet_size =
            build_response_data(reply, reply->payload.response.rop.raw, count);
  
    /* encapsualte it */
    ret =  encap_corefs_header(g_buffer2, reply);
    encap_corefs_response(g_buffer2 + ret, reply);
#ifdef DEBUG_NETWORK
    dprintf(stderr, "Printing response packet\n");
    print_packet(*reply);
#endif    
    send_packet(ctx, g_buffer2, packet_size);
    return 0;
	
}

int handle_getattr(COMMCTX* ctx, corefs_packet* cmd)
{
    corefs_packet reply;
    corefs_request req = cmd->payload.request;
  
    struct stat st;
    int ret;
  
#ifdef DEBUG
    dprintf(stderr, "GETATTR: file \'%s\'.\n", req.op.fileop.path);
#endif

    /* Check with the security layer if the user should be allowed to access the file */
    if(my_ops.up_check_access){
        if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret,  cmd->payload.request.op.fileop.path, NULL, cmd->payload.request.type) != PROCEED){
            dprintf(stderr, "check_access: access denied\n");
            error_reply(ctx, cmd->header.sequence, ret);
            return -1;
        }
    }
  
    ret=lstat(req.op.fileop.path, &st);
    if (ret < 0) {
        dprintf(stderr, "stat failed.\n");
        error_reply(ctx, cmd->header.sequence, errno);
        return -1;
    }

    /* Build the response packet */
    build_header(&reply, COREFS_RESPONSE);

    reply.payload.response.type = COREFS_RESPONSE_ATTR;
    reply.payload.response.rop.attr.mode = st.st_mode;
    reply.payload.response.rop.attr.uid  = st.st_uid;
    reply.payload.response.rop.attr.gid  = st.st_gid;
    reply.payload.response.rop.attr.size = st.st_size; // fixme: truncated? 64-bit?
    reply.payload.response.rop.attr.mtime= st.st_mtime;
    reply.payload.response.rop.attr.atime= st.st_atime;
    reply.payload.response.rop.attr.ctime= st.st_ctime;
    reply.payload.response.rop.attr.nlinks = st.st_nlink;
    reply.header.payload_size = SIZEOF_ATTR(reply.payload.response.rop.attr) + RESPONSE_BASE_SIZE(reply.payload.response);
  

    /* Encapsulate the packet */
    ret = encap_corefs_header(g_buffer, &reply);
    ret += encap_corefs_response(g_buffer + ret, &reply);
#ifdef DEBUG_NETWORK
    dprintf(stderr, "Printing response packet\n");
    print_packet(reply);
#endif  
    send_packet(ctx, g_buffer, ret);
    return 0;
}

int handle_readlink(COMMCTX* ctx, corefs_packet* cmd)
{
    corefs_packet* reply = (corefs_packet*)g_buffer;
    int ret;
    const char* path = cmd->payload.request.op.fileop.path;
    unsigned int size = cmd->payload.request.op.fileop.size;
#ifdef DEBUG
    dprintf(stderr, "READLINK: file \'%s\'.\n", path);
#endif
    /* Check with the security layer if the user should be allowed to
     * access the file */
    if(my_ops.up_check_access){
        if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret,  cmd->payload.request.op.fileop.path,  NULL, cmd->payload.request.type) != PROCEED){
            dprintf(stderr, "check_access: access denied\n");
            error_reply(ctx, cmd->header.sequence, ret);
            return -1;
        }
    }
    ret = readlink(path, reply->payload.response.rop.raw, size);
    if (ret == -1) {
        dprintf(stderr, "readlink failed: error no [%d]\n",errno);
        error_reply(ctx, cmd->header.sequence, errno);
        return -1;
    }
    size = build_response_data(reply, reply->payload.response.rop.raw, ret);
    ret = encap_corefs_header(g_buffer2, reply);
    encap_corefs_response(g_buffer2+ ret, reply);
    send_packet(ctx, g_buffer2, size);
    return 0;
	
}


/*  Handle a bunch of different commands that don't need */
/*  to do anything hard and just return status info. */
/*  This makes the network protocol simpler. */

int handle_simple(COMMCTX* ctx, corefs_packet* cmd)
{
    corefs_packet reply;
    int ret = 0;
    corefs_simple * simp = (corefs_simple*)&cmd->payload.request.op.simple;
    unsigned int mode;
    struct utimbuf utim;

    switch (simp->type) {

    case COREFS_SIMPLE_UTIME:
#ifdef DEBUG0
        dprintf(stderr, "UTIME: \'%s\' w/ actime %u modtime %u mode %o\n",
                simp->path1, simp->offset, simp->mode1);
#endif

        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }
        utim.actime = simp->offset;
        utim.modtime = simp->mode1;
        ret = my_ops.utime(simp->path1, &utim);
        break;
      
    case COREFS_SIMPLE_CHMOD:
#ifdef DEBUG0
        dprintf(stderr,"CHMOD: \'%s\' w/ mode %o\n", simp->path1, simp->mode1);
#endif
        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }

				//log
				ret = log_chmod(simp->path1, simp->mode1);

        ret = my_ops.chmod(simp->path1, simp->mode1);
        break;
      
    case COREFS_SIMPLE_TRUNCATE:
#ifdef DEBUG
        dprintf(stderr, "TRUNCATE: \'%s\' %u\n", simp->path1, simp->offset);
#endif
        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }

				//log
        ret = log_truncate(simp->path1, simp->offset);

        ret = my_ops.truncate(simp->path1, simp->offset);
        break;

    case COREFS_SIMPLE_MKNOD:
#ifdef DEBUG
        dprintf(stderr,"MKNOD: \'%s\' w/ mode %o\n", simp->path1, simp->mode1);
#endif
		
        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }
        // fixme: iozone won't work without this.  why?
        // (if mode bits are all zeros, set to 0666).
        mode = simp->mode1;
        if (!(mode & 0666)) mode |= 0666;

				//log
        ret = log_mknod(simp->path1, mode, 0);

        ret = my_ops.mknod(simp->path1, mode, 0);
        break;

    case COREFS_SIMPLE_UNLINK:
#ifdef DEBUG
        dprintf(stderr, "UNLINK: \'%s\'\n", simp->path1);
#endif
        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }

				//log
        ret = log_unlink(simp->path1);

        ret = my_ops.unlink(simp->path1);

        break;

    case COREFS_SIMPLE_SYMLINK:
#ifdef DEBUG
        dprintf(stderr, "SYMLINK: old \'%s\' new  \'%s\'\n",
                simp->path1, simp->path2);
      
#endif
        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }

				//log
        ret = log_symlink(simp->path1, simp->path2);

        ret = my_ops.symlink(simp->path1, simp->path2);
        break;
      
    case COREFS_SIMPLE_LINK:
#ifdef DEBUG
        dprintf(stderr, "LINK: old \'%s\' new  \'%s\'\n",
                simp->path1, simp->path2);
#endif
        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }
        ret = my_ops.link(simp->path1, simp->path2);
        break;
      
    case COREFS_SIMPLE_RENAME:
#ifdef DEBUG
        dprintf(stderr, "RENAME: old \'%s\' new  \'%s\'\n",
                simp->path1, simp->path2);
#endif
        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }
        ret = my_ops.rename(simp->path1, simp->path2);
        break;

    case COREFS_SIMPLE_MKDIR:
#ifdef DEBUG
        dprintf(stderr, "MKDIR: \'%s\'\n", simp->path1);
#endif
        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }
        ret = my_ops.mkdir(simp->path1, simp->mode1);

        break;

    case COREFS_SIMPLE_RMDIR:
#ifdef DEBUG
        dprintf(stderr, "RMDIR: \'%s\'\n", simp->path1);
#endif
        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }
        ret = my_ops.rmdir(simp->path1);
        break;
    case COREFS_SIMPLE_OPEN:
#ifdef DEBUG
        dprintf(stderr, "OPEN: \'%s\'\n", simp->path1);
    
#endif
        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }
        ret = my_ops.open(simp->path1, simp->mode1);
        break;
    case COREFS_SIMPLE_RELEASE:
        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }
        ret = my_ops.release(simp->path1, simp->mode1);
#ifdef DEBUG
        dprintf(stderr, "RELEASE: \'%s\'\n", simp->path1);
#endif
        break;

    case COREFS_SIMPLE_ACCESS:
        /* Check with the security layer if the user should be allowed to
         * access the file */
        if(my_ops.up_check_access){
            if(my_ops.up_check_access(ctx, &(cmd->payload.request.user_ids), &ret, simp->path1, simp->path2, simp->type) != PROCEED){
                dprintf(stderr, "check_access: access denied\n");
                error_reply(ctx, cmd->header.sequence, ret);
                return -1;
            }
        }
        ret = my_ops.access(simp->path1, simp->mode1);
#ifdef DEBUG
        dprintf(stderr, "ACCESS: \'%s\' mode %d\n", simp->path1, simp->mode1);
#endif
        break;

    default:
        dprintf(stderr, "unknown simple command.\n");
        ret = -1;
        errno = EOPNOTSUPP;
    }

    if (ret < 0) {
        dprintf(stderr, "simple command failed, errno %s\n", strerror(errno));
        error_reply(ctx, cmd->header.sequence, errno);
        return -1;
    }
	

    unsigned int packet_size = build_status(&reply, 0, COREFS_RESPONSE_STATUS);
    ret = encap_corefs_header(g_buffer, &reply);
    encap_corefs_response(g_buffer + ret, &reply);
    send_packet(ctx, g_buffer, packet_size);
    return 0;
}


int handle_fileop(COMMCTX * ctx, corefs_packet * cmd)
{
    switch(cmd->payload.request.op.fileop.type){
    case COREFS_REQUEST_GETATTR:
        my_ops.handle_getattr(ctx, cmd);
        break;
    case COREFS_REQUEST_READ:
        my_ops.handle_read(ctx, cmd);
        break;
    case COREFS_REQUEST_WRITE:
        my_ops.handle_write(ctx, cmd);
        break;
    case COREFS_REQUEST_READDIR:
        my_ops.handle_readdir(ctx, cmd);
        break;
    case COREFS_REQUEST_READLINK:
        my_ops.handle_readlink(ctx, cmd);
        break;
    default:
        dprintf(stderr, "handle_fileop: bad type 0x%x\n",
                cmd->payload.request.op.fileop.type);
        error_reply(ctx, cmd->header.sequence, EOPNOTSUPP);
        break;
    }
    return 0;
}

int handle_xattr(COMMCTX * ctx, corefs_packet * cmd)
{

#ifdef HAVE_SETXATTR
    switch(cmd->payload.request.op.xattr.type){
    case COREFS_XATTR_SETXATTR:
        my_ops.handle_setxattr(ctx, cmd);
        break;
    case COREFS_XATTR_GETXATTR:
        my_ops.handle_getxattr(ctx, cmd);
        break;
    case COREFS_XATTR_REMOVEXATTR:
        my_ops.handle_removexattr(ctx, cmd);
        break;
    case COREFS_XATTR_LISTXATTR:
        my_ops.handle_listxattr(ctx, cmd);
        break;
    default:
        dprintf(stderr, "handle_xttr: received unexpected type %i.\n",
                cmd->payload.request.op.xattr.type);
        error_reply(ctx, cmd->header.sequence, EOPNOTSUPP);
        break;
    }
#endif
    return 0;
}

int check_sanity(corefs_packet * cmd)
{
    /* check sanity of the request */   
    if (cmd->header.magic != COREFS_MAGIC) {
        dprintf(stderr, "bad magic number.\n");
        return -1;
    }
  
    corefs_request * req = (corefs_request *)&cmd->payload.request;
  
    if(req->user_ids.num_sgids > MAX_COREFS_GIDS) 
        return EUSERS; // don't have a good errno for this
  
    if(req->type == COREFS_REQUEST_FILEOP){
        if(req->op.fileop.pathlen > MAX_COREFS_PATH)
            return ENAMETOOLONG;
    }
    if(req->type == COREFS_REQUEST_SIMPLE){
        if(req->op.simple.path1len > MAX_COREFS_PATH ||
           req->op.simple.path2len  > MAX_COREFS_PATH)
            return ENAMETOOLONG;
    }
    return 0;
  
}

int handle_command(COMMCTX *ctx, corefs_packet *cmd, int packetsize)
{
 
    int ret = check_sanity(cmd);
    if(ret){
        error_reply(ctx, cmd->header.sequence, ret);
        return 0;
    }

		//log the cmd

		//exe the cmd from file
    /*
		 *bzero(cmd, BUFFERSIZE);
		 *FILE *f = fopen(log_path,"rw"); 
		 *if(f == NULL) {
		 *  printf("Error in opening file: %s", log_path);
		 *}
		 *fgets(cmd, BUFFERSIZE, f);
		 *fclose(f);
     */

  
    // process request
#ifdef DEBUG_NETWORK
    dprintf(stderr, "Printing request packet\n");
    print_packet(*cmd);
#endif
    //	dprintf(stderr, "-- got new request. -- \n");
    switch(cmd->payload.request.type) {
    case COREFS_REQUEST_FILEOP:
        handle_fileop(ctx, cmd);
        break;
    case COREFS_REQUEST_SIMPLE:
        handle_simple(ctx, cmd);
        break;
    case COREFS_REQUEST_XATTR:
        handle_xattr(ctx, cmd);
        break;
    default:
        dprintf(stderr, "handle_connection: received unexpected packet type %i.\n", cmd->header.type);
        error_reply(ctx, cmd->header.sequence, EPROTO);
        break;
    }
    return 0;
}

int handle_connection(COMMCTX* ctx)
{
    char* buffer;
    int packetsize;
    corefs_packet* cmd;

    buffer=(char*)malloc(BUFFERSIZE);
    char * temp_buffer=(char*)malloc(BUFFERSIZE);
    cmd=(corefs_packet*)temp_buffer;

    while(1) {

        memset(buffer,0, BUFFERSIZE);
        /* receive client request */    
        if ((packetsize = receive_packet(ctx, buffer)) <= 0) {
            return -1;
        }
 
        /* convert to host orderx */
        memcpy(temp_buffer, buffer,  header_size);
        decap_corefs_request(buffer + header_size, cmd);
 
        /* handle the request */
        handle_command(ctx, cmd, packetsize);
    }
    if(buffer) free(buffer);
    if(temp_buffer)free(temp_buffer);
  
    return 0;
}

// returns 0 on success, 1 on failure.
int daemonize()
{
    // to become a unix daemon, must fork twice.
    switch (fork()) {
    case 0: break;      // child continues.
    case -1: return 1; // fork() failed.
    default: _exit(0);  // parent exits.
    }

    if (setsid() < 0) return 1; // make sure we're process group leader.

    switch (fork()) {
    case 0: break;      // child continues.
    case -1: return 1; // fork() failed.
    default: _exit(0);  // parent exits.
    }

    // close stdin/stdout/stderr
    close(0);
    close(1);
    close(2);

    return 0;
}

void server_op_init(void){

    /* Setup all the initial function pointers */
    my_ops.handle_getattr = handle_getattr;
    my_ops.handle_read = handle_read;
    my_ops.handle_write = handle_write;
    my_ops.handle_readdir = handle_readdir;
    my_ops.access = handle_access;
    my_ops.truncate = truncate;
    my_ops.mknod = mknod;
    my_ops.unlink = unlink;
    my_ops.rename = rename;
    my_ops.symlink = symlink;
    my_ops.handle_readlink = handle_readlink;
    my_ops.mkdir = mkdir;
    my_ops.rmdir = rmdir;
    my_ops.open = handle_open;
    my_ops.release = handle_release;
    my_ops.utime = utime;
    my_ops.chmod = chmod;
    my_ops.link = link;
#ifdef HAVE_SETXATTR
    my_ops.handle_setxattr = handle_setxattr;
    my_ops.handle_getxattr = handle_getxattr;
    my_ops.handle_listxattr = handle_listxattr;
    my_ops.handle_removexattr = handle_removexattr;
#endif
}


void usage(char * prog)
{
    fprintf(stderr, "usage: %s <corefs usage> <upper-layer usage>\n", prog);
    fprintf(stderr, "corefs usage: [-b] [-f] [-P portnumber]\n");
    fprintf(stderr, "-b: run the server as a background daemon\n");
    fprintf(stderr, "-f: fork a server process per client connection\n");
    fprintf(stderr, "-P: server port number\n");
}


int parse_arguments(int argc, char** argv ,char * config_path)
{
    int ch, option_index=0;
    char argstr[MAX_OPTS]="bfhP:";
    opterr=0; // ignore unknown options
  
    static struct option long_options[] = {
        {"background", 0, 0, 'b'},
        {"fork", 0, 0, 'f'},
        {"port",1,0,'P'},
        {"help",0,0,'h'},
        {0,0,0,0}
    };
  
  
    /*  Check if upper layer has got all of its command line args */
    if(my_ops.up_parse_arguments){    
        if(my_ops.up_parse_arguments((char*)argstr, argc, argv) != PROCEED) {
            usage(argv[0]);
            exit(1);
        }
    }
  
    option_index = 0;
    optind = 0;
  
    while ((ch=getopt_long(argc, argv, argstr, long_options, &option_index))
           != -1) {
        switch (ch) {
        case 'b': {
            become_daemon = 1;
        }
            break;
        case 'f': {
            fork_client = 1;
        }
            break;
        case 'P': {
            if(optarg)
                server_port = atoi(optarg);
        }
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
            break;
        default:
            break;
        }
    }
    return 0;
}


int main(int argc, char **argv)
{
    int listenfd, maxfd, flag, packetsize;
    struct sockaddr_in server_addr, peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);
    fd_set read_set, temp_set;
    int i, num_ready, max_client_num, connfd, clients[FD_SETSIZE];  
    COMMCTX* temp_ctx=NULL;
    /* list for keeping track of ctx's */
    list_head head;
    list_tail *tail;
    char *fdchar = (char*)calloc(FDLEN,1);
    init_list_head(&head);


    /* Initialize header size */
    init_sizes();
    /* Initialize function pointers */
    server_op_init();

    /* Call the upper layer's init function */
    up_server_init(&my_ops);

    /* Parse command line arguments */
    parse_arguments(argc, argv, NULL);
  
  
    g_buffer=(char*)calloc(BUFFERSIZE,1);
    g_buffer2=(char*)calloc(BUFFERSIZE,1);

    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(server_port);

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        fprintf(stderr, "ERROR: socket creation failed: %s\n",
                strerror(errno));
        return 1;
    }
     
    flag=1;
    if (setsockopt(listenfd, IPPROTO_TCP, TCP_NODELAY,
                   (char*) &flag, sizeof(int))) {
        fprintf(stderr, "ERROR: unable to set socket options.\n");
    }

    if (bind(listenfd, (struct sockaddr *)&server_addr, sizeof(server_addr))
        < 0) {
            fprintf(stderr, "ERROR: bind on control socket failed: %s\n",
                    strerror(errno));
            return 1;
    }
    dprintf(stderr,"bind successful.\n");

    if (become_daemon) {
        dprintf(stderr,"Moving to background.\n");
        daemonize();
    }
  

  
    if (listen(listenfd, MAXCONN) < 0) {
        fprintf(stderr, "ERROR: listen on control socket failed: %s\n",
                strerror(errno));
        return 1;
    }

  
    dprintf(stderr, "waiting for connection on port %d.\n", server_port);

    if (fork_client == 0) {
        
        for (i=0; i<FD_SETSIZE; i++) {
            clients[i] = -1;
        }
        maxfd = listenfd;
        FD_ZERO(&read_set);
        FD_SET(listenfd, &read_set);
        max_client_num=-1;
        char *buffer=(char*)calloc(BUFFERSIZE,1);
        char *buf=(char*)calloc(BUFFERSIZE,1);
      
        corefs_packet *cmd=(corefs_packet*)buf;
      
        while(1) {
            /* copy the entire set to the temporary set select modifies
             * the set it is sent, this is why temp_set is used and
             * read_set is saved as a master set */
            memcpy(&temp_set, &read_set, sizeof(temp_set));
        
            /*select - returns when one or more sockets are ready to be ready*/
            num_ready = select(maxfd+1, &temp_set, NULL, NULL, NULL);
          
            /* checks to see if listenfd is ready to read (ie new
             * connection ready) */
            if (FD_ISSET(listenfd, &temp_set)) {
                connfd = accept(listenfd,
                                (struct sockaddr *)&peer_addr, &peer_addrlen);
                if (connfd < 0) { 
                    fprintf(stderr, "ERROR: accept failed for control socket: %s, errno[%d]\n", strerror(errno),errno);
                    break;
                }
                /* find the first available space in the client array,
                 * and store the new client's file decriptor there */
                for (i=0; i<FD_SETSIZE; i++) {
                    if (clients[i] < 0) {
                        clients[i] = connfd;
                        break;
                    }
                }
                /* If i iterates through all the possible spaces in the client
                   array, it must not have found an open one.
                   Close this connection then, we have no room for it */
                if (i == FD_SETSIZE) {
                    dprintf(stderr, "server: incoming connection dropped\n");
                    close(connfd);
                } else {
                    dprintf(stderr,"accepted connection.\n");
          
                    /* setup a ctx for the new client and put it in the list */
                    memset(fdchar,0,FDLEN);
                    sprintf(fdchar,"%d",connfd);
                    temp_ctx = (COMMCTX*)calloc(sizeof(COMMCTX), 1);
                    temp_ctx->sock_ctx=(SOCK_CTX*)calloc(sizeof(SOCK_CTX), 1);
                    ((SOCK_CTX*)(temp_ctx->sock_ctx))->sock=connfd;

                    if(my_ops.up_new_client) {
                        char my_dns[4096];
                        memset(my_dns,4096,0);
                        gethostname(my_dns, 4095);
                        /* TODO: get client ip in string */
                        my_ops.up_new_client(NULL,my_dns,temp_ctx);
                    }
                    if (insert_info_ptr(&head, &tail, fdchar, FDLEN,
                                        (void *) temp_ctx) < 0 ) {
                        dprintf(stderr,
                                "server: error inserting ctx into list\n");
                        /* cleanup and continue */
                        close(connfd);
                        free(temp_ctx->sock_ctx);
                        free(temp_ctx);
                        temp_ctx = NULL;
                    } else {
          
                        /* set the new client as active in the read_set */
                        FD_SET(connfd, &read_set);
                        if (connfd > maxfd)
                            maxfd = connfd;
                        if (i > max_client_num)
                            max_client_num = i;
                    }
                }
                if (--num_ready <= 0)
                    continue;
            }
        
        
            for (i=0; i<=max_client_num; i++) {
                /* find the file descriptors that have active clients */
                if ((connfd = clients[i])<0) {
                    continue;
                }
                //check to see if the socket is ready to read
                if (FD_ISSET(connfd, &temp_set)) {
                    memset(fdchar,0,FDLEN);
                    sprintf(fdchar,"%d",connfd);
                    if (get_info_ptr(&head,&tail,
                                     fdchar,FDLEN,(void *)&temp_ctx)<0) {
                        dprintf(stderr,"server: cannot find ctx in list. Inserted incorrectly?\n");
                        dprintf(stderr,"closing connection\n");
                        close(connfd);
                    } else {
                        /* read packet */
                        packetsize = receive_packet(temp_ctx, buffer);
                        if (packetsize <= 0) {
                            //client closed connection, remove client
                            close(connfd);
                            FD_CLR(connfd, &read_set);
                            clients[i] = -1;
                            if (remove_info(&head,&tail,fdchar,FDLEN)<0) {
                                dprintf(stderr, "server: cannot remove ctx from list\n");
                            }
                            if (temp_ctx->sock_ctx) {
                                free(temp_ctx->sock_ctx);   
                                temp_ctx->sock_ctx=NULL;
                            }
                            if (temp_ctx) {
                                free(temp_ctx);
                                temp_ctx=NULL;
                            }
                        }
                        else {
                            /* convert to host order */
                            memcpy(buf, buffer, header_size);
                            /* Use separate buffers  */
                            decap_corefs_request(buffer + header_size, cmd); 
                            /* handle the received command */
                            handle_command(temp_ctx, cmd, packetsize);
                        }
                    }
                    if (--num_ready <= 0) {
                        break;
                    }
                }
            }
        
            temp_ctx=NULL;
            memset(buffer,0,BUFFERSIZE);
            memset(buf,0,BUFFERSIZE);
        }
      
        free(buffer);
        if(buf) free(buf);
      
        free(fdchar);
      
        return 0;
    }
    
    else {
        /* we want to fork per connection */
        while(1) {
            int pid;
          
            connfd=accept(listenfd,(struct sockaddr*)&peer_addr,&peer_addrlen);
            if (connfd < 0) { 
                dprintf(stderr, "ERROR: accept failed for control socket: %s, errno[%d]\n", strerror(errno),errno);
                break;
            }
            // TODO: for parent probably disable SIGCHLD and SIGINT
            dprintf(stderr,"accepted connection.\n");
            switch (pid=fork()) {
            case -1:
                dprintf(stderr,"Error during fork().\n");
                _exit(1);
            case 0:
                // this is the child.
                // TODO: disable SIGINT
                close(listenfd); // close the parent's socket.
                break; // child continues below.
            default:
                // this is the parent.
                close(connfd); // close the child's socket.
                while(waitpid(-1, NULL, WNOHANG)) {} // periodically reap zombies.
                continue; // parent waits for a new connection.
            }
            /* if fork_client is true, we are the child process.  if
             * fork_client is false, we are the only process. either
             * way, we now handle the incoming connection. */
            temp_ctx = (COMMCTX*)calloc(sizeof(COMMCTX), 1);
            temp_ctx->sock_ctx = (SOCK_CTX*)calloc(sizeof(SOCK_CTX), 1);
            ((SOCK_CTX*)(temp_ctx->sock_ctx))->sock = connfd;

            if(my_ops.up_new_client) {
                /* TODO: get client ip in string */
                char my_dns[4096];
                memset(my_dns,4096,0);
                gethostname(my_dns, 4095);
                my_ops.up_new_client(NULL,my_dns,temp_ctx);
            }
            
            handle_connection(temp_ctx);
            
            if (temp_ctx->sock_ctx) {
                free(temp_ctx->sock_ctx);
                temp_ctx->sock_ctx=NULL;
            }
            if (temp_ctx) {
                free(temp_ctx);
                temp_ctx=NULL;
            }
            _exit(0); // child process exits.
        }
    }
    return 0;
}
