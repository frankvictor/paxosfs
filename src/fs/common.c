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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include "common.h"
#include "protocol.h"


/* Variables to hold size of strucutres. These should be initialized
 * only once and should not need any locking. */
 size_t header_size = 0;


void init_sizes(void){
  corefs_header header;
  /*   Initialize the sizes */
   header_size = SIZEOF_HEADER(header);
}


inline int donothing(FILE* f, const char* fmt, ...) { return 0; }

/* encodes the header structure and copies it into the location
 * pointer by buf. */
unsigned int encap_corefs_header(char * buf, corefs_packet * pkt){

  unsigned int pos = 0;
  
  /* Copy header */
  corefs_header * header = &pkt->header;

  unsigned int ui = htonl(header->magic);
  *((unsigned int *)(buf + pos)) = ui;
  
  //  memcpy((buf + pos), &ui, sizeof(ui));
  pos +=  sizeof(ui);
  
  ui = htonl(header->type);
  *((unsigned int *)(buf + pos)) = ui;
  //  memcpy((buf + pos), &ui, sizeof(ui));
  pos +=  sizeof(ui);

  ui = htonl(header->sequence);
  *((unsigned int *)(buf + pos)) = ui;
  //memcpy((buf + pos), &ui, sizeof(ui));
  pos +=  sizeof(ui);

  ui = htonl(header->payload_size);
  *((unsigned int *)(buf + pos)) = ui;
  // memcpy((buf + pos), &ui, sizeof(ui));
  pos +=  sizeof(ui);


  return pos;
}


/* dencodes the header structure and copies it into the location
 * pointer by pkt. Note the receive function decaps the header by
 * default. So this function does not have to be used outside the
 * receive function; otherwise, the header will be decaped twice!*/
unsigned int decap_corefs_header(char * buf, corefs_packet * pkt){

  unsigned int pos = 0;
  
  /* Copy header */
  corefs_header * header = &pkt->header;
  
  header->magic = ntohl(*(unsigned int *)(buf + pos));
  pos += sizeof(unsigned int);

  header->type = ntohl(*(unsigned int *)(buf + pos));
  pos += sizeof(unsigned int);

  header->sequence = ntohl(*(unsigned int *)(buf + pos));
  pos += sizeof(unsigned int);

  header->payload_size = ntohl(*(unsigned int *)(buf + pos));
  pos += sizeof(unsigned int);


  return pos;
}


/* encodes the request structure and copies it into the location
 * pointer by buf. Make sure that buf points to the location where you
 * want the request to be copied and not the the location where the
 * header should be copied.  */
unsigned int encap_corefs_request(char * buf, corefs_packet * pkt){

  unsigned int pos =0;
  unsigned int ui;
  unsigned int i;
  
  corefs_request *req = (corefs_request *) &pkt->payload.request;
  
  ui = htonl(req->type);
  *(unsigned int *)(buf + pos) = ui;
  //  memcpy((buf + pos), &ui, sizeof(ui));
  pos +=  sizeof(ui);
  
  ui = htonl(req->user_ids.uid);
  *(unsigned int *)(buf + pos) = ui;
  //  memcpy((buf + pos), &ui, sizeof(ui));
  pos +=  sizeof(ui);
    
  ui = htonl(req->user_ids.gid);
  *(unsigned int *)(buf + pos) = ui;
  // memcpy((buf + pos), &ui, sizeof(ui));
  pos +=  sizeof(ui);
    
  ui = htonl(req->user_ids.num_sgids);
  *(unsigned int *)(buf + pos) = ui;
  //  memcpy((buf + pos), &ui, sizeof(ui));
  pos +=  sizeof(ui);
    
  for(i = 0; i < req->user_ids.num_sgids; i++){
    ui = htonl(req->user_ids.sgids[i]);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);
  }

  /* The request contails raw data */
  if(req->type == COREFS_REQUEST_DATA){
    memcpy((buf + pos), req->op.raw, pkt->header.payload_size - pos);
    pos =  pkt->header.payload_size;
  }
  /* The request contains simple op */
  else if(req->type == COREFS_REQUEST_SIMPLE){
    corefs_simple * simple_op = (corefs_simple*)&req->op.simple;
    
    ui = htonl(simple_op->type);
    *(unsigned int *)(buf + pos) = ui;
    //    memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(simple_op->offset);
    *(unsigned int *)(buf + pos) = ui;
    //    memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(simple_op->mode1);
    *(unsigned int *)(buf + pos) = ui;
    //    memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(simple_op->path1len);
    *(unsigned int *)(buf + pos) = ui;
    //    memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(simple_op->path2len);
    *(unsigned int *)(buf + pos) = ui;
    // memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    memcpy((buf + pos),  simple_op->path1,  simple_op->path1len);
    pos +=  simple_op->path1len;
    
    memcpy((buf + pos),  simple_op->path2,  simple_op->path2len);
    pos +=  simple_op->path2len;
  }
  /* The request contains file op */
  else if(req->type == COREFS_REQUEST_FILEOP){
    corefs_fileop * file_op = (corefs_fileop*)&req->op.fileop;

    ui = htonl(file_op->type);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);
    
    ui = htonl(file_op->offset);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(file_op->size);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);
    
    ui = htonl(file_op->pathlen);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);
    
    memcpy((buf + pos),  file_op->path,  file_op->pathlen);
    pos +=  file_op->pathlen;
  }
  /* The request for xattr op */
  else if(req->type == COREFS_REQUEST_XATTR){
    corefs_xattr * xattr = (corefs_xattr*)&req->op.xattr;

    ui = htonl(xattr->type);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);
    
    ui = htonl(xattr->flags);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);
    
    ui = htonl(xattr->sizeofvalue);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(xattr->pathlen);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(xattr->namelen);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    memcpy((buf + pos), xattr->params,  xattr->pathlen + 1 +  xattr->namelen);
    pos += xattr->pathlen+ 1 +  xattr->namelen;
    
  }
  
  return pos;
}



/* decodes the request structure and copies it into the location
 * pointed by pkt. Make sure that buf points to the location from
 * where you want the request to be copied and not the location of the
 * header.  */
unsigned int decap_corefs_request(char * buf, corefs_packet * pkt){

  unsigned int pos =0;
  unsigned int i;
  
  corefs_request *req = (corefs_request *) &pkt->payload.request;

  req->type = ntohl(*(unsigned int *)(buf + pos));
  pos += sizeof(unsigned int);

  req->user_ids.uid = ntohl(*(unsigned int *)(buf + pos));
  pos += sizeof(unsigned int);

  req->user_ids.gid = ntohl(*(unsigned int *)(buf + pos));
  pos += sizeof(unsigned int);

  req->user_ids.num_sgids = ntohl(*(unsigned int *)(buf + pos));
  pos += sizeof(unsigned int);
    
  for(i = 0; i < req->user_ids.num_sgids; i++){
    req->user_ids.sgids[i] =  ntohl(*(unsigned int *)(buf + pos));
    pos +=  sizeof(unsigned int);
  }

  /* The request contails raw data */
  if(req->type == COREFS_REQUEST_DATA){
    memcpy(req->op.raw, (buf + pos), pkt->header.payload_size - pos);
    pos =  pkt->header.payload_size;
  }
  /* The request contains simple op */
  else if(req->type == COREFS_REQUEST_SIMPLE){
    corefs_simple * simple_op = (corefs_simple*)&req->op.simple;

    simple_op->type = ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);
    
    simple_op->offset =  ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);
    
    simple_op->mode1 =  ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);

    simple_op->path1len  =  ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);

    simple_op->path2len  =  ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);
    
    memcpy((char*)simple_op->path1, (buf + pos), simple_op->path1len);
    pos +=  simple_op->path1len;
    simple_op->path1[simple_op->path1len] = '\0';
    
    memcpy((char*)simple_op->path2, (buf + pos),  simple_op->path2len);
    simple_op->path2[simple_op->path2len] = 0;
    pos +=  simple_op->path2len;
    
  } 
  /* The request contains file op */
  else if(req->type == COREFS_REQUEST_FILEOP){
    corefs_fileop * file_op = (corefs_fileop*)&req->op.fileop;

    file_op->type  =  ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);

    file_op->offset  =  ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);

    file_op->size  =  ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);
    
    file_op->pathlen = ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);
    
    memcpy((char*)file_op->path, (buf + pos),  file_op->pathlen);
    file_op->path[file_op->pathlen] = 0;
    pos +=  file_op->pathlen;
  }
  /* The request for xattr op */
  else if(req->type == COREFS_REQUEST_XATTR){
    corefs_xattr * xattr = (corefs_xattr*)&req->op.xattr;

    xattr->type = ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);

    xattr->flags = ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);

    xattr->sizeofvalue  = ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);


    xattr->pathlen = ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);

    xattr->namelen = ntohl(*(unsigned int *)(buf + pos));
    pos += sizeof(unsigned int);
                                        
    memcpy((char*)xattr->params, (buf + pos), xattr->pathlen+ 1 +  xattr->namelen);
    pos += xattr->pathlen+ 1 +  xattr->namelen;
    
  }
  
  return pos;
}



/* encodes the response structure and copies it into the location
 * pointer by buf. Make sure that buf points to the location where you
 * want the response to be copied and not the the location where the
 * header should be copied.  */
unsigned int encap_corefs_response(char * buf, corefs_packet * pkt){

  unsigned int pos =0;
  unsigned int ui;
  
  corefs_response * resp = (corefs_response *) &pkt->payload.response;
  ui = htonl(resp->type);
  *(unsigned int *)(buf + pos) = ui;
  //memcpy((buf + pos), &ui, sizeof(ui));
  pos +=  sizeof(ui);

  ui = htonl(resp->more_offset);
  *(unsigned int *)(buf + pos) = ui;
  //memcpy((buf + pos), &ui, sizeof(ui));
  pos +=  sizeof(ui);
  
  if(resp->type == COREFS_RESPONSE_DATA || resp->type == COREFS_RESPONSE_MOREDATA){
    memcpy((buf + pos), resp->rop.raw,  pkt->header.payload_size - pos);
    pos =  pkt->header.payload_size;
  }
  else if (resp->type ==  COREFS_RESPONSE_STATUS || resp->type ==  COREFS_RESPONSE_ERROR){
    corefs_status * s = (corefs_status*)&resp->rop.status;
    ui = htonl(s->bits);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);
  }
  else if (resp->type ==  COREFS_RESPONSE_ATTR){
    corefs_attr * attr = (corefs_attr*)&resp->rop.attr;
    ui = htonl(attr->mode);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(attr->uid);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(attr->gid);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);
  
    ui = htonl(attr->size);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(attr->mtime);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(attr->atime);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(attr->ctime);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);

    ui = htonl(attr->nlinks);
    *(unsigned int *)(buf + pos) = ui;
    //memcpy((buf + pos), &ui, sizeof(ui));
    pos +=  sizeof(ui);
  }
  return pos;
}



/* decodes the response structure and copies it into the location
 * pointer by pkt. Make sure that buf points to the location from
 * where you want the response to be copied and not the the location
 * of the header.  */
unsigned int decap_corefs_response(char * buf, corefs_packet * pkt){

  unsigned int pos =0;
  
  corefs_response * resp = (corefs_response *) &pkt->payload.response;

  resp->type = ntohl(*(unsigned int *)(buf + pos));
  pos+= sizeof(unsigned int);

  resp->more_offset = ntohl(*(unsigned int *)(buf + pos));
  pos+= sizeof(unsigned int);
  
  if(resp->type == COREFS_RESPONSE_DATA || resp->type == COREFS_RESPONSE_MOREDATA){
    memcpy(resp->rop.raw,  (buf + pos), pkt->header.payload_size - pos);
    pos =  pkt->header.payload_size;
  }
  else if (resp->type ==  COREFS_RESPONSE_STATUS || resp->type ==  COREFS_RESPONSE_ERROR){
    corefs_status * s = (corefs_status*)&resp->rop.status;
    s->bits =  ntohl(*(unsigned int *)(buf + pos));
    pos+= sizeof(unsigned int);
  }
  else if (resp->type ==  COREFS_RESPONSE_ATTR){
    corefs_attr * attr = (corefs_attr*)&resp->rop.attr;

    attr->mode =  ntohl(*(unsigned int *)(buf + pos));
    pos+= sizeof(unsigned int);

    attr->uid =  ntohl(*(unsigned int *)(buf + pos));
    pos+= sizeof(unsigned int);

    attr->gid =  ntohl(*(unsigned int *)(buf + pos));
    pos+= sizeof(unsigned int);
    
    attr->size  =  ntohl(*(unsigned int *)(buf + pos));
    pos+= sizeof(unsigned int);
    
    attr->mtime  =  ntohl(*(unsigned int *)(buf + pos));
    pos+= sizeof(unsigned int);

    attr->atime  =  ntohl(*(unsigned int *)(buf + pos));
    pos+= sizeof(unsigned int);

    attr->ctime  =  ntohl(*(unsigned int *)(buf + pos));
    pos+= sizeof(unsigned int);
    
    attr->nlinks  =  ntohl(*(unsigned int *)(buf + pos));
    pos+= sizeof(unsigned int);
    
  }
  return pos;
}




/* Helper functions to initialize all the various types of
 * packets. All except build_header return packet size. */
unsigned int build_header(corefs_packet* packet, unsigned int type)
{
	packet->header.magic = COREFS_MAGIC;
	packet->header.type = type;
  return SIZEOF_HEADER(packet->header);
}

// returns total packet size
unsigned int build_request_data(corefs_packet* packet, const char* data, size_t size)
{
	build_header(packet, COREFS_REQUEST);
	packet->header.payload_size = size + REQUEST_BASE_SIZE(packet->payload.request);
  packet->payload.request.type = COREFS_REQUEST_DATA;
	memmove(packet->payload.request.op.raw, data, size);
	return SIZEOF_HEADER(packet->header) + packet->header.payload_size;
}

unsigned int build_response_data(corefs_packet* packet, const char* data, size_t size)
{
	build_header(packet, COREFS_RESPONSE);
	packet->header.payload_size = size + RESPONSE_BASE_SIZE(packet->payload.response);
  packet->payload.response.type = COREFS_RESPONSE_DATA;
  packet->payload.response.more_offset = 0;
	memcpy(packet->payload.response.rop.raw, data, size);
	return SIZEOF_HEADER(packet->header) + packet->header.payload_size;
}

unsigned int build_response_with_moredata(corefs_packet* packet, const char* data, size_t size, unsigned int offset)
{
	build_header(packet, COREFS_RESPONSE);
	packet->header.payload_size = size + RESPONSE_BASE_SIZE(packet->payload.response);
  packet->payload.response.type = COREFS_RESPONSE_MOREDATA;
  packet->payload.response.more_offset = offset;
	memcpy(packet->payload.response.rop.raw, data, size);
	return SIZEOF_HEADER(packet->header) + packet->header.payload_size;
}


/* size and flags are useful only for setxattr. for getxattr they can
 * be just set to 0 */
unsigned int build_xattr(corefs_packet * packet, unsigned int type, const char * name, const char *path, int size, int flags){

	unsigned int pathlen;
  unsigned int namelen;

  build_header(packet, COREFS_REQUEST);
  packet->payload.request.type = COREFS_REQUEST_XATTR;

  corefs_xattr * xattr =  (corefs_xattr*)&(packet->payload.request.op.xattr);
  xattr->type = type;
  xattr->flags = flags;
  pathlen = size;

  xattr->sizeofvalue = pathlen;
  pathlen = strlen(path);
  xattr->pathlen = pathlen;
  if(name)
    namelen = strlen(name);
  else namelen = 0;
  
  xattr->namelen = namelen;
  
  strcpy((char*)xattr->params,path);
  if(name)
    strcpy((char*)xattr->params+pathlen+1,name); // format: path || attribute name
  
  packet->header.payload_size =  REQUEST_BASE_SIZE(packet->payload.request) + SIZEOF_XATTR((*xattr));

  dprintf(stderr, "build_xattr payload_size %u pathlen %u , namelen%u\n", packet->header.payload_size, pathlen, namelen);
  dprintf(stderr, "build_xattr header_size %u\n", header_size);
  
  return   packet->header.payload_size + SIZEOF_HEADER(packet->header);
}


/* Assumes that the user info is already intialized before calling
 * this function. Returns total packet size. */
unsigned int build_fileop(corefs_packet* packet, unsigned int type, unsigned int offset, unsigned int size, 
	const char* path)
{
	unsigned int pathlen;

  build_header(packet,COREFS_REQUEST);
  packet->payload.request.type = COREFS_REQUEST_FILEOP;
  packet->payload.request.op.fileop.type = type;
	packet->payload.request.op.fileop.offset=offset;
	packet->payload.request.op.fileop.size=size;
	pathlen=strlen(path);
	packet->payload.request.op.fileop.pathlen = pathlen;
	strcpy((char*)packet->payload.request.op.fileop.path, path);

  packet->header.payload_size = REQUEST_BASE_SIZE(packet->payload.request) + SIZEOF_FILEOP_NOPATH(packet->payload.request.op.fileop) + pathlen;
    
	return 	packet->header.payload_size +  SIZEOF_HEADER(packet->header);
  
}

/*  assumption: opt_path if not used is NULL */
unsigned int build_simple(corefs_packet* packet, unsigned int type, const char* path1, off_t offset, mode_t mode1, const char *opt_path)
{

  build_header(packet, COREFS_REQUEST);
  packet->payload.request.type = COREFS_REQUEST_SIMPLE;
  corefs_simple * simple = (corefs_simple*)&(packet->payload.request.op.simple);
  
  simple->type = type;
  simple->offset = offset;
  simple->mode1 = mode1;
  simple->path1len = (unsigned int)strlen(path1);
  strcpy((char*)simple->path1, path1);
  simple->path2len = 0;
  
  if(opt_path) { // assumption: opt_path if not used is NULL
    simple->path2len = (unsigned int)strlen(opt_path);
    strcpy((char*)simple->path2, opt_path);
  }
  
  packet->header.payload_size = REQUEST_BASE_SIZE(packet->payload.request) + SIZEOF_SIMPLEOP((*simple)) ;


  return packet->header.payload_size + SIZEOF_HEADER(packet->header);
}

unsigned int build_status(corefs_packet* packet, unsigned int status, unsigned int type)
{
	build_header(packet, COREFS_RESPONSE);
	packet->header.payload_size=SIZEOF_STATUS(packet->payload.response.rop.status) + RESPONSE_BASE_SIZE(packet->payload.response);
  packet->payload.response.type = type;
	packet->payload.response.rop.status.bits=status;
	return header_size + SIZEOF_STATUS(packet->payload.response.rop.status) + RESPONSE_BASE_SIZE(packet->payload.response);
}

/*  loops until all of the data is received or until IO error.  If */
/*  successful, returns the requested write size otherwise returns -1 */
/*  in case of IO error */

int socket_read(int sock, char* buffer, size_t size)
{
    int read=0;
    int ret;

    //dprintf(stderr, "in socket_read(size=%i). [sock=%i]\n",size,sock);

    while (read < size) {
        if ((ret=recv(sock, buffer+read, (size_t)size-read, 0)) < 0) {
            fprintf(stderr, "socket_read() error %i (%s).\n",
                    errno, strerror(errno));
            return -1;
        } else if (ret == 0) {
            fprintf(stderr, "Client disconnected.\n");
            return -1;
        } else {
            //fprintf(stderr, "read %i bytes.\n", ret);
            read+=ret;
        }
    }
    return read;
}


 /* loops until all of the data is sent or until IO error.  If
  * successful, returns the requested write size otherwise returns -1
  * in case of IO error */
   
int socket_write(int sock, char* buffer, size_t size)
{
	int written=0;
	int ret;

	//dprintf(stderr, "in socket_write(). [sock=%i]\n",sock);

	while (written < size) {
		if ((ret=send(sock, buffer+written, (size_t)size-written, 0)) <= 0) {
			return -1;
		}
		else {
			//dprintf(stderr, "sent %i bytes.\n", ret);
			written+=ret;
		}
	}
	return written;
}
// physical layer function to send data.
int phy_send(COMMCTX* ctx, char* buffer, int size)
{
	SOCK_CTX* mctx;
	mctx=(SOCK_CTX*)ctx->sock_ctx;

	return socket_write(mctx->sock, buffer, size);
}

// physical layer function to send data.
int phy_receive(COMMCTX* ctx, char* buffer, int size)
{
	SOCK_CTX* mctx;
  
	mctx=(SOCK_CTX*)ctx->sock_ctx;
	return socket_read(mctx->sock, buffer, size);
  //  dprintf(stderr, "in phy_receive() received %i.\n",ret);

}

// security layer callback to log debug messages.
int cb_log(COMMCTX* ctx, char* buffer)
{
	// add this later...
	return 0;
}

/* This function is called by the server to receive a specific type of
 * response. Returns payload size on success or -EIO otherwise */
int server_receive_specified(COMMCTX* ctx, char* buffer, unsigned int type)
{
	int ret;
  corefs_packet* packet = (corefs_packet*)buffer; 
  char resp_buf[BUFFERSIZE];
  memset(resp_buf, 0, BUFFERSIZE);
	ret=receive_packet(ctx, resp_buf);

  if (ret < header_size) {
		dprintf(stderr, "error receiving packet.\n");
    return -EIO;
	}
  
  /* Copy the header */
  corefs_packet * reply =(corefs_packet*)resp_buf;
  packet->header.magic = reply->header.magic;
  packet->header.type = reply->header.type;
  packet->header.sequence = reply->header.sequence;
  packet->header.payload_size = reply->header.payload_size;

  /* decap the received message */
  if(packet->header.type == COREFS_REQUEST)
    decap_corefs_request(resp_buf + header_size, packet);
  else{
    dprintf(stderr, "server_receive_specified: Received wrong packet type [%u], packet sequence[%u]\n", packet->header.type,packet->header.sequence);
    return -EPROTO;
  }
 
  if (packet->payload.request.type != type)    {
    dprintf(stderr, "server_receieve_specified: Error- expecting packet type %u, received %u.\n", type, packet->payload.request.type);
    return -EPROTO;
  }
  else {
		ret= packet->header.payload_size;
  }
  return ret;
}



/* Called by the client to fetch response of the specified type. This
 * function will decapsulate and copy the received packet in
 * buffer. If client is waiting for status, then returns the status on
 * success. Otherwise returns payload size on success or returns
 * -errno on failure. If the received packet is not of the specified
 * type -EIO is returned.*/

int client_receive_specified(COMMCTX* ctx, char* buffer, unsigned int type)
{
    int ret;
    corefs_packet * packet =(corefs_packet*)buffer; 
    char resp_buf[BUFFERSIZE];
    memset(resp_buf, 0, BUFFERSIZE);
  
    ret=receive_packet(ctx, resp_buf);

    if (ret < header_size) {
        dprintf(stderr, "error receiving packet.\n");
        return -EIO;
    }

    /* Copy the header */
    corefs_packet * reply =(corefs_packet*)resp_buf;
    packet->header.magic = reply->header.magic;
    packet->header.type = reply->header.type;
    packet->header.sequence = reply->header.sequence;
    packet->header.payload_size = reply->header.payload_size;
  

    /* decap the received message */
    
    if(packet->header.type == COREFS_RESPONSE)
        decap_corefs_response(resp_buf + header_size, packet);
    else{
        dprintf(stderr, "client_receive_specified: Received wrong packet type [%u], packet sequence[%u]\n", packet->header.type, packet->header.sequence);
        return -EPROTO;
    }
#ifdef DEBUG_NETWORK
    dprintf(stderr, "client_receive_specified: printing response\n");
    print_packet(*packet);
#endif
 
    if(packet->payload.response.type == COREFS_RESPONSE_ERROR){
        return -packet->payload.response.rop.status.bits;
    }
    else if((packet->payload.response.type != type) &&
            !((type == COREFS_RESPONSE_DATA) &&
              (packet->payload.request.type == COREFS_RESPONSE_MOREDATA))) {
        dprintf(stderr, "client_receive_specified: Error - expecting packet type %i, received %i.\n", type, packet->payload.response.type);
        return -EPROTO;
    }
    else if (packet->payload.response.type == COREFS_RESPONSE_STATUS){
        ret = packet->payload.response.rop.status.bits;
    }
    else {
        ret= packet->header.payload_size;
    }

    return ret;
  
}


int receive_packet(COMMCTX* ctx, char* buffer)
{
	//dprintf(stderr, "in receive_packet.\n");
	return ctx->receive(ctx, buffer, BUFFERSIZE);
}

int send_packet(COMMCTX* ctx, char* buffer, size_t size)
{
	int ret = ctx->send(ctx, buffer, size);
  return ret;
  
}




/* Print functions for debugging. These will print the contents of the
 * network packet. */
void print_response(corefs_packet pkt){
  dprintf(stderr, "<response payload>\n");
  dprintf(stderr, "\t| type[0x%x] | offset[0x%x]\n", pkt.payload.response.type, pkt.payload.response.more_offset);
  if(COREFS_RESPONSE_STATUS == pkt.payload.response.type || COREFS_RESPONSE_ERROR == pkt.payload.response.type){
    dprintf(stderr,"\t<status>\n");
    dprintf(stderr, "\t\t| status[0d%u] |\n", pkt.payload.response.rop.status.bits);
    dprintf(stderr,"\t<\\status>\n");
  }
  else if(COREFS_RESPONSE_ATTR == pkt.payload.response.type){
    dprintf(stderr,"\t<attr>\n");
    dprintf(stderr, "\t\t| mode[0x%x] | uid[0x%x] | gid[0x%x] | size[0d%d] | mtime[0d%d] |\n",  pkt.payload.response.rop.attr.mode,  pkt.payload.response.rop.attr.uid ,  pkt.payload.response.rop.attr.gid,  pkt.payload.response.rop.attr.size,  pkt.payload.response.rop.attr.mtime);
    dprintf(stderr,"\t<\\attr>\n");
  }
  dprintf(stderr, "<\\response payload>\n");
  dprintf(stderr, "--------------------------------------------------------\n");
}


void print_request(corefs_packet pkt){

  int i = 0;
  dprintf(stderr, "<request payload>\n");
  dprintf(stderr, "\t| type[0x%x] | uid[0x%x] | gid[0x%x] | num_sgids[0x%x] |", pkt.payload.request.type, pkt.payload.request.user_ids.uid, pkt.payload.request.user_ids.gid, pkt.payload.request.user_ids.num_sgids);
  
  for(i = 0; i < pkt.payload.request.user_ids.num_sgids; i++){
    dprintf(stderr, "| sgid_%d[0x%x] |", i, pkt.payload.request.user_ids.sgids[i]);
  }
  dprintf(stderr,"\n");
  
  if(pkt.payload.request.type == COREFS_REQUEST_FILEOP){
     dprintf(stderr, "\t<fileop>\n");
     dprintf(stderr, "\t\t|type [0x%x] | offset[0d%u] | size[0d%u] | pathlen[0d%u] | path[%s] |\n",pkt.payload.request.op.fileop.type, pkt.payload.request.op.fileop.offset, pkt.payload.request.op.fileop.size, pkt.payload.request.op.fileop.pathlen, pkt.payload.request.op.fileop.path);
     dprintf(stderr, "\t<\\fileop>\n");
  }
  else if(pkt.payload.request.type == COREFS_REQUEST_SIMPLE){
    dprintf(stderr, "\t<simpleop>\n");
    dprintf(stderr, "\t\t| type[0x%x] | offset[0d%u] | mode[0x%x] | path1len[0d%u] | path2len[0d%d] | path1[%s] | path2[%s] |\n", pkt.payload.request.op.simple.type, pkt.payload.request.op.simple.offset, pkt.payload.request.op.simple.mode1, pkt.payload.request.op.simple.path1len, pkt.payload.request.op.simple.path2len, pkt.payload.request.op.simple.path1, pkt.payload.request.op.simple.path2);
     dprintf(stderr, "\t<\\simpleop>\n");
  }
  else if(pkt.payload.request.type == COREFS_REQUEST_XATTR){
    dprintf(stderr, "\t<xattr>\n");
    dprintf(stderr, "\t\t| type[0x%x] | flags[0x%x] | sizeofvalue[0d%u] | pathlen[0d%u] | namelen[0d%u] | path[%s] | name[%s] |\n", pkt.payload.request.op.xattr.type, pkt.payload.request.op.xattr.flags, pkt.payload.request.op.xattr.sizeofvalue, pkt.payload.request.op.xattr.pathlen, pkt.payload.request.op.xattr.namelen, pkt.payload.request.op.xattr.params, pkt.payload.request.op.xattr.params + pkt.payload.request.op.xattr.pathlen+1);
    dprintf(stderr, "\t<\\xattr>\n");
  }
  dprintf(stderr, "<\\request payload>\n");
  dprintf(stderr, "--------------------------------------------------------\n");
}

void print_packet(corefs_packet pkt){
   dprintf(stderr, "--------------------------------------------------------\n");
  dprintf(stderr,"<header>\n");
  dprintf(stderr, "\t| magic[0x%x] | type[0x%x] | sequence[0x%x] | payload_size[0d%u] |\n",pkt.header.magic, pkt.header.type, pkt.header.sequence, pkt.header.payload_size);
  dprintf(stderr,"<\\header>\n");
  dprintf(stderr, "--------------------------------------------------------\n");
  if(pkt.header.type == COREFS_REQUEST) print_request(pkt);
  if(pkt.header.type == COREFS_RESPONSE) print_response(pkt);
}

