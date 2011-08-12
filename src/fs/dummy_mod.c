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
#include <string.h>
#include "common.h"
//#include <fuse.h>


/* corefs_server_operations myop; */
/* int temp_read(COMMCTX* ctx, corefs_packet* cmd){ */
/*  return myop.handle_read(ctx,cmd); */
  
/* } */
/* int temp_write(COMMCTX* ctx, corefs_packet* cmd){ */
/*   return myop.handle_write(ctx, cmd); */
  
/* } */

/* dummy upper layer module */


int my_check_access(COMMCTX * ctx, const user_info * u, int * status, const char * path, const char * path1, int op){
  /* Do nothing */
  *status = 0;
  return PROCEED;
}



void my_get_user_info(user_info * u, const char * path, const char * opt_path)
{
  u->uid = fuse_get_context()->uid;
  u->gid = fuse_get_context()->gid;
  u->num_sgids = 0;
}

void my_goodbye(COMMCTX* ctx) {
  return;
}

int my_receive(COMMCTX* ctx, char* buf, int len) {
  /* note "len" here is the buffer size.  we want one packet of any
   * length up to "len". then return the actual size received. */
  
  corefs_header *header=(corefs_header*)buf;
  int psize;
  
  if (phy_receive(ctx, buf, header_size) < 0) {
  
    return -1;
  }
  
  /* We need to decap the header to understand the file size */
  char temp_buf[header_size];
  memcpy(temp_buf,buf,header_size);
  decap_corefs_header(temp_buf, (corefs_packet*)buf); /* Just to be
                                                       * safe lets use
                                                       * different
                                                       * buffers */
  
   psize=header->payload_size;
  
  if (phy_receive(ctx, buf+header_size, psize) < 0) {
    return -1;
  }
  return header_size + psize;
}

int my_send(COMMCTX* ctx, char* buf, int len) {
	return phy_send(ctx, buf, len);
}

int setup(COMMCTX* ctx) {
  
  ctx->receive = my_receive;
  ctx->send = my_send;
  return PROCEED;
}

int server_hello(char * client, char * server, COMMCTX * ctx) { 
  
  return setup(ctx); 
}

int client_hello(char * client, char * server, COMMCTX * ctx){
  
  return setup(ctx);
  
}


int my_parse_arguments(char * argstr, int argc, char** argv){

  /*
    EXAMPLE: Heres an example from my accounting file system. This is
    just a sample code and will not work if you uncomment and
    comile. It just shows how the upper layer should/can do the parsing of
    arugments.
  */

  
 /*  int ch, option_index=0; */

/*   strncat(argstr, "p:C:R:B:H:", strlen("p:C:R:B:H:")); */
/*   opterr=0; // ignore unknown options */
  
/*   static struct option long_options[] = { */
/*     {"socket", required_argument, 0, 'p'}, */
/*     {"config", required_argument, 0, 'C'}, */
/*     {"receipts", required_argument, 0, 'R'}, */
/*     {"bwrcpt", optional_argument, 0, 'B'}, */
/*     {"chunk", required_argument, 0, 'H'}, */
/*     {0,0,0,0} */
/*   }; */
  
/*   while ((ch=getopt_long(argc, argv, argstr, long_options, &option_index)) != -1) { */
/*     switch (ch) { */
/*       case 'C': */
/*         if(optarg) */
/*           strncpy(config_file,optarg,MAX_PATH); */
/*         break; */
/*       case 'R': */
/*         if(optarg) */
/*           strncpy(receipt_file,optarg,MAX_PATH); */
/*         break; */
/*       case 'H': */
/*         if(optarg){ */
/*           int exp = atoi(optarg); */
/*           double t = pow(2, (double)exp); */
/*           chunk_size_s = (uint64_t) t; */
/*           chunk_size_b =  chunk_size_s; */
/*           chunk_size_d =  chunk_size_s; */
/* #ifdef DEBUG */
/*           fprintf(stderr, "client chunk sizes = %llu %llu %llu\n",chunk_size_s, chunk_size_b, chunk_size_d); */
/* #endif */
/*         } */
/*         break; */
/*       case 'B': */
/*         if(optarg) */
/*           strncpy(bw_rcpt_file,optarg,MAX_PATH); */
/*         break; */
/*       case 'p': { */
/*         if(optarg != NULL){ */
/*           strncpy(socket_path,optarg,MAX_PATH); */
/*         } */
/*         break; */
/*       } */
/*     } */
/*   } */

/*   if(strlen(receipt_file) ==0 || strlen(socket_path) == 0){ */
/*     fprintf(stderr, "accounting usage: -p socket_path -C config_file_path -R receipt_file [-B bw_rcpt_file for server]\n"); */
/*     return STOP; */
/*   } */

  return PROCEED;
}


int up_client_init(corefs_client_operations * op){
  op->up_new_server = client_hello;
  op->up_eof_connection = my_goodbye;
  op->up_parse_arguments = my_parse_arguments;
  op->up_get_user_info = my_get_user_info;
  return PROCEED;
  
}



int up_server_init(corefs_server_operations * op){
  op->up_new_client = server_hello;

  /* Exmaple to replace read with temp_read, but also use the original
   * handle_read from server.c */
  
  /* myop.handle_read = op->handle_read;
     myop.handle_write = op->handle_write ;
     op->handle_read = temp_read;
     op->handle_write = temp_write;*/
  
  op->up_eof_connection = my_goodbye;
  op->up_parse_arguments = my_parse_arguments;
  op->up_check_access = my_check_access;
  return PROCEED;
  
}
