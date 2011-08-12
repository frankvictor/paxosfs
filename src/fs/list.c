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
#include <stdlib.h>
#include "list.h"

#define MAX_PATH 257
#define MAX_LIST_LENGTH 100

//extern int MAX_PATH ;
//extern int MAX_LIST_LENGTH;


int init_list_head(list_head * head)
{
  if(head == NULL){
    fprintf(stderr, "init_list_head: received NULL head value - initialize head\n");
    return -1;
  }
  head->next = NULL;
  head->prev = NULL;
  head->alength = 0;
  head->data = NULL;
  head->server_addr = NULL;
  return 0;
}
                   

int insert_info_ptr(list_head * head,  list_tail ** tail, const char* addr,
                    unsigned int addr_length, void * data)
{

  server_list * node = NULL;
#ifdef ACCOUNT_DEBUG
  fprintf(stderr, "INSERT: inserting file %s with key size %u \n", addr, alength);
#endif

  if(addr_length > MAX_PATH){
    fprintf(stderr,"Insert: file name %s exceeds length limit %d\n", addr,MAX_PATH);
    return -1;
  }
  
  if(head == NULL){
    fprintf(stderr,"Insert: head of the list is NULL - initialize it!\n");
    return -1;
  }
  
  
  if(head->alength == MAX_LIST_LENGTH){
    
    if(tail == NULL){ // this case should never happen, but just in case
      fprintf(stderr,"INSERT: tail of the list is NULL - potential error while initializing list head\n");
      return -1;
    }
    node = *tail;
    if(node->alength < addr_length){
      free(node->server_addr);
      node->server_addr = (char *) calloc(addr_length, 1);
      if(node->server_addr == NULL) {
        fprintf(stderr, "INSERT: out of memory errno[%i]\n",errno);
        return -1;
      }
    }

    memcpy(node->server_addr,addr,addr_length);
    node->alength = addr_length;

    node->data=data;
    
    (*tail)->next = NULL;
    if(MAX_LIST_LENGTH  == 1)
      return 0;
    *tail = (*tail)->prev;
  }
  else {
    node = (server_list*)calloc(1,sizeof(server_list));
    if(node == NULL) {
      fprintf(stderr, "out of memory errno[%i]\n",errno);
      return -1;
    }
    
    node->server_addr = (char *) calloc(addr_length, 1);
    if(node->server_addr == NULL) {
      fprintf(stderr, "INSERT out of memory errno[%i]\n",errno);
      return -1;
    }
    
    memcpy(node->server_addr,addr, addr_length);
    node->alength = addr_length;

    node->data=data;
    
    if(head->alength == 0) // this is the first item in the list
      *tail = node;
    head->alength += 1;
  }
  node->next = head->next;
  if(head->next)
    head->next->prev = node;
  node->prev = head;
  head->next = node;

  return 0;
}


int get_info_ptr(list_head * head,  list_tail ** tail, const char *addr,
                 unsigned int addr_length, void **pointer_to_data)
{

  server_list * node;
  if(head == NULL || addr == NULL)
    return -1;

  
#ifdef ACCOUNT_DEBUG
  fprintf(stderr, "GET_INFO: for addr %s\n",addr);
#endif

  node = head->next;
  while(node){
    //print_node(node);
    //fprintf(stderr, "comparing [%s] , [%s] : result %d \n",node->file_path,path,strcmp(node->file_path,path));
    
    if(node->alength == addr_length &&
       memcmp(node->server_addr,addr,addr_length) == 0){
      // remove node from the list
      if(node->prev != head){
        node->prev->next = node->next;
        if(node->next)
          node->next->prev = node->prev;
        else // this is the last element
          *tail = node->prev;
        //insert node at the front
        node->next = head->next;
        node->next->prev = node;
        head->next = node;
        node->prev = head;
      }
      *pointer_to_data=node->data;
      return node->alength;
    }
    node = node->next;
  }
  return -1;
}



int change_info_ptr(list_head * head,  list_tail ** tail, const char * addr,
                unsigned int addr_length, void * data)
{
  server_list * node;
  if(head == NULL || addr == NULL)
    return -1;

  node = head->next;
  while(node){
    if(node->alength == addr_length &&
       memcmp(node->server_addr,addr, addr_length) == 0){
      if(node->prev != head){
        // remove node from the list
        node->prev->next = node->next;
        if(node->next)
          node->next->prev = node->prev;
        else // this is the last element
          *tail = node->prev;
        
        //insert node at the front
        node->next = head->next;
        node->next->prev = node;
        head->next = node;
        node->prev = head;
      }
      node->data=data;
      return node->alength;
    }
    node = node->next;
  }
  return -1;
  
}



int delete_info(list_head * head,  list_tail ** tail, const char * addr,
                unsigned int addr_length){
  server_list * node;
  if(head == NULL || addr == NULL)
    return -1;

  node = head->next;
  //print_list(head);
  while(node){
    if(memcmp(node->server_addr,addr,addr_length) == 0){
      // remove node from the list
      node->prev->next = node->next;
      if(node->next)
        node->next->prev = node->prev;
      else // this is the last element
        *tail = node->prev;
      if(node->server_addr) free(node->server_addr);
      if(node->data) free(node->data);
      if(node) free(node);
      head->alength -= 1;

      //print_list(head);
      
      return 0;
    }
    node = node->next;
  }
  return -1;
}

int remove_info(list_head * head,  list_tail ** tail, const char * addr,
                unsigned int addr_length){
  server_list * node;
  if(head == NULL || addr == NULL)
    return -1;

  node = head->next;
  //print_list(head);
  while(node){
    if(memcmp(node->server_addr,addr,addr_length) == 0){
      // remove node from the list
      node->prev->next = node->next;
      if(node->next)
        node->next->prev = node->prev;
      else // this is the last element
        *tail = node->prev;
      head->alength -= 1;

      //print_list(head);
      
      return 0;
    }
    node = node->next;
  }
  return -1;
}

//removes all objects from list that point to same data as ptr
int remove_info_ptr(list_head * head,  list_tail ** tail, void *ptr){
  server_list * node;
  if(head == NULL || ptr == NULL)
    return -1;

  node = head->next;
  //print_list(head);
  while(node){
    if(node->data == ptr){
      // remove node from the list
      node->prev->next = node->next;
      if(node->next)
        node->next->prev = node->prev;
      else // this is the last element
        *tail = node->prev;
      head->alength -= 1;
    }
    node = node->next;
  }
  return -1;
}


void free_list(list_head * head)
{
  if(head == NULL)
    return;
  server_list * node = head->next;
  while(node){
    head->next = node->next;
    if(node->server_addr) free(node->server_addr);
    if(node->data) free(node->data);
    if(node) free(node);
    node = head->next;
  }
  head->alength = 0;
  head->next = NULL;
  head->prev = NULL;
}

