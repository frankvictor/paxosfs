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
#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif
//#define FUSE_USE_VERSION 25
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statfs.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "corefs.h"

#define ATTR_CACHE_ENTRIES 64
#define ATTR_CACHE_PATHLEN 128
#define ATTR_CACHE_ATTRSIZE (sizeof(struct stat))

typedef struct _corefs_attr_cache_entry
{
    char path[ATTR_CACHE_PATHLEN];
    char valid;
    char attr[ATTR_CACHE_ATTRSIZE];
} corefs_attr_cache_entry;

corefs_attr_cache_entry attr_cache[ATTR_CACHE_ENTRIES];
static int attr_cache_last_stored=0;
static int attr_cache_initialized=0;

corefs_client_operations mop;

void attr_cache_init()
{
    int ii;

    attr_cache_last_stored=0;
    attr_cache_initialized=1;

    for (ii=0; ii<ATTR_CACHE_ENTRIES; ii++) {
	attr_cache[ii].valid=0;
    }
}


// returns 1 on successful lookup.
// 0 if not found.
int attr_cache_lookup(const char* path, void* return_attr)
{
    int ii;

    if (! attr_cache_initialized) attr_cache_init();

    for (ii=0; ii<ATTR_CACHE_ENTRIES; ii++) {
	if ((attr_cache[ii].valid) && (0==strcmp(attr_cache[ii].path, path))) {
	    memcpy(return_attr, attr_cache[ii].attr, ATTR_CACHE_ATTRSIZE);
	    printf("cache hit on '%s'.\n", path);
	    return 1;
	}
    }
    printf("cache MISS on '%s'.\n", path);
    return 0;
}

// returns 1 on successful lookup and removal
// 0 if not found.
int attr_cache_remove(const char* path)
{
    int ii;

    if (! attr_cache_initialized) attr_cache_init();

    for (ii=0; ii<ATTR_CACHE_ENTRIES; ii++) {
	if ((attr_cache[ii].valid) && (0==strcmp(attr_cache[ii].path, path))) {
	    printf("successfully removed '%s' from cache.\n", path);
	    attr_cache[ii].valid=0;
	    return 1;
	}
    }
    printf("tried to remove '%s' from cache but not found.\n", path);
    return 0;
}

void attr_cache_store(const char* path, void* attr)
{
    if (! attr_cache_initialized) attr_cache_init();

    /* Note this is an unoptimized liner implementation */
    
    // copy path
    strncpy(attr_cache[attr_cache_last_stored].path, path, ATTR_CACHE_PATHLEN-1);
    // make sure it's null-terminated.
    attr_cache[attr_cache_last_stored].path[ATTR_CACHE_PATHLEN-1]='\0';
    // store attributes
    memcpy(attr_cache[attr_cache_last_stored].attr, attr, ATTR_CACHE_ATTRSIZE);
    // set valid bit
    attr_cache[attr_cache_last_stored].valid=1;

    printf("path '%s' stored in cache in slot %i.\n", path, attr_cache_last_stored);

    // increment the counter
    attr_cache_last_stored=(attr_cache_last_stored+1) % ATTR_CACHE_ENTRIES;

}

typedef struct _corefs_settings
{
    char cache_attr;
    char cache_dirlist;
    char cache_timeout;
    char spoof_uids;
    char spoof_gids;
    char spoof_perms;
    int spoof_permbits;

} corefs_settings;

corefs_settings g_ms;
corefs_settings * g_msp=&g_ms;


void init_settings(corefs_settings* ms)
{
    ms->cache_attr=0;
    ms->cache_dirlist=0;
    ms->cache_timeout=0;
    ms->spoof_uids=0;
    ms->spoof_gids=0;
    ms->spoof_perms=0;
    ms->spoof_permbits=00700; // everything rwx to owner.
}

static int corefs_getattr(const char *path, struct stat *stbuf)
{
    int res;

    // if we're not caching attributes or cache fails do the syscall.
    if ((! g_msp->cache_attr) || (! attr_cache_lookup(path, stbuf))) {
      res = mop.getattr(path, stbuf);
      if(res < 0)
        return res;
      if (g_msp->cache_attr) attr_cache_store(path, stbuf);
    }

    if (g_msp->spoof_uids) stbuf->st_uid=getuid();
    if (g_msp->spoof_gids) stbuf->st_gid=getgid();
    if (g_msp->spoof_perms) {
      stbuf->st_mode &= 0770000; // preserve directory, symlink, etc bits
      stbuf->st_mode |= g_msp->spoof_permbits; // add back in user bits
    }
    return 0;
}


static struct fuse_operations corefs_oper;

void client_op_init(corefs_client_operations *op){

    // preserve the actual functions
    if (op->getattr)  mop.getattr = op->getattr;
    if (op->read)     mop.read = op->read;
    if (op->write)    mop.write = op->write;
    if (op->readdir)  mop.readdir = op->readdir;
    if (op->mknod)    mop.mknod = op->mknod;
    if (op->truncate) mop.truncate = op->truncate;
    if (op->unlink)   mop.unlink = op->unlink;
    if (op->rename)   mop.rename = op->rename;
    if (op->symlink)  mop.symlink = op->symlink;
    if (op->readlink) mop.readlink = op->readlink; 
    if (op->mkdir)    mop.mkdir = op->mkdir;
    if (op->rmdir)    mop.rmdir = op->rmdir;
    if (op->open)     mop.open = op->open;
    if (op->release)  mop.release = op->release;
    if (op->utime)    mop.utime = op->utime;
    if (op->chmod)    mop.chmod = op->chmod;
    if (op->link)     mop.link = op->link;
    if (op->flush)    mop.flush = op->flush;
#ifdef HAVE_SETXATTR
    if (op->setxattr)  mop.setxattr = op->setxattr;
    if (op->getxattr)  mop.getxattr = op->getxattr;
    if (op->listxattr)  mop.listxattr = op->listxattr;
    if (op->removexattr)  mop.removexattr = op->removexattr;
 #endif   

    /* Change the getattr pointer */
    if (op->getattr)  op->getattr = corefs_getattr;
  
  
}

int corefs_main(int argc, char *argv[], const corefs_client_operations *op)
{

  // set all unused functions to null.
  memset(&corefs_oper, 0, sizeof(corefs_oper));
    
  // connect any functions supplied by the client.
  if (op->getattr)  corefs_oper.getattr =  op->getattr;
  if (op->read)     corefs_oper.read = op->read;
  if (op->write)    corefs_oper.write = op->write;
  if (op->readdir)  corefs_oper.readdir = op->readdir;
  if (op->mknod)    corefs_oper.mknod = op->mknod;
  if (op->truncate) corefs_oper.truncate = op->truncate;
  if (op->unlink)   corefs_oper.unlink = op->unlink;
  if (op->rename)   corefs_oper.rename = op->rename;
  if (op->symlink)  corefs_oper.symlink = op->symlink;
  if (op->readlink)  corefs_oper.readlink = op->readlink; 
  if (op->mkdir)  corefs_oper.mkdir = op->mkdir;
  if (op->rmdir)  corefs_oper.rmdir = op->rmdir;
  if (op->open)  corefs_oper.open = op->open;
  if (op->release)  corefs_oper.release = op->release;
  if (op->utime)  corefs_oper.utime = op->utime;
  if (op->chmod)  corefs_oper.chmod = op->chmod;
  if (op->link)  corefs_oper.link = op->link;
  if (op->flush)  corefs_oper.flush = op->flush;
  if (op->destroy) corefs_oper.destroy = op->destroy;
#ifdef HAVE_SETXATTR
  if (op->setxattr)  corefs_oper.setxattr = op->setxattr;
  if (op->getxattr)  corefs_oper.getxattr = op->getxattr;
  if (op->listxattr)  corefs_oper.listxattr = op->listxattr;
  if (op->removexattr)  corefs_oper.removexattr = op->removexattr;
#endif
    
  umask(0);
  init_settings(&g_ms);
  g_ms.spoof_uids = 1;
  g_ms.spoof_gids = 1;
  g_ms.cache_attr = 0; //1;
  g_ms.spoof_perms = 0; /* set to 1 to change default permission */
  g_ms.spoof_permbits = 00700;
  return fuse_main(argc, argv, &corefs_oper);
}
