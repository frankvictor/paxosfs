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
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <getopt.h>
#include <sys/statfs.h>
#include <pwd.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <dirent.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "corefs.h"
#include "protocol.h"
#include "common.h"
#include "list.h"


#define MAXCONN 5
//maximum length for a file path
#define MAXPATH 200
//length of local mirror address: 17 + size of username
#define LOCALSIZE 42
//maximum length for a server address
#define MAXADDR 100

corefs_client_operations my_ops; /* This does not need any locking */
int server_port = SERVER_PORT;

/* local path for .corefs directory - set in main() */
char *local_path;
/* list for storing multiple servers */
list_head head;
list_tail *tail;


//structure for holding server data
//will be kept in a list
typedef struct _server_data {
    COMMCTX g_ctx;
    COMMCTX* ctx;
    SOCK_CTX g_mctx;
    /*pthread_mutex_t ctx_mutex;
    list_head req_head;
    list_tail *req_tail;
    pthread_mutex_t req_mutex;
    sem_t req_sem; 
    unsigned int sequence;
    pthread_mutex_t sequence_mutex; */
} server_data;


int init_server_data(server_data *sd)
{
    sd->ctx=&(sd->g_ctx);
    sd->g_ctx.sock_ctx=&(sd->g_mctx);
    sd->g_mctx.sock=-1;
    return 0;
}

int delete_server_data(server_data *sd)
{
    free(sd);
    sd=NULL;
    return 0;
}

/* Sets up a server:
 * Creates the server_data structure, adds it to the server list, and
 * then sets up socket communication */
int init(char *serverid, server_data **sdata)
{
    int flag;
    struct sockaddr_in server_addr;
    struct hostent* host=NULL;
    char g_server_addr[4];
    static int sock=-1;
    int ret, insertval=0;
    
    //find out host info right away
    host=gethostbyname(serverid);
    if (host) {
        memcpy(g_server_addr, host->h_addr, 4);
    }
    else {
        dprintf(stderr,"gethostbyname FAILED!\n");
        return -EHOSTUNREACH;
    }
    //use full addresses instead of host abbreviations
    //ie computer.abc.def.ghi instead of just computer
    if (strncmp(host->h_name,serverid,MAXADDR) != 0) {
        memset(serverid,0,MAXADDR);
        strncpy(serverid,host->h_name,MAXADDR);
    }

    server_data* sd = NULL;
    ret = get_info_ptr(&head,&tail,serverid,MAXADDR,(void *)&sd);
    if (ret < 0) {
        if (&head == NULL || serverid == NULL) {
            //an error occured, list not set up correctly or null serverid
            return ret;
        }
        else {
            //server could not be found in the list, set it up and add
            //it to the list
                     
            sd = (server_data*)calloc(sizeof(server_data),1);              
            init_server_data(sd);
            
            insertval = insert_info_ptr(&head,&tail,serverid,
                                        MAXADDR,(void *)sd);
            if (insertval<0) {
                //error inserting new sd into list
                return insertval;
            }
        }
    }

    /* This should only be true if the server was listed under host->h_name
     * and thus check_setup didn't see it.  */
    if (sd->g_mctx.sock > 0) {
        if (sdata) {
            *sdata=sd;
        }
        return 0;
    }
    
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;

    memcpy(&server_addr.sin_addr.s_addr, g_server_addr, 4);
    
    server_addr.sin_port = htons(server_port);

    sock=socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        dprintf(stderr, "ERROR: socket creation failed: %s\n",
                strerror(errno));
        return -1;
    }
    flag=1;

    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
                   (char*) &flag, sizeof(int))) {
        dprintf(stderr, "ERROR: unable to set socket options.\n");
    }

    int rval = connect(sock, (struct sockaddr *)&server_addr,
                       sizeof(server_addr));
    if (rval != 0) {
        dprintf(stderr, "ERROR: connect failed: %s\n", strerror(errno));
            
        if (errno == ECONNREFUSED) {
            //check to see if a local directory for the server exists
            //if it does, remove it
            struct stat st;
            char dir_path[MAXPATH+LOCALSIZE];
            sprintf(dir_path, "%s/mnt/%s", local_path,serverid);
            int stret = stat(dir_path, &st);
            if (stret >= 0) {
                if (rmdir(dir_path)) {
                    perror("Error deleting directory of server");
                }
            }
            ret = -EHOSTUNREACH;
        }
        else
            ret = -1;
        
        return ret;
    }
        
    sd->g_mctx.sock=sock;

    if(my_ops.up_new_server) {
        char my_dns[4096];
        memset(my_dns,4096,0);
    
        gethostname(my_dns, 4095);
            
        if(my_ops.up_new_server(my_dns, serverid, sd->ctx) != PROCEED){
            shutdown(sd->g_mctx.sock, 2);
            sock = sd->g_mctx.sock = -1;
      
            return -1;
        }
    }
        
    //create the local directory, if it doesn't already exist
    struct stat st;
    char dir_path[MAXPATH+LOCALSIZE];
    sprintf(dir_path, "%s/mnt/%s", local_path, serverid);
    int stret = stat(dir_path, &st);
    if (stret < 0) {
        if (mkdir(dir_path, 0700)) {
            perror("Failed to create local .corefs/mnt/server directory");
            exit(1);
        }
    }
    
    //set the server data pointer
    if (sdata) {
        *sdata = sd;
    }

    return 0;
}

//disconnects all connections cleanly
void do_destroy(void *input) {
    server_list *node = head.next;
    server_data *sd = NULL;
    while(node) {
        sd = (server_data*)node->data;
        if (sd == NULL) {
            return;
        }
        shutdown(sd->g_mctx.sock, SHUT_RDWR);
        close(sd->g_mctx.sock);
        node=node->next;
    }

    return;
}

//parses a path to find the server address
//sets server_addr with the address, and removes it from path
//sets ret_path to the rest of the path with the server removed
//server_addr needs to be of length MAXADDR
//ret_path needs to be of length MAXPATH
int remove_addr(const char *path, char **ret_path, char *server_addr)
{
    int i=0;
    if (path == NULL) {
        *ret_path = NULL;
        return 0;
    }
    if (server_addr != NULL) {
        memset(server_addr, 0, MAXADDR);
        memset(*ret_path, 0, MAXPATH);
        strncpy(*ret_path, path, MAXPATH);
        //skip i=0, it is always /
        i = 1;
        while (path[i] != '/' && path[i] != '\0' && i < MAXADDR - 1) {
            server_addr[i-1] = path[i];
            i++;
        }
        *ret_path += i;
        if (i>1 && *ret_path[0] == '\0') {
            //this wasn't the root directory, but yet there is nothing left
            //It was an 'ls mnt/server' - add a '/' to send to server
            *ret_path[0]='/';
        }
    }
    else {
        memset(*ret_path, 0, MAXPATH);
        strncpy(*ret_path, path, MAXPATH);
        //skip i=0, it is always /
        i = 1;
        while (path[i] != '/' && path[i] != '\0' && i < MAXADDR - 1) {
            i++;
        }
        *ret_path += i;
        if (i>1 && *ret_path[0] == '\0') {
            //this wasn't the root directory, but yet there is nothing left
            //It was an 'ls mnt/server' - add a '/' to send to server
            *ret_path[0]='/';
        }
    }
    
    return i-1;
}

//checks to see if the server specified in path is setup
//if it isn't it calls init, which sets it up
//s_addr needs to be of length MAXADDR
int check_setup(char *s_addr, server_data **sdata)
{
    int ret;
    server_data *sd=NULL;

    ret = get_info_ptr(&head,&tail,s_addr,MAXADDR,(void *) &sd);
    if (ret < 0) {
        if (&head == NULL || s_addr == NULL) {
            //an error occured, list not set up correctly or null serverid
            return ret;
        }
        else {
            //server could not be found in the list, set it up
            return init(s_addr, sdata);
        }
    }
    else {
        if (sd->g_mctx.sock <= 0) {
            //server is in list, but socket wasn't/isn't set up correctly
            return init(s_addr, sdata);
        }
    }
    
    //by getting to this point, the server was in the list and set up
    if (sdata) {
        *sdata=sd;
    }
    return 0;
}


int do_read_local(const char* path, char* buf, size_t size, off_t offset,
                  struct fuse_file_info* fi)
{
    return -EACCES;
}

int do_read(const char* path, char* buf, size_t size, off_t offset,
            struct fuse_file_info* fi)
{

    char buffer[BUFFERSIZE];
    corefs_packet req_packet;
    memset(&req_packet, 0, sizeof(req_packet));
    int ret;
    unsigned int packet_size;
    server_data *sd=NULL;
    
    /* Get user info from the upper layer */
    if(my_ops.up_get_user_info)
        my_ops.up_get_user_info(&(req_packet.payload.request.user_ids),
                                path, NULL);
    
    char r_path_[MAXPATH];
    char s_addr[MAXADDR];
    char *r_path = &r_path_[0];
    remove_addr(path, &r_path, s_addr);
    if (r_path[0]=='\0') {
        //there was no path other than the first '/'
        //ie this is for the root directory
        return do_read_local(path, buf, size, offset, fi);
    }

    ret = check_setup(s_addr, &sd);
    if (ret == -EHOSTUNREACH) return -EHOSTUNREACH;
    if (ret < 0) return -EIO;
    
    memset(buffer, 0, BUFFERSIZE);
    /* Prepare request */
    packet_size = build_fileop(&req_packet, COREFS_REQUEST_READ, offset,
                               size, r_path);

    /* Encapsualte the request */
    ret = encap_corefs_header(buffer, &req_packet);
    encap_corefs_request(buffer + ret, &req_packet);

#ifdef DEBUG
    dprintf(stderr, "READ: %s : %llu : %u\n", path, offset, size);
#endif
#ifdef DEBUG_NETWORK
    fprintf(stderr,"read request\n");
    print_packet(req_packet);
#endif
  
    if (send_packet(sd->ctx, buffer, packet_size) <=0) {
        dprintf(stderr, "error sending packet.\n");
        return -EIO;
    }
    /* Buffer will contain the received packet in the correct host format */
    memset(buffer, 0, BUFFERSIZE);
    if ((ret = client_receive_specified(sd->ctx, buffer, COREFS_RESPONSE_DATA))
        <= 0) {
        dprintf(stderr, "error receiving read data.\n");
        return ret;
    }
    /* Estimate the returned data size */
    corefs_packet * reply = (corefs_packet*)buffer;
  
    ret = reply->header.payload_size -
        RESPONSE_BASE_SIZE(reply->payload.response);
    memcpy(buf, reply->payload.response.rop.raw, ret);
  
    return ret;
}

int do_write_local(const char* path, const char* buf, size_t size,
                   off_t offset, struct fuse_file_info* fi)
{
    return -EACCES;
}

int do_write(const char* path, const char* buf, size_t size, off_t offset,
             struct fuse_file_info* fi)
{

    char buffer[BUFFERSIZE];
    memset(buffer, 0, BUFFERSIZE);
    corefs_packet req_packet;
    memset(&req_packet, 0, sizeof(req_packet));
    int ret;
    unsigned int packet_size;
    server_data *sd=NULL;

    /* Get user info from the upper layer */
    if(my_ops.up_get_user_info)
        my_ops.up_get_user_info(&(req_packet.payload.request.user_ids),
                                path, NULL);
    
    char r_path_[MAXPATH];
    char s_addr[MAXADDR];
    char *r_path = &r_path_[0];
    remove_addr(path, &r_path, s_addr);
    if (r_path[0]=='\0') {
        //there was no path other than the first '/'
        //ie this is for the root directory
        return do_write_local(path, buf, size, offset, fi);
    }

    ret = check_setup(s_addr, &sd);
    if (ret == -EHOSTUNREACH) return -EHOSTUNREACH;
    if (ret < 0) return -EIO;


    /* Send the write command first */
    /* Prepare request */
    packet_size = build_fileop(&req_packet, COREFS_REQUEST_WRITE, offset,
                               size, r_path);

    /* Encapsualte the request */
    ret = encap_corefs_header(buffer, &req_packet);
    encap_corefs_request(buffer + ret, &req_packet);

#ifdef DEBUG
    dprintf(stderr, "WRITE: %s : %llu : %u\n", path, offset, size);
#endif
#ifdef DEBUG_NETWORK
    fprintf(stderr,"write request\n");
    print_packet(req_packet);
#endif
  
    if (send_packet(sd->ctx, buffer, packet_size) <=0) {
        dprintf(stderr, "error sending packet.\n");
        return -EIO;
    }

    /* Now send the data */
    packet_size =  build_request_data((corefs_packet*) buffer, buf, size);
    char out_buffer[packet_size];
    ret = encap_corefs_header(out_buffer,(corefs_packet*)buffer);
    encap_corefs_request(out_buffer + ret, (corefs_packet*)buffer);
  
    if (send_packet(sd->ctx, out_buffer, packet_size) <=0) {
        dprintf(stderr, "error sending packet.\n");
        return -EIO;
    }
    memset(buffer, 0, BUFFERSIZE);
    if ((ret=client_receive_specified(sd->ctx, buffer, COREFS_RESPONSE_STATUS))
        < 0) {
        dprintf(stderr, "write returned error.\n");
        return ret;
    }
    return size;
}

int do_readdir_local(const char* path, void* buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    DIR* d;
    struct dirent* de;
    int count=0;
    char dirinfo[BUFFERSIZE];
#ifdef DEBUG
    dprintf(stderr, "LOCAL READDIR: directory \'%s\'.\n", path);
#endif
    char full_path[MAXPATH+LOCALSIZE];
    sprintf(full_path, "%s/mnt%s", local_path, path);
    d=opendir(full_path);
    if (!d) {
        dprintf(stderr, "opendir failed.\n");
        return -errno;
    }
    
    while((de = readdir(d)) != NULL) {
        //dprintf(stderr, "parsing dir: %s, type %i\n", de->d_name, de->d_type);
        switch (de->d_type) {
        case DT_UNKNOWN:
            dirinfo[count++]='u';
            break;
        case DT_DIR:
            dirinfo[count++]='d';
            break;
        case DT_REG:
            dirinfo[count++]='f';
            break;
        default:
            continue; // don't return anything but files and directories
            //reply->payload.raw[count++]='u';
            //break;
        }
        strcpy(dirinfo+count,de->d_name);
        count+=strlen(de->d_name)+1; // +1 for terminating null
    }
    closedir(d);

  
#ifdef DEBUG
    dprintf(stderr, "LOCAL READDIR: %s : %llu \n", path, offset);
#endif
    char *dirinfo_ptr = dirinfo;
    while (dirinfo_ptr < dirinfo+count) {
        char type;
        char* name;
        struct stat st;
        
        type=*dirinfo_ptr;
        name=(++dirinfo_ptr);
        
        st.st_mode=0700;
        if (type=='d') st.st_mode |= 0040000;
        filler(buf, name, &st, 0);
        dirinfo_ptr+=strlen(name)+1;
    }
    return 0;
}

int do_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
               off_t offset, struct fuse_file_info *fi)
{
    char buffer[BUFFERSIZE];
    unsigned int packet_size;
    int ret;
    server_data *sd=NULL;    

    char* dirinfo;
    corefs_packet req_packet;
    memset(&req_packet, 0, sizeof(req_packet));
  
    /* Get user info from the upper layer */
    if(my_ops.up_get_user_info)
        my_ops.up_get_user_info(&(req_packet.payload.request.user_ids),
                                path, NULL);
  
    char r_path_[MAXPATH];
    char s_addr[MAXADDR];
    char *r_path = &r_path_[0];
    ret = remove_addr(path, &r_path, s_addr);
    if (r_path[0]=='\0') {
        //there was no path other than the first '/'
        //ie this is for the root directory
        return do_readdir_local(path, buf, filler, offset, fi);
    }

    ret = check_setup(s_addr, &sd);
    if (ret == -EHOSTUNREACH) return -EHOSTUNREACH;
    if (ret < 0) return -EIO;

    while(1) {
        memset(buffer, 0, BUFFERSIZE);
        packet_size = build_fileop(&req_packet, COREFS_REQUEST_READDIR,
                                   offset, 0, r_path);
    
        /* Encapsulate the request */
        ret = encap_corefs_header(buffer, &req_packet);
        encap_corefs_request(buffer + ret, &req_packet);

#ifdef DEBUG
        dprintf(stderr, "READDIR: %s : %llu \n", path, offset);
#endif
    
#ifdef DEBUG_NETWORK
        fprintf(stderr,"readdir request\n");
        print_packet(req_packet);
#endif
    
        if (send_packet(sd->ctx, buffer, packet_size) <=0) {
            dprintf(stderr, "error sending packet.\n");
            return -EIO;
        }
        memset(buffer, 0, BUFFERSIZE);
        if ((ret = client_receive_specified(sd->ctx, buffer,
                                            COREFS_RESPONSE_DATA)) <= 0) {
            dprintf(stderr, "error receiving readdir data.\n");
            return ret;
        }
        
        // use same buffer for reply
        corefs_packet* reply=(corefs_packet*)buffer; 
        dirinfo = reply->payload.response.rop.raw;
    
        /*  Loop and insert all dirents in the filler func */
        while (dirinfo < buffer + header_size + ret) {
            char type;
            char* name;
            struct stat st;
            memset(&st, 0, sizeof(st));
            type = *dirinfo;
            name = (++dirinfo);
      
            st.st_mode = type << 12;
            if(filler(buf, name, &st, 0)) {
                /* FUSE buffer full, lets return */
                return 0;
            }
            dirinfo += strlen(name) + 1;
        }

        if(reply->payload.response.type == COREFS_RESPONSE_MOREDATA){
      
            /*  According to the server, the previous readdir was
             *  incomplete. Lets reissue readdir with the server provided
             *  offset. */
            offset = reply->payload.response.more_offset;
        }
        else /* readdir complete */
            break;
    }
  
    return 0;
}

int do_getattr_local(const char* path, struct stat *stbuf)
{
    struct stat st;
    int ret;
#ifdef DEBUG
    dprintf(stderr, "LOCAL GETATTR: file \'%s\'.\n", path);
#endif
    char full_path[MAXPATH+LOCALSIZE];
    sprintf(full_path, "%s/mnt%s", local_path, path);
    ret=lstat(full_path, &st);
    if (ret < 0) {
        dprintf(stderr, "stat failed.\n");
        return -errno;
    }

    memset(stbuf, 0, sizeof(struct stat));
    stbuf->st_mode=st.st_mode;
    stbuf->st_uid=st.st_uid;
    stbuf->st_gid=st.st_gid;
    stbuf->st_size=st.st_size;
    stbuf->st_mtime=st.st_mtime;
    stbuf->st_atime=st.st_mtime;
    stbuf->st_ctime=st.st_mtime;

    return 0;
}

int do_getattr(const char* path, struct stat *stbuf)
{
    server_data *sd=NULL;
    int ret;
    int packet_size = 0;
    corefs_packet packet;
    memset(&packet, 0, sizeof(packet));
 
#ifdef DEBUG
    dprintf(stderr, "GETATTR: %s \n", path);
#endif

    char r_path_[MAXPATH];
    char s_addr[MAXADDR];
    char *r_path = &r_path_[0];
    remove_addr(path, &r_path, s_addr);
    if (r_path[0]=='\0') {
        //there was no path other than the first '/'
        //ie this is for the root directory
        return do_getattr_local(path,stbuf);
    }
    ret = check_setup(s_addr, &sd);
    if (ret == -EHOSTUNREACH) return -EHOSTUNREACH;
    if (ret < 0) return -EIO;
  
    /* Get user info from the upper layer */
    if(my_ops.up_get_user_info)
        my_ops.up_get_user_info(&(packet.payload.request.user_ids), path, NULL);

    /* Create the request */
    packet_size = build_fileop(&packet, COREFS_REQUEST_GETATTR, 0, 0, r_path);

    /* Encap the request */
    char buffer[packet_size];

    ret = encap_corefs_header(buffer, &packet);
    
    encap_corefs_request(buffer + ret, &packet);
 
#ifdef DEBUG_NETWORK
    fprintf(stderr, "getattr request\n");
    print_packet(packet);
#endif
    /* Send the request */
    if (send_packet(sd->ctx, buffer, packet_size) <=0) {
        dprintf(stderr, "error sending packet.\n");
        return -EIO;
    }
  
    /* Receive the response */
    memset(buffer, 0, packet_size);
    if ((ret=client_receive_specified(sd->ctx, buffer, COREFS_RESPONSE_ATTR))
        <= 0) {
        dprintf(stderr, "GETATTR: error receiving attr data for file %s.\n",
                path);
        return ret;
    }
    corefs_packet * reply  =(corefs_packet*)buffer;
  
    memset(stbuf, 0, sizeof(struct stat));
    stbuf->st_mode  = reply->payload.response.rop.attr.mode;
    stbuf->st_uid   = reply->payload.response.rop.attr.uid;
    stbuf->st_gid   = reply->payload.response.rop.attr.gid;
    stbuf->st_size  = (unsigned int) reply->payload.response.rop.attr.size;
    stbuf->st_mtime = reply->payload.response.rop.attr.mtime;
    stbuf->st_atime = reply->payload.response.rop.attr.atime;
    stbuf->st_ctime = reply->payload.response.rop.attr.ctime;
    stbuf->st_nlink = reply->payload.response.rop.attr.nlinks;
  
    return 0;
	
}

#ifdef HAVE_SETXATTR

int do_listxattr_local(const char *path, char *list, size_t size) {
    return -EACCES;
}
/** List extended attributes */
int do_listxattr (const char * path, char * list, size_t size){
    char buffer[BUFFERSIZE];
    memset(buffer, 0, BUFFERSIZE);
    corefs_packet* packet = (corefs_packet*)buffer;
    int ret;
    unsigned int packet_size;
    server_data *sd=NULL;
    
    char r_path_[MAXPATH];
    char s_addr[MAXADDR];
    char *r_path = &r_path_[0];
    remove_addr(path, &r_path, s_addr);
    if (r_path[0]=='\0') {
        //there was no path other than the first '/'
        //ie this is for the root directory
        return do_listxattr_local(path, list, size);
    }
    
    ret = check_setup(s_addr, &sd);
    if (ret == -EHOSTUNREACH) return -EHOSTUNREACH;
    if (ret < 0) return -EIO;
    
#ifdef DEBUG
    dprintf(stderr, "LISTXATTR: path[%s] : requested list of max size[%d]\n",
            path,size);
#endif

    /* Get user info from the upper layer */
    if(my_ops.up_get_user_info)
        my_ops.up_get_user_info(&(packet->payload.request.user_ids),
                                path, NULL);

    /* Build the request packet */
    packet_size = build_xattr(packet, COREFS_XATTR_LISTXATTR, NULL,
                              r_path, size, 0);

    /* encapsulate in network order */
    char request_buf[packet_size];
    memset(request_buf, 0, packet_size);
  
    ret = encap_corefs_header(request_buf, packet);
    encap_corefs_request(request_buf + ret, packet);
#ifdef DEBUG_NETWORK
    fprintf(stderr, "printing listxattr request\n");
    print_packet(*packet);
#endif 
    if (send_packet(sd->ctx, request_buf, packet_size) <=0) {
        dprintf(stderr, "error sending packet.\n");
        return -EIO;
    }
    memset(buffer, 0, BUFFERSIZE);
    if(size == 0){
        if ((ret=client_receive_specified(sd->ctx, buffer,
                                          COREFS_RESPONSE_STATUS)) < 0) {
            dprintf(stderr, "LISTXATTR: error receiving listxattr size.\n");
        }
        return ret;
    }
    else{
        if ((ret=client_receive_specified(sd->ctx, buffer,
                                          COREFS_RESPONSE_DATA)) <= 0) {
            dprintf(stderr, "LISTXATTR: error receiving listxattr value.\n");
            return ret;
        }
    }

    /* Estimate the returned data size */
    corefs_packet * reply = (corefs_packet*)buffer;
    ret = reply->header.payload_size -
        RESPONSE_BASE_SIZE(reply->payload.response);
    memcpy(list, reply->payload.response.rop.raw, ret);
  
    return ret;

}

int do_removexattr_local(const char *path, const char *name) {
    return -EACCES;
}

/** Remove extended attributes */
int do_removexattr (const char * path, const char *name){
    char buffer[BUFFERSIZE];
    memset(buffer, 0, BUFFERSIZE);
    corefs_packet* packet = (corefs_packet*)buffer;
    int ret;
    unsigned int packet_size;
    server_data *sd=NULL;

    char r_path_[MAXPATH];
    char s_addr[MAXADDR];
    char *r_path = &r_path_[0];
    remove_addr(path, &r_path, s_addr);
    if (r_path[0]=='\0') {
        //there was no path other than the first '/'
        //ie this is for the root directory
        return do_removexattr_local(path, name);
    }
    ret = check_setup(s_addr, &sd);
    if (ret == -EHOSTUNREACH) return -EHOSTUNREACH;
    if (ret < 0) return -EIO;

#ifdef DEBUG
    dprintf(stderr, "REMOVEXATTR: path[%s] name[%s]\n", path, name);
#endif

    /* Get user info from the upper layer */
    if(my_ops.up_get_user_info)
        my_ops.up_get_user_info(&(packet->payload.request.user_ids),
                                path, NULL);

    /* Build the request packet */
    packet_size = build_xattr(packet, COREFS_XATTR_REMOVEXATTR, name,
                              r_path, 0, 0);

    /* encapsulate in network order */
    char request_buf[packet_size];
    memset(request_buf, 0, packet_size);
    ret = encap_corefs_header(request_buf, packet);
    encap_corefs_request(request_buf + ret, packet);
#ifdef DEBUG_NETWORK
    fprintf(stderr, "printing removexattr request\n");
    print_packet(*packet);
#endif 
    if (send_packet(sd->ctx, request_buf, packet_size) <=0) {
        dprintf(stderr, "error sending packet.\n");
        return -EIO;
    }
    memset(buffer, 0, BUFFERSIZE);
    if ((ret = client_receive_specified(sd->ctx, buffer,
                                        COREFS_RESPONSE_STATUS)) < 0) {
        dprintf(stderr, "GETXATTR: error receiving removexattr status.\n");
        return ret;
    }
    return 0;
}


int do_getxattr_local(const char *path, const char *name,
                     char *value, size_t size)
{
    /* Return no data so "ls -l mnt" doesn't complain about permissions */
    return -ENODATA;
}

int do_getxattr(const char *path, const char *name, char *value, size_t size)
{
    char buffer[BUFFERSIZE];
    memset(buffer, 0, BUFFERSIZE);
    corefs_packet* packet = (corefs_packet*)buffer;
    int ret;
    unsigned int packet_size;
    server_data *sd=NULL;

    char r_path_[MAXPATH];
    char s_addr[MAXADDR];
    char *r_path = &r_path_[0];
    remove_addr(path, &r_path, s_addr);
    if (r_path[0]=='\0') {
        //there was no path other than the first '/'
        //ie this is for the root directory
        return do_getxattr_local(path, name, value, size);
    }
    
    ret = check_setup(s_addr, &sd);
    if (ret == -EHOSTUNREACH) return -EHOSTUNREACH;
    if (ret < 0) return -EIO;

#ifdef DEBUG
    dprintf(stderr, "GETXATTR: path[%s] : name[%s] requested value of max size[%d]\n", path, name,size);
#endif

    /* Get user info from the upper layer */
    if(my_ops.up_get_user_info)
        my_ops.up_get_user_info(&(packet->payload.request.user_ids),
                                path, NULL);

    /* Build the request packet */
    packet_size = build_xattr(packet, COREFS_XATTR_GETXATTR, name, r_path,
                              size, 0);

    /* encapsulate in network order */
    char request_buf[packet_size];
    memset(request_buf, 0, packet_size);
    ret = encap_corefs_header(request_buf, packet);
    encap_corefs_request(request_buf + ret, packet);
#ifdef DEBUG_NETWORK
    fprintf(stderr, "printing getxattr request\n");
    print_packet(*packet);
#endif 
    if (send_packet(sd->ctx, request_buf, packet_size) <=0) {
        dprintf(stderr, "error sending packet.\n");
        return -EIO;
    }
    memset(buffer, 0, BUFFERSIZE);
    if(size == 0){
        if ((ret = client_receive_specified(sd->ctx, buffer,
                                            COREFS_RESPONSE_STATUS)) < 0) {
            dprintf(stderr, "GETXATTR: error receiving getxattr size.\n");
        }
        return ret;
    }
    else{
        if ((ret=client_receive_specified(sd->ctx, buffer,
                                          COREFS_RESPONSE_DATA)) <= 0) {
            dprintf(stderr, "GETXATTR: error receiving getxattr value.\n");
            return ret;
        }
    }

    /* Estimate the returned data size */
    corefs_packet * reply = (corefs_packet*)buffer;
    ret = reply->header.payload_size -
        RESPONSE_BASE_SIZE(reply->payload.response);
    memcpy(value, reply->payload.response.rop.raw, ret);
  
    return ret;
}

int do_setxattr_local(const char *path, const char *name, const char *value,
                size_t size, int flags)
{
    return -EACCES;
}

int do_setxattr(const char *path, const char *name, const char *value,
                size_t size, int flags)
{
    char buffer[BUFFERSIZE];
    char request_buf[BUFFERSIZE];
    memset(buffer, 0, BUFFERSIZE);
    memset(request_buf, 0, BUFFERSIZE);
  
    corefs_packet* packet=(corefs_packet*)buffer;
    int ret;
    unsigned int packet_size;
    server_data *sd=NULL;

    char r_path_[MAXPATH];
    char s_addr[MAXADDR];
    char *r_path = &r_path_[0];
    remove_addr(path, &r_path, s_addr);
    if (r_path[0]=='\0') {
        //there was no path other than the first '/'
        //ie this is for the root directory
        return do_setxattr_local(path, name, value, size, flags);
    }

    ret = check_setup(s_addr, &sd);
    if (ret == -EHOSTUNREACH) return -EHOSTUNREACH;
    if (ret < 0) return -EIO;
 
#ifdef DEBUG
    dprintf(stderr, "SETXATTR: path[%s] : name[%s]\n", path, name);
#endif
    

    /* Get user info from the upper layer */
    if(my_ops.up_get_user_info)
        my_ops.up_get_user_info(&(packet->payload.request.user_ids),
                                path, NULL);
  
    /* First send the command */
    packet_size = build_xattr(packet, COREFS_XATTR_SETXATTR, name,
                              r_path, size, flags);

    ret = encap_corefs_header(request_buf, packet);   /* encapsulate in
                                                       * network
                                                       * order */
    encap_corefs_request(request_buf + ret, packet);
  
#ifdef DEBUG_NETWORK
    fprintf(stderr, "printing setxattr request\n");
    print_packet(*packet);
#endif
  
    if (send_packet(sd->ctx, request_buf, packet_size) <=0) {
        dprintf(stderr, "setxattr: error sending packet.\n");
        return -EIO;
    }

    /* Now send the attribute value */
    packet_size = build_request_data(packet, value, size);
    ret = encap_corefs_header(request_buf, packet);
    encap_corefs_request(request_buf + ret, packet);
  
    if (send_packet(sd->ctx, request_buf, packet_size) <=0) {
        dprintf(stderr, "setxattr: error sending packet.\n");
        return -EIO;
    }
  
    memset(buffer, 0, BUFFERSIZE);
    if ((ret = client_receive_specified(sd->ctx, buffer,
                                        COREFS_RESPONSE_STATUS)) < 0) {
        dprintf(stderr, "setxattr returned error.\n");
        return ret;
    }
  
    return 0;
}

#endif


int simple_op_local(unsigned int type, const char* path1, off_t offset,
              mode_t mode1, const char *opt_path, char *s_addr)
{
    if (type == COREFS_SIMPLE_RMDIR) {
        server_data *sd=NULL;
        int sdret = check_setup(s_addr, &sd);
        if (sdret == -EHOSTUNREACH) return sdret;
        if (sdret < 0) return -EIO;

        int ret;
        struct stat st;
        char dir_path[MAXPATH+LOCALSIZE];
        sprintf(dir_path, "%s/mnt/%s", local_path, s_addr);
        int stret = stat(dir_path, &st);
        if (stret >= 0) {
            if ((ret = rmdir(dir_path))) {
                perror("Error deleting directory of server");
            }
        }

        shutdown(sd->g_mctx.sock, SHUT_RDWR);
        close(sd->g_mctx.sock);
        delete_server_data(sd);
        remove_info_ptr(&head, &tail, (void *)sd);
        return ret;
    }
    
    return -EACCES;
}

/* A common function that handles truncate, mknod, unlink... */
/*  all these functions return simple status and can be handled
 *  together. */
int simple_op(unsigned int type, const char* path1, off_t offset,
              mode_t mode1, const char *opt_path)
{
    unsigned int packet_size;
    int ret;
  
    corefs_packet packet;
    memset(&packet, 0, sizeof(packet));
    server_data *sd=NULL;

    char r_path_[MAXPATH];
    char s_addr[MAXADDR];
    char *r_path1 = &r_path_[0];
    char r_opt_path_[MAXPATH];
    char *r_opt_path = &r_opt_path_[0];

    if (type == COREFS_SIMPLE_SYMLINK) {
        remove_addr(opt_path, &r_opt_path, s_addr);
        strncpy(r_path1, path1, MAXPATH);
    }
    remove_addr(path1, &r_path1, s_addr);
    remove_addr(opt_path, &r_opt_path, NULL);
    
    if (r_path1[0]=='\0' || r_path1[1]=='\0') {
        //there was no path other than the first '/'
        //ie this is for the root directory
        //OR this is a simple_op on something in the root directory
        //and we will take that to be local (rmdir / not good anyways:P)
        return simple_op_local(type, path1, offset, mode1, opt_path, s_addr);
    }

    ret = check_setup(s_addr, &sd);
    if (ret == -EHOSTUNREACH) return -EHOSTUNREACH;
    if (ret < 0) return -EIO;

    
    /* Get user info from the upper layer */
    if(my_ops.up_get_user_info)
        my_ops.up_get_user_info(&(packet.payload.request.user_ids),
                                path1, opt_path);

    packet_size = build_simple(&packet, type, r_path1, offset, mode1,
                               r_opt_path);
    char buffer[packet_size];
    memset(buffer, 0, packet_size);  
    ret = encap_corefs_header(buffer, &packet);
    encap_corefs_request(buffer + ret, &packet);
#ifdef DEBUG_NETWORK
    fprintf(stderr, "simple_op: printing request\n");
    print_packet(packet);
#endif
    if (send_packet(sd->ctx, buffer, packet_size) <=0) {
        dprintf(stderr, "error sending packet.\n");
        return -EIO;
    }
    memset(buffer, 0, packet_size);
    if ((ret = client_receive_specified(sd->ctx, buffer,
                                        COREFS_RESPONSE_STATUS)) < 0) {
        dprintf(stderr, "error receiving simple status.\n");
        return ret;
    }
    return 0;
}


int do_access(const char* path, int mode){
#ifdef DEBUG
    dprintf(stderr, "ACCESS: path[%s] :  mode[%d]\n", path,mode);
#endif
  
    int ret = simple_op(COREFS_SIMPLE_ACCESS, path, 0, mode, NULL);
    return ret;
}

int do_truncate(const char *path, off_t size)
{
    int ret = 0;
#ifdef DEBUG
    dprintf(stderr, "TRUNCATE: %s : %llu\n", path, size);
#endif
    ret  = simple_op(COREFS_SIMPLE_TRUNCATE, path, size, 0, NULL);
    return ret;
}

int do_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int ret = 0;
#ifdef DEBUG
    dprintf(stderr, "MKNOD: %s \n", path);
#endif
    ret =  simple_op(COREFS_SIMPLE_MKNOD, path, 0, mode, NULL);
    return ret;
}

int do_unlink(const char *path)
{
    int ret;

#ifdef DEBUG
    dprintf(stderr, "UNLINK: %s \n", path);
#endif
    ret = simple_op(COREFS_SIMPLE_UNLINK, path, 0, 0, NULL);
    return ret;
}


int do_rename(const char* from, const char* to)
{
    int ret = 0;
    dprintf(stderr, "attempting to rename %s to %s\n", from,to);
    ret = simple_op(COREFS_SIMPLE_RENAME, from, 0, 0, to);
    return ret;
}

int do_symlink(const char* from, const char* to)
{
    dprintf(stderr, "Requesting SYMLINK: %s : %s \n", from, to);
    return simple_op(COREFS_SIMPLE_SYMLINK, from, 0, 0, to);
}


int do_link(const char* from, const char* to)
{
#ifdef DEBUG
    dprintf(stderr, "SYMLINK: old \'%s\' new  \'%s\'\n", from, to);
#endif

    return simple_op(COREFS_SIMPLE_LINK, from, 0, 0, to);
}
int do_mkdir(const char* path, mode_t mode)
{
    int ret;
    dprintf(stderr, "attempting to mkdir %s with perms %x\n", path, mode);
    ret = simple_op(COREFS_SIMPLE_MKDIR, path, 0, mode, NULL);
    return ret;
}

int do_rmdir(const char* path)
{
    int ret;
    dprintf(stderr, "Requesting rmdie: %s \n", path);
    ret = simple_op(COREFS_SIMPLE_RMDIR, path, 0, 0, NULL);
    return ret;
}

int do_readlink_local(const char* path, char* buf, size_t size)
{
    return -EACCES;
}

int do_readlink(const char* path, char* buf, size_t size)
{
    int ret;
    unsigned int packet_size;
    char buffer[BUFFERSIZE];
    corefs_packet packet;
    memset(&packet, 0, sizeof(packet));
    server_data *sd=NULL;

    char r_path_[MAXPATH];
    char s_addr[MAXADDR];
    char *r_path = &r_path_[0];
    remove_addr(path, &r_path, s_addr);
    if (r_path[0]=='\0') {
        //there was no path other than the first '/'
        //ie this is for the root directory
        return do_readlink_local(path, buf, size);
    }
    ret = check_setup(s_addr, &sd);
    if (ret == -EHOSTUNREACH) return -EHOSTUNREACH;
    if (ret < 0) return -EIO;

    /* Get user info from the upper layer */
    if(my_ops.up_get_user_info)
        my_ops.up_get_user_info(&(packet.payload.request.user_ids),
                                path, NULL);

    memset(buffer, 0, BUFFERSIZE);
    packet_size = build_fileop(&packet, COREFS_REQUEST_READLINK, 0,
                               size, r_path);
    ret = encap_corefs_header(buffer, &packet);
    encap_corefs_request(buffer + ret, &packet);

      
#ifdef DEBUG
    dprintf(stderr, "READLINK: %s : %u\n", path, size);
#endif
#ifdef DEBUG_NETWORK
    fprintf(stderr,"readlink request\n");
    print_packet(packet);
#endif

    if (send_packet(sd->ctx, buffer, packet_size) <=0) {
        dprintf(stderr, "error sending packet.\n");
        return -EIO;
    }

    memset(buffer, 0, BUFFERSIZE);
    if ((ret = client_receive_specified(sd->ctx, buffer,
                                        COREFS_RESPONSE_DATA)) <= 0) {
        dprintf(stderr, "error receiving readlink data.\n");
        return ret;
    }

    /* Estimate the returned data size */
    corefs_packet * reply = (corefs_packet*)buffer;
    ret = reply->header.payload_size -
        RESPONSE_BASE_SIZE(reply->payload.response);
    memcpy(buf, reply->payload.response.rop.raw, ret);
    buf[ret] = '\0';
    return 0;
}


int do_open(const char *path, struct fuse_file_info *fi)
{
#ifdef DEBUG
    dprintf(stderr, "OPEN: %s \n", path);
#endif
  
    int ret = simple_op(COREFS_SIMPLE_OPEN, path, 0, fi->flags, NULL);
    return ret;
}

int do_release(const char *path, struct fuse_file_info *fi)
{
#ifdef DEBUG
    dprintf(stderr, "RELEASE: %s \n", path);
#endif
    simple_op(COREFS_SIMPLE_RELEASE, path, 0,  fi->flags, NULL);

    return 0;
}

int do_chmod(const char *path, mode_t mode)
{
 
#ifdef DEBUG
    dprintf(stderr, "CHMOD: %s mode %u\n", path, mode);
#endif
    /*  we assume that the uid and gid of the user is same at the client
     *   and server side. The upper layer can performing its own
     *   mapping, if necessary. */
    return  simple_op(COREFS_SIMPLE_CHMOD, path, 0, mode, NULL);
}

int do_flush (const char * path, struct fuse_file_info * fi)
{
    /*   Place holder function; */
    return 0;
}

int do_utime (const char * path, struct utimbuf * tbuf){
    /*  we use offset and mode1 variables for actime and modtime,
     *  respectively */

    if(tbuf == NULL){

        struct timeval tv;
        struct timezone tz;
        gettimeofday(&tv, &tz);
#ifdef DEBUG
        dprintf(stderr, "UTIME: %s actime %lu modtime %lu\n",
                path, tv.tv_sec,tv.tv_sec);
#endif
        simple_op(COREFS_SIMPLE_UTIME, path, tv.tv_sec, tv.tv_sec, NULL);
    }
#ifdef DEBUG
    dprintf(stderr, "UTIME: %s actime %lu modtime %lu\n", path,
            tbuf->actime, tbuf->modtime);
#endif
    return simple_op(COREFS_SIMPLE_UTIME, path, tbuf->actime,
                     tbuf->modtime, NULL);
}

int fuse_argc=0;
char* fuse_argv[20];

void add_fuse_arg(char* new_arg)
{
    char* new_alloc;
    new_alloc=malloc(strlen(new_arg)+1);
    strcpy(new_alloc, new_arg);
    fuse_argv[fuse_argc++]=new_alloc;
}

void usage(char * prog)
{
    fprintf(stderr, "usage:%s <corefs usage> <upper-layer usage>\n", prog);
    fprintf(stderr, "corefs usage: [options] mount-point\n");
    fprintf(stderr, "options:\n"
            "   -S   corefs server name\n"
            "   -P   corefs server port\n"
            "   [FUSE options]           \n");
  
}


int parse_arguments(int argc, char** argv,char * config_path)
{
    int ch, option_index=0;
    const char argstr[]="P:o:S:dsh";
    //extern char* optarg;
    int i;
    char g_server_addr[4];
    memset(g_server_addr, 0, 4);

    opterr=0; // ignore unknown options

    static struct option long_options[] = {
        {"server", 1, 0, 'S'},
        {"port", 1, 0, 'P'},
        {"debug", 0, 0, 'd'},
        {"fuse_arg", 1, 0, 'o'},
        {"single_threaded", 0, 0, 's'},
        {"help", 0, 0, 'h'},
        {0,0,0,0}
    };

    add_fuse_arg(argv[0]);
    add_fuse_arg("-s"); // For now, must run FUSE single-threaded!
    /* Next two lines cause FUSE to run in direct_io mode.
       Useful for benchmarking, but doesn't allow execution of files */
    //add_fuse_arg("-o");
    //add_fuse_arg("direct_io");
  
    /*  Check if upper layer has got all of its command line args */
    if(my_ops.up_parse_arguments){    
        if(my_ops.up_parse_arguments((char*)argstr, argc, argv) != PROCEED) {
            usage(argv[0]);
            exit(1);
        }
    }

    optind = 0;
  
    while ((ch=getopt_long(argc, argv, argstr, long_options, &option_index)) != -1) {
        switch (ch) {
        case 'S': {
            char server_addr[MAXADDR];
            strncpy(server_addr, optarg, MAXADDR);
            int ret = check_setup(server_addr, NULL);
            if (ret == -EHOSTUNREACH) return -EHOSTUNREACH;
            if (ret < 0) return -EIO;
            
            break;
        }
        case 'P': 
            if(optarg){
                server_port = atoi(optarg);
            }
            break;
        case 'd': {
            add_fuse_arg("-d");
            break;
        }
        case 'o':
            if(optarg){
                add_fuse_arg("-o");
                add_fuse_arg(optarg);
            }
            break;
        case 's':
            add_fuse_arg("-s");
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            fprintf(stderr, "ignoring option character %c\n", optopt);
            break;
        }
    }
    while (optind < argc) {
        fprintf(stderr, "non-option element: %s\n",argv[optind]);
        add_fuse_arg(argv[optind]);
        optind++;
    }

    fprintf(stderr, "arguments for FUSE: ");
    for (i=0; i<fuse_argc; i++) {
        fprintf(stderr, "%s ", fuse_argv[i]);
    }
    fprintf(stderr, "\n");
    return 0;
}



int main(int argc, char *argv[])
{
    char config_path[MAX_PATH];
    memset(config_path,0,MAX_PATH);

    /* Setup all the initial function pointers */
    my_ops.getattr = do_getattr;
    my_ops.read = do_read;
    my_ops.write = do_write;
    my_ops.readdir = do_readdir;
    my_ops.truncate = do_truncate;
    my_ops.mknod = do_mknod;
    my_ops.unlink = do_unlink;
    my_ops.rename = do_rename;
    my_ops.symlink = do_symlink;
    my_ops.readlink = do_readlink;
    my_ops.mkdir = do_mkdir;
    my_ops.rmdir = do_rmdir;
    my_ops.open = do_open;
    my_ops.release = do_release;
    my_ops.utime = do_utime;
    my_ops.chmod = do_chmod;
    my_ops.link = do_link;
    my_ops.flush = do_flush;
    my_ops.access = do_access;
    my_ops.destroy = do_destroy;
#ifdef HAVE_SETXATTR
    my_ops.setxattr = do_setxattr;
    my_ops.getxattr = do_getxattr;
    my_ops.listxattr = do_listxattr;
    my_ops.removexattr = do_removexattr;
#endif

    /* Check with corefs_op_init if we need to replace any of the pointers */
    client_op_init(&my_ops);

    /* Call the upper layer's init function */
    if(up_client_init(&my_ops) != PROCEED){
        fprintf(stderr, "ERROR: up_client_init failed, proceeding to load corefs...\n");
    }
    
    /* set the local path to $HOME/.corefs */
    local_path = calloc(LOCALSIZE,1);
    sprintf(local_path, "%s/.corefs",getenv("HOME"));
    
    /* See if the local path exists and if there is a mnt directory in it.
       Create, if there isn't  */
    struct stat st;
    char dir_path[MAXPATH+LOCALSIZE];
    int stret = stat(local_path, &st);
    if (stret < 0) {
        if (mkdir(local_path, 0700)) {
            perror("Failed to create local .corefs directory");
            exit(1);
        }
    }
    memset(dir_path, 0, MAXPATH+LOCALSIZE);
    sprintf(dir_path, "%s/mnt", local_path);
    stret = stat(dir_path, &st);
    if (stret < 0) {
        if (mkdir(dir_path, 0700)) {
            perror("Failed to create local .corefs/mnt directory");
            exit(1);
        }
    }

    init_list_head(&head);
    
    /* Parse the command line args */
    parse_arguments(argc, argv, config_path);
    init_sizes();
    if(corefs_main(fuse_argc, fuse_argv, &my_ops) != 0){
        usage(argv[0]);
        return -1;
    }
    return 0;
  
}


