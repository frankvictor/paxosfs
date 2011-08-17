#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "log.h"

char * log_path = "./paxosfs.log";

int log_cmd(char* cmd) {
	FILE *f = fopen(log_path,"a"); 
	size_t len = strlen(cmd);

	if(f == NULL) {
		printf("Error in opening file: %s", log_path);
	}
	fwrite(cmd, len , 1, f);
	fwrite("\n", 1 , 1, f);
	fclose(f);

	return 0;
}

int log_write(char* path, size_t offset, size_t size, char* data) {
	char *buf;
	int path_len = 512;
	int offset_size_len = 50;
	int data_size = size;
	FILE *f = fopen(log_path,"a"); 

	buf = (char*)malloc(path_len + offset_size_len + data_size);
	bzero(buf, path_len + offset_size_len + data_size);
	sprintf(buf,"WRITE<>%s<>%llu<>%llu<>%s", path, (long long unsigned int)offset, (long long unsigned int)size, data);

	if(f == NULL) {
		printf("Error in opening file: %s", log_path);
	}
	fwrite(buf, strlen(buf) , 1, f);
	fwrite("\n", 1 , 1, f);
	fclose(f);
	free(buf);

	return 0;
}

int log_setxattr(char* path, char* attrname, char* data, size_t sizeofvalue, int flags) {
	return 0;
}

int log_removexattr(char* path, char* attrname) {
	return 0;
}

int log_chmod(char* path, unsigned int mode) {
	return 0;
}

int log_truncate(char* path, unsigned int offset) {
	return 0;
}

int log_mknod(char* path, unsigned int mode, unsigned int dev) {
	return 0;
}

int log_unlink(char* path) {
	return 0;
}

int log_symlink(char* path1, char* path2) {
	return 0;
}
