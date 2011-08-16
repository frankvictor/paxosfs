#include <stdio.h>
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
}

int log_write(char* path, size_t offset, size_t size, char data) {
}

int log_setxattr(char* path, char* attrname, char* data, size_t sizeofvalue, int flags) {
}

int log_removexattr(char* path, char* attrname) {
}

int log_chmod(char* path, unsigned int mode) {
}

int log_truncate(char* path, unsigned int offset) {
}

int log_mknod(char* path, unsigned int mode, unsigned int dev) {
}

int log_unlink(char* path) {
}

int log_symlink(char* path1, char* path2) {
}
