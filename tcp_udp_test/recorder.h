#ifndef RECORDER_H_
#define RECORDER_H_

#include <stdlib.h>
#include <stdio.h>



#ifdef __cplusplus
extern "C" {
#endif

int create_file(const char* filename, const char* buf, unsigned int len);

int append_file(const char* filename, const char* buf, unsigned int len);

int create_multi_dir(const char* path);

FILE * open_file_only(const char* filename);


#ifdef __cplusplus
}
#endif

#endif
