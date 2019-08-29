#include <MESA/MESA_list_queue.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
 #include "recorder.h"
//#define DATA_QUEUE_LEN 10000
MESA_lqueue_head  log_writer_init(const char *path);
//MESA_lqueue_head cert_writer_init(const char *path);
#define MAX_FILE_NAME_LEN 255
typedef struct queue_buffer_t
{
 //   char file_path[MAX_FILE_NAME_LEN];
    void *pdata;
    unsigned int len;
}queue_buffer;

typedef struct cert_queue_buffer_t
{
        char file_name[MAX_FILE_NAME_LEN];
        void *pdata;
        unsigned int len;
}cert_queue_buffer;
