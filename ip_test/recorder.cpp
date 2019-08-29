#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "recorder.h"

//@deprecated
int create_file(const char* filename, const char* buf, unsigned int len)
{
    //return 1;

    FILE * fp;
    fp = fopen(filename,"wb");
    if(fp == NULL)
    {
        return 0;
    }
    if(len>0 && buf != NULL)
        fwrite(buf, sizeof(char),len,fp);
    fclose(fp);
    return 1;
}

//create file if doesn't exist
int append_file(const char* filename, const char* buf, unsigned int len)
{
    //return 1;
    //if(create_multi_dir(filename,23)==0) return 0;
    FILE * fp;
    fp = fopen(filename,"ab");
    if(fp == NULL)
    {
        if(create_multi_dir(filename)==0)
            return 0;
        else
        {
             fp = fopen(filename,"ab");
             if(fp == NULL) return 0;
        }
    }
    if(len>0 && buf != NULL)
        fwrite(buf, sizeof(char),len,fp);
    fclose(fp);
    return 1;
}

FILE * open_file_only(const char* filename)
{
    FILE * fp = NULL;
    fp = fopen(filename,"ab");
    if(fp == NULL)
    {
        if(create_multi_dir(filename)==0)
        {
            //info_print(("Can not create file directory:%s",filename));
            return NULL;
        }
        else
        {
             fp = fopen(filename,"ab");
             if(fp == NULL)
             {
                // info_print(("Can not open file:%s",data_file_path));
                 return NULL;
             }
        }
    }
    return fp;
}

//recursive create dir.notice: The last level of the path will be graded as file e.g /a/b/c  will create dir /a/b only
int create_multi_dir(const char* path)
{
    int i,len=0;
    len =strlen(path);
    if(len == 0)
    {
        printf("dirpath lenth == 0!\n");
        return 0;
    }
    while(len&&path[--len] != '/');
    if(len < 1)
    {
        printf("create_multi_dir: no / found! \n");
        return 0;
    }
    len = len+1;
    char dir_path[128+1]; 	//warning: may out of index
    dir_path[len] = '\0';

    strncpy(dir_path, path, len);

    for(i = 0 ;i < len; i++)
    {
        if(dir_path[i] == '/' && i > 0)
        {
            dir_path[i]='\0';
            if(access(dir_path, F_OK)<0)
            {
                if(mkdir(dir_path, 0755) < 0)
                {
                    return 0;
                }
            }
            dir_path[i]='/';
        }
    }
    return 1;
}


