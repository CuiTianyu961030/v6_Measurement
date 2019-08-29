#include"log_writer.h"
#include <MESA/MESA_handle_logger.h>
#define DATA_QUEUE_LEN 10000
#define DPKT_PLUG_NAME "runtime_log"
extern MESA_lqueue_head g_log_queue;
extern MESA_lqueue_head g_cert_queue;
extern time_t g_CurrentTime;
int g_log_curtime=0;
int g_cert_curtime=0;

char g_log_time_buf[256]={0};
char g_log_filename[256]={0};
//char g_cert_time_buf[256]={0};
//char g_cert_filename[256]={0};

FILE *g_fp=NULL;
extern char g_json_path[256];
//extern char g_cert_path[256];
extern long iwrite[],iread;
extern void* g_log_handle;
void  writer_to_log( char *buf,int len)
{
    tm* tm_temp=localtime(&g_CurrentTime);
	/*
    if(g_log_curtime==tm_temp->tm_hour)
    {
        fprintf(g_fp,"%s\n",buf);
        return;
    }
    else
    {
        //printf("\n\n\n\n%s\n\n\n\n","else");
        if(g_fp!=NULL)
        {
            iwrite[16]=iwrite[0]+iwrite[1]+iwrite[2]+iwrite[3]+iwrite[4]+iwrite[5]+iwrite[6]+iwrite[7]+iwrite[8]\
                       +iwrite[9]+iwrite[10]+iwrite[11]+iwrite[12]+iwrite[13]+iwrite[14]+iwrite[15];
            MESA_handle_runtime_log(g_log_handle,RLOG_LV_INFO,DPKT_PLUG_NAME,"write quene num:%d\tread quene num:%d",iwrite[16],iread);
            fclose(g_fp);
        }
	
        g_log_curtime=tm_temp->tm_hour;
		*/
        sprintf(g_log_time_buf,"%4d%02d%02d/dns_%4d%02d%02d_%02d",\
                1900+tm_temp->tm_year,\
                tm_temp->tm_mon+1,\
                tm_temp->tm_mday,\
                1900+tm_temp->tm_year,\
                tm_temp->tm_mon+1,\
                tm_temp->tm_mday,\
                tm_temp->tm_hour
                );
        sprintf(g_log_filename,"%s/%s",g_json_path,g_log_time_buf);
        g_fp=open_file_only(g_log_filename);
        if(g_fp==NULL)
        {
            printf("g_fp is null\n");
            return;
        }
        fprintf(g_fp,"%s\n",buf);
        fclose(g_fp);        
    //

}

//char key[16]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
/*
void  writer_to_cert( char *buf,char file_name[],int len)
{
    tm* tm_temp=localtime(&g_CurrentTime);
    sprintf(g_cert_time_buf,"%4d%02d%02d",\
            1900+tm_temp->tm_year,\
            tm_temp->tm_mon+1,\
            tm_temp->tm_mday);
    
    if(g_cert_curtime!=tm_temp->tm_hour)
    {
        for(int i=0;i<16;i++)
        {
            for(int j=0;j<16;j++)
            {
                sprintf(g_cert_filename,"%s/%s/%02d/%c%c/",g_cert_path,g_cert_time_buf,tm_temp->tm_hour,key[i],key[j]);
                create_multi_dir(g_cert_filename);
                //  printf("%s\n",g_cert_filename);
            }
        }
        g_cert_curtime=tm_temp->tm_hour;
    }
    sprintf(g_cert_filename,"%s/%s/%02d/%c%c/%s",g_cert_path,g_cert_time_buf,tm_temp->tm_hour,file_name[0],file_name[1],file_name);
    
    //printf("%s %d\n",g_cert_filename,len);
    FILE *g_cert_fp=NULL;
    g_cert_fp=fopen(g_cert_filename,"wb");
    if(g_cert_fp==NULL)
    {
        printf("g_cert_fp is null\n");
        return;
    }
    fwrite(buf,sizeof(char),len,g_cert_fp);
    //   fprintf(g_cert_fp,"%s",buf);
    fclose(g_cert_fp);
}*/
//


void *log_writer_thread(void *arg)
{

    int ret;
    queue_buffer buffer;
    g_fp=NULL;

    long buffer_len = sizeof(buffer);
    char path[256]={0};
    memcpy(path,arg,strlen((char *)arg ));
    //   printf("%s\n",path);
    while (1)
    {
        ret = MESA_lqueue_try_get_head(g_log_queue, &buffer, &buffer_len);
        if (MESA_QUEUE_RET_OK == ret)
        {
            writer_to_log((char *)buffer.pdata,buffer.len);
            iread++;
            /*
            //create_multi_dir((const char *)buffer.file_path);
            //create_file(( char *)buffer.file_path,(const char *)buffer.pdata,buffer.len);
            append_file(g_log_filename,(char *)buffer.pdata,buffer.len);
            */
            free(buffer.pdata);
            buffer.pdata=NULL;
        }
        else
        {
            usleep(64);
        }
    }

    return NULL;
}
/*
void *cert_writer_thread(void *arg)
{
    int ret;
    cert_queue_buffer buffer;
    long buffer_len = sizeof(buffer);
    char path[256]={0};
    memcpy(path,arg,strlen((char *)arg ));
    while (1)
    {
        ret = MESA_lqueue_try_get_head(g_cert_queue, &buffer, &buffer_len);
        if (MESA_QUEUE_RET_OK == ret)
        {
            writer_to_cert((char *)buffer.pdata,buffer.file_name,buffer.len);
            //iread++;
            free(buffer.pdata);
            buffer.pdata=NULL;
        }
        else
        {
            usleep(64);
        }
    }
    return NULL;
}*/


MESA_lqueue_head  log_writer_init(const char *path)
{
    create_multi_dir(path);
    // memcpy(g_json_path,path,strlen(path));
    g_log_queue= MESA_lqueue_create(1, DATA_QUEUE_LEN);
    if(g_log_queue ==NULL)
    {
        printf("log queue init error\n");
        return NULL;
    }
    pthread_t thread_index;
    if(  pthread_create(&thread_index, NULL, log_writer_thread,(void *) path)!=0)
    {
        printf("Thread log init error\n");
        return NULL;
    }
    return g_log_queue;
}

/*
MESA_lqueue_head  cert_writer_init(const char *path)
{
    create_multi_dir(path);
    // memcpy(g_cert_path,path,strlen(path));
    g_cert_queue= MESA_lqueue_create(1, DATA_QUEUE_LEN);
    if(g_cert_queue ==NULL)
    {               
        printf("cert queue init error\n");
        return NULL;    
    }                           
    pthread_t thread_index;                 
    if(  pthread_create(&thread_index, NULL, cert_writer_thread,(void *) path)!=0)
    {                                                   
        printf("Thread log init error\n");
        return NULL;            
    }                                   
    return g_cert_queue;                             
}*/
