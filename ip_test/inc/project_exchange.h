#define HTTP_RESOURCE_NAME "HTTP_INFO"
#define FTP_RESOURCE_NAME "FTP_INFO"
#define MAIL_RESOURCE_NAME "MAIL_INFO"
#define DNS_RESOURCE_NAME "DNS_INFO"
#define SSL_RESOURCE_NAME "SSL_INFO"
#define P2P_RESOURCE_NAME "P2P_INFO"


#define HTTP_TYPE 1
#define FTP_TYPE 2
#define SMTP_TYPE 3
#define POP3_TYPE 4
#define IMAP_TYPE 5
#define DNS_TYPE 6
#define P2P_TYPE 7
#define SSL_TYPE 8

typedef struct _resource
{
    char *json_info_string;//json格式串
    int len;//json格式串的长度
    int type;//资源类型,HTTP为1，FTP为2，SMTP为3，POP3为4，IMAP为5，DNS为6，P2P为7，SSL为8  
}resource,http_resource,ftp_resource,mail_resource,dns_resource,p2p_resource,ssl_resource;
void info_project_req_free_t(int thread_seq, void *project_req_value)
{
    resource *info=( dns_resource*)project_req_value;
    printf("\nfree_success\n");
    if(info->json_info_string!=NULL)
    {   
        free(info->json_info_string);
        info->json_info_string=NULL;
        free(info);
        info=NULL;
    }   
}
int strlen_safe(const char *str, int max_len)
{
    int i=0;
    if(str==NULL )
        return -1; 
    for(i=0;i<max_len;i++)
    {   
        if(0==str[i])
        {   

            return i;


        }   
    }   
    //超过了长度，直接返回>--1，此时调用函数需要对错误进行处理
    return -1;
}

