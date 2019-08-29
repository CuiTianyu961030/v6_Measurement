#define ENABLE_DEBUG_PRINT
#define ENABLE_INFO_PRINT

#include <sstream>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <math.h>
#include "tcp_udp_demo.h"
#include "log_writer.h"

#ifdef ENABLE_PRETTY_PRINT
#define DYNAMIC_WRITER PrettyWriter<StringBuffer>
#else
#define DYNAMIC_WRITER Writer<StringBuffer>
#endif

#define MAX_STR_IP_LEN 64
#define prot_flag_req_num 5
#define prot_flag_res_num 2
int no_entry_req_prot_flag_num = 0;
int no_entry_res_prot_flag_num = 0;
//char *Host, *User_Agent, *REQ_LINE, *MESSAGE_URL, *URI, *REFERER, *COOKIE;
//char *SERVER, *ETAG, *LOCATION, *RES_LINE;
int flag0 = 0;
int flag1 = 0;
int flag2 = 0;
int http_type;
uint32 session_seq = 0;
extern time_t g_CurrentTime;
MESA_lqueue_head g_log_queue;
char g_json_path[256] = "/home/cuitianyu/tcp_udp/tcp_udp_log";
long iwrite[128]={0},iread=0;
void *g_log_handle;
char g_log_path[256]="/home/cuitianyu/tcp_udp/runtime_log";
int udp_flag = 0;
typedef struct _service_pmeinfo_t
{
    DYNAMIC_WRITER *jsonwriter;
    rapidjson::StringBuffer *infoBuffer;
}service_pmeinfo_t;

void getip(unsigned int addr, char buf[20])
{
    char *ip = NULL;
    in_addr inaddr;
    inaddr.s_addr = addr;
    ip = inet_ntoa(inaddr);
    strcpy(buf, ip);
}

void getip6(unsigned char addr[IPV6_ADDR_LEN], char buf[MAX_STR_IP_LEN])
{	
	inet_ntop(AF_INET6, addr, buf, MAX_STR_IP_LEN);
}

int hex_to_dec(char ipv6_str_temp[10], int len)
{
	int ip_temp_dec = 0;
	int i, j;
	for(i = 0, j = len - 1; i <= len - 1; i++, j--)
	{
		switch(ipv6_str_temp[i])
		{
			case 97: 
			{
				ip_temp_dec = ip_temp_dec + pow(16,j) * 10;
				break;
			}
			case 98:
			{
				ip_temp_dec = ip_temp_dec + pow(16,j) * 11;
				break;
			}
			case 99: 
			{
				ip_temp_dec = ip_temp_dec + pow(16,j) * 12;
				break;
			}
			case 100: 
			{
				//printf("\n1\n");
				ip_temp_dec = ip_temp_dec + pow(16,j) * 13;
				//printf("\n--%d--\n",ip_temp_dec );
				break;
			}
			case 101: 
			{
				ip_temp_dec = ip_temp_dec + pow(16,j) * 14;
				break;
			}
			case 102: 
			{
				ip_temp_dec = ip_temp_dec + pow(16,j) * 15;
				break;
			}
			default:
			{
				//printf("\n--%d--\n",(int)ipv6_str_temp[i]);
				ip_temp_dec = ip_temp_dec + ((int)ipv6_str_temp[i]-48) * pow(16,j);
				//printf("----\n%d\n----", ip_temp_dec);
			}
		}
	}
	//printf("\n%d\n",ip_temp_dec);
	return ip_temp_dec;
}

void itoa(int ipv6_temp_dec, char str[20])
{
	int i = 0, j;
	char temp;
	do{
		str[i++] = ipv6_temp_dec % 10 + '0';
	}while((ipv6_temp_dec /= 10) > 0);
	str[i] = '\0';
	j = i - 1;
	i = 0;
	while(i < j)
	{
		temp = str[i];
		str[i] = str[j];
		str[j] = temp;
		i++;
		j--;
	}
}

int put_data_in_log_queue( char *content, int len)
{
    if(len<=0)
    {
        return 0;
    }
    queue_buffer data;

    char *buf=(char *)calloc(len+1,sizeof(char));
    if(buf==NULL)
    {
        return 0;
    }
    memcpy(buf,content,len);

    data.pdata = buf;
    data.len=len;
    int succ = MESA_lqueue_join_tail(g_log_queue, &data, sizeof(data));

    if (MESA_QUEUE_RET_OK != succ)
    {
        printf("MESA_lqueue_try_join_tail Failed FLAG:%d May lost data sorry!\n", succ);
        return 0;
    }
    return 1;

}

int init_pmeinfo(void** pme, const streaminfo* a_stream)
{
	
    service_pmeinfo_t* service_pme = (service_pmeinfo_t*)malloc(sizeof(service_pmeinfo_t));
    if (service_pme == NULL)
    {
        return -1;
    }
    service_pme->infoBuffer = new StringBuffer();
    service_pme->jsonwriter = new DYNAMIC_WRITER(*service_pme->infoBuffer);
	
	//if(a_stream->addr.tuple4_v6->saddr != NULL)
    	//printf("%s\n", a_stream->addr.tuple4_v6->saddr);
		
	//if(flag0 == 4 || flag1 == 1)
	//{
		service_pme->jsonwriter->StartObject();
		//if(flag0 == 5 || flag1 == 1)
		//{
		service_pme->jsonwriter->Key("time");
		service_pme->jsonwriter->Uint64(g_CurrentTime);
		service_pme->jsonwriter->Key("create_time");
		service_pme->jsonwriter->Uint64(a_stream->ptcpdetail->createtime);
		service_pme->jsonwriter->Key("last_time");
		service_pme->jsonwriter->Uint64(a_stream->ptcpdetail->lastmtime);
		//char buf[MAX_STR_IP_LEN];
		//getip6(a_stream->pfather->addr.ipv6->saddr, buf);
		//printf("\nIP: %s\n", buf);
		//printf("\nstart layer: %d\n", a_stream->addr.addrtype);
		//printf("\nfather layer: %d\n", a_stream->pfather->addr.addrtype);
		//printf("\nfather father layer: %d\n", a_stream->pfather->pfather->addr.addrtype);
		//printf("\nfather father father layer: %d\n", a_stream->pfather->pfather->pfather->addr.addrtype);
		//printf("\nfather father father father layer: %d\n", a_stream->pfather->pfather->pfather->pfather->addr.addrtype);
		char sip[MAX_STR_IP_LEN] = {0};
		char dip[MAX_STR_IP_LEN] = {0};
		//printf("%d",a_stream->addr.addrtype);
		//if(flag0 == 4 )
		//{
			if(a_stream->addr.addrtype == ADDR_TYPE_IPV4 || a_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4)
			{
				//printf("1\n");
				getip(a_stream->addr.ipv4->saddr, sip);
				getip(a_stream->addr.ipv4->daddr, dip);
				//count = count +1;
			}
			else if(a_stream->addr.addrtype == ADDR_TYPE_IPV6 || a_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V6)
			{
				//printf("2\n");
				getip6(a_stream->addr.ipv6->saddr, sip);
				getip6(a_stream->addr.ipv6->daddr, dip);
				//count = count +1;
			}
		//}
		/*
		if(flag1 == 1 )
		{
			if(a_stream->addr.addrtype == ADDR_TYPE_IPV4 || a_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4)
			{
				//printf("1\n");
				getip(a_stream->addr.tuple4_v4->saddr, dip);
				getip(a_stream->addr.tuple4_v4->daddr, sip);
				//count = count +1;
			}
			else if(a_stream->addr.addrtype == ADDR_TYPE_IPV6 || a_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V6)
			{
				//printf("2\n");
				getip6(a_stream->addr.tuple4_v6->saddr, dip);
				getip6(a_stream->addr.tuple4_v6->daddr, sip);
				//count = count +1;
			}
		}*/
		
		service_pme->jsonwriter->Key("sip");
		service_pme->jsonwriter->String(sip);
		service_pme->jsonwriter->Key("dip");
		service_pme->jsonwriter->String(dip);
		//if(flag0 == 4 )
		//{
		if(a_stream->addr.addrtype == ADDR_TYPE_IPV4 || a_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4)
		{
			service_pme->jsonwriter->Key("sport");
			service_pme->jsonwriter->Uint(ntohs(a_stream->addr.ipv4->source));
			service_pme->jsonwriter->Key("dport");
			service_pme->jsonwriter->Uint(ntohs(a_stream->addr.ipv4->dest));
		}
		else if(a_stream->addr.addrtype == ADDR_TYPE_IPV6 || a_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V6)
		{
			service_pme->jsonwriter->Key("sport");
			service_pme->jsonwriter->Uint(ntohs(a_stream->addr.ipv6->source));
			service_pme->jsonwriter->Key("dport");
			service_pme->jsonwriter->Uint(ntohs(a_stream->addr.ipv6->dest));
		}
		//}
		/*
		if(flag1 == 1 )
		{
			service_pme->jsonwriter->Key("sport");
			service_pme->jsonwriter->Uint(ntohs(a_stream->addr.tuple4_v6->dest));
			service_pme->jsonwriter->Key("dport");
			service_pme->jsonwriter->Uint(ntohs(a_stream->addr.tuple4_v6->source));
		}*/
		
		service_pme->jsonwriter->Key("info_type");
		service_pme->jsonwriter->Uint64(a_stream->type);
		
		//service_pme->jsonwriter->Key("payload");
		//service_pme->jsonwriter->String(a_stream->ptcpdetail->pdata);
		// char payload[10000]={'0'};
		printf("datalen is %d\n", a_stream->ptcpdetail->datalen);
		printf("pdata1 is %d hex: %x\n", *(unsigned int *)a_stream->ptcpdetail->pdata, *(unsigned int *)a_stream->ptcpdetail->pdata);
		FILE *fpWrite=fopen("pdata.txt", "w");
		fprintf(fpWrite, "%x", (char *)a_stream->ptcpdetail->pdata);
		fclose(fpWrite);
		int i = 0;
		// for(i = 0; i < a_stream->ptcpdetail->datalen; i++)
		// {
		    // printf("datalen is %d   %d\n", a_stream->ptcpdetail->datalen,i);
			// //printf("this is a test : %s\n ", &payload);
			// payload[i] = ((char *)a_stream->ptcpdetail->pdata)[i];
			// printf("this is a test : %s\n ", payload[i]);
		// }
			//payload[i] = a_stream->ptcpdetail->*(pdata +i);
			// printf("this is a test : %s\n ", *payload);
	//flag2 = 1;
//	}
     *pme = service_pme;
	
    return 0;
}


char tcp_entry(const struct streaminfo* a_tcp,  void** pme, int thread_seq, const void* raw_pkt)
{
	
	/*
	init_pmeinfo(pme,a_stream);
    if((session_info->session_state&SESSION_STATE_PENDING))//会话处于pending状态，申请内存
    {
        if(init_pmeinfo(pme,a_stream)!=0)
        {
            return PROT_STATE_DROPME;
        }
    }
    else
    {
        if(*pme==NULL)
        {
            return PROT_STATE_DROPME;
        }
    }

   
    
    if(!(session_info->session_state&SESSION_STATE_CLOSE))//会话未结束
    {
        return PROT_STATE_GIVEME;
    }
	//init_pmeinfo(pme, a_stream);
	//http_analyse(session_info, pme, a_stream);


    if (!session_info->session_state&SESSION_STATE_CLOSE)
    {
        return PROT_STATE_GIVEME;
    }
    
    service_pmeinfo_t* service_pme = (service_pmeinfo_t*) *pme;
	
	//int flag_end = 0;
	
	//if(flag2 == 1)
	//{
		service_pme->jsonwriter->EndObject();
		
		printf("%s\n\n", service_pme->infoBuffer->GetString());
		//flag2 = 0;		//flag_end = 1;
		put_data_in_log_queue((char *)service_pme->infoBuffer->GetString(),strlen(service_pme->infoBuffer->GetString()));
		iwrite[thread_seq]++;
		//free(*pme);
	//}
    delete(service_pme->infoBuffer);
    delete(service_pme->jsonwriter);


    free(*pme);
	
	//if(flag_end == 0)
	//return 0;
	return PROT_STATE_DROPME;
	//if(flag_end == 1)
		//return PROT_STATE_DROPME;
		
	*/
	if (a_tcp->opstate == OP_STATE_PENDING)
    {
        if (init_pmeinfo(pme, a_tcp) != 0)
        {
            return APP_STATE_DROPME;
        }
    }
   
    else
    {
        if (*pme == NULL)
        {
            return APP_STATE_DROPME;
        }
    }
    

    service_pmeinfo_t* service_pme = (service_pmeinfo_t*) *pme;
	service_pme->jsonwriter->Key("protocol");
	service_pme->jsonwriter->String("tcp");
    service_pme->jsonwriter->EndObject();
    printf("%s\n\n", service_pme->infoBuffer->GetString());
	put_data_in_log_queue((char *)service_pme->infoBuffer->GetString(),strlen(service_pme->infoBuffer->GetString()));
	iwrite[thread_seq]++;
    delete(service_pme->infoBuffer);
    delete(service_pme->jsonwriter);
    free(*pme);
    return APP_STATE_DROPME;
	
}

char udp_entry(const struct streaminfo* a_udp,  void** pme, int thread_seq, const void* raw_pkt)
{
	udp_flag = 1;
	/*
    if((session_info->session_state&SESSION_STATE_PENDING))//会话处于pending状态，申请内存
    {
        if(init_pmeinfo(pme,a_stream)!=0)
        {
            return PROT_STATE_DROPME;
        }
    }
    else
    {
        if(*pme==NULL)
        {
            return PROT_STATE_DROPME;
        }
    }
    
    if(!(session_info->session_state&SESSION_STATE_CLOSE))//会话未结束
    {
        return PROT_STATE_GIVEME;
    }
	//init_pmeinfo(pme, a_stream);
	//http_analyse(session_info, pme, a_stream);


    if (!session_info->session_state&SESSION_STATE_CLOSE)
    {
        return PROT_STATE_GIVEME;
    }
    
    service_pmeinfo_t* service_pme = (service_pmeinfo_t*) *pme;
	
	
	service_pme->jsonwriter->EndObject();
		
	printf("%s\n\n", service_pme->infoBuffer->GetString());

	put_data_in_log_queue((char *)service_pme->infoBuffer->GetString(),strlen(service_pme->infoBuffer->GetString()));
	iwrite[thread_seq]++;

	
    delete(service_pme->infoBuffer);
    delete(service_pme->jsonwriter);


    free(*pme);
	
	
	return PROT_STATE_DROPME;
	*/
	if (a_udp->opstate == OP_STATE_PENDING)
    {
        if (init_pmeinfo(pme, a_udp) != 0)
        {
            return APP_STATE_DROPME;
        }
    }
   
    else
    {
        if (*pme == NULL)
        {
            return APP_STATE_DROPME;
        }
    }
    

    service_pmeinfo_t* service_pme = (service_pmeinfo_t*) *pme;
	service_pme->jsonwriter->Key("protocol");
	service_pme->jsonwriter->String("udp");
    service_pme->jsonwriter->EndObject();
    printf("%s\n\n", service_pme->infoBuffer->GetString());
	put_data_in_log_queue((char *)service_pme->infoBuffer->GetString(),strlen(service_pme->infoBuffer->GetString()));
	iwrite[thread_seq]++;
    delete(service_pme->infoBuffer);
    delete(service_pme->jsonwriter);
    free(*pme);
	
    return APP_STATE_DROPME;
}

int tcp_udp_demo_init()
{
    printf("\nEntry TCP/UDP Capture\n");
	g_log_queue = log_writer_init(g_json_path);
    if (g_json_path == NULL)
    {
        printf("Entry TCP/UDP Capture Fail\n");
        return -1;
    }
	g_log_handle=MESA_create_runtime_log_handle(g_log_path,RLOG_LV_INFO);
	printf("Entry TCP/UDP Capture Success\n");
	
    return 0;
}

void tcp_udp_demo_destroy()
{
	MESA_destroy_runtime_log_handle(g_log_handle);
    printf("http_demo_destroy success");
}
