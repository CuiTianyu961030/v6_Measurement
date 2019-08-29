#define ENABLE_DEBUG_PRINT
#define ENABLE_INFO_PRINT

#define DEFAULT_BUFFER_LEN 512
#define MAX_BUFFER_LEN 65535
#define DATA_QUEUE_LEN 16000
#define DATA_PATH_LEN 256
#define DATA_FILENAME_LEN DATA_PATH_LEN + 16

#include <stdio.h>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_list_queue.h>
#include <MESA/ssl.h>
#include <MESA/MESA_handle_logger.h>
#include "ssl_capture.h"
#include <math.h>
using namespace std;

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#ifdef ENABLE_PRETTY_PRINT
#define DYNAMIC_WIRTER PrettyWriter<StringBuffer>
#else
#define DYNAMIC_WIRTER Writer<StringBuffer>
#endif

#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "GetFileSHA1.h"
#include "log_writer.h"
//#include "stdafx.h"
using namespace rapidjson;


#define _SSL_V3_VERSION 0x300
#define _TLS_V1DOT0_VERSION 0x301
#define _TLS_V1DOT1_VERSION 0x302
#define _TLS_V1DOT2_VERSION 0x303


#define RESOURCE_NAME "SSL_INFO"
#define MAX_STR_LEN (300)
#define MAX_SINGLE_STR_LEN 255

#define MAX_STR_IP_LEN 64
extern time_t g_CurrentTime;
extern int g_iThreadNum;
MESA_lqueue_head g_log_queue;
MESA_lqueue_head g_cert_queue;
char g_json_path[256]="/home/cuitianyu/ssl/ssl_log";
long iwrite[128]={0},iread=0;
void *g_log_handle;
char g_log_path[256]="/home/cuitianyu/ssl/runtime_log";
//char g_cert_path[256]="/home/cuitianyu/ssl_cert";

typedef struct _service_pmeinfo_t
{
    DYNAMIC_WIRTER *jsonwriter;
    rapidjson::StringBuffer *infoBuffer;
    //char SNI[300];
    //char SCN[512];
    //char ICN[512];
    //char To[80];
    //int flag;
}service_pmeinfo_t;
//*/

void getip(unsigned int addr,char buf[20])
{
    char *ip=NULL;
    in_addr inaddr;
    inaddr.s_addr=addr;
    ip=inet_ntoa(inaddr);
    strcpy(buf,ip);
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

char* getversion(unsigned short ssl_ver)
{
    static char version[5][8]={"sslv3","tls1.0","tls1.1","tls1.2","unknown"};
    int version_index=4;
    switch(ssl_ver)
    {
        case  _SSL_V3_VERSION:
            version_index=0;
            break;
        case _TLS_V1DOT0_VERSION:
            version_index=1;
            break;
        case _TLS_V1DOT1_VERSION:
            version_index=2;
            break;
        case _TLS_V1DOT2_VERSION:
            version_index=3;
            break;
        default:
            version_index=4;
            break;
    }
    return version[version_index];
}

//初始化指针**service_pme
int init_pmeinfo(void **pme,struct streaminfo *a_stream)
{
    service_pmeinfo_t* service_pme=(service_pmeinfo_t *)malloc(sizeof(service_pmeinfo_t));
    if(service_pme==NULL)
    {
        return -1;
    }
    service_pme->infoBuffer = new StringBuffer();
    service_pme->jsonwriter = new DYNAMIC_WIRTER(*service_pme->infoBuffer);
    //service_pme->flag = 0;

    service_pme->jsonwriter->StartObject();

    service_pme->jsonwriter->Key("time");
    service_pme->jsonwriter->Uint64(g_CurrentTime);
    service_pme->jsonwriter->Key("create_time");
    service_pme->jsonwriter->Uint64(a_stream->ptcpdetail->createtime);

    char sip[MAX_STR_IP_LEN]={0};
    char dip[MAX_STR_IP_LEN]={0};
    //getip(a_stream->addr.tuple4_v4->saddr,sip);
    //getip(a_stream->addr.tuple4_v4->daddr,dip);  
	
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
	//printf("2\n");
    service_pme->jsonwriter->Key("sip");
    service_pme->jsonwriter->String(sip);
    service_pme->jsonwriter->Key("dip");
    service_pme->jsonwriter->String(dip);

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
	
	if(a_stream->addr.addrtype == ADDR_TYPE_IPV6 || a_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V6)
		{
			char ipv6_prefix_sip[10], ipv6_prefix_dip[10];
			int tunnel_judge_flag = 0;
			//6to4
			strncpy(ipv6_prefix_sip, sip, 4);
			strncpy(ipv6_prefix_dip, dip, 4);
			if((strncmp(ipv6_prefix_sip, "2002", 4) == 0 || strncmp(ipv6_prefix_dip, "2002", 4) == 0) && 
			a_stream->pfather->pfather->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4 && tunnel_judge_flag == 0)
			{
				service_pme->jsonwriter->Key("6to4");
				service_pme->jsonwriter->StartObject();
				
				if(strncmp(ipv6_prefix_sip, "2002", 4) == 0)
				{
					char gateway_ip[20], ipv6_str_temp[10], buf1[20], buf2[20], buf3[20], buf4[20];
					int ip_temp_dec1, ip_temp_dec2, ip_temp_dec3, ip_temp_dec4;
				
					strncpy(ipv6_str_temp, sip + 5, 2);
					ip_temp_dec1 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec1, buf1);
					strcpy(gateway_ip, buf1);
					strcat(gateway_ip, ".");

					strncpy(ipv6_str_temp, sip + 7, 2);
					ip_temp_dec2 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec2, buf2);
					strcat(gateway_ip, buf2);
					strcat(gateway_ip, ".");
					
					strncpy(ipv6_str_temp, sip + 10, 2);
					ip_temp_dec3 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec3, buf3);
					strcat(gateway_ip, buf3);
					strcat(gateway_ip, ".");
					
					strncpy(ipv6_str_temp, sip + 12, 2);
					ip_temp_dec4 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec4, buf4);	
					strcat(gateway_ip, buf4);
					
					service_pme->jsonwriter->Key("source_6to4_gateway_IPv4");
					service_pme->jsonwriter->String(gateway_ip);
				
					strncpy(ipv6_str_temp, sip + 15, 4);
					if(strncmp(ipv6_str_temp, ":", 1) == 0)
					{
						service_pme->jsonwriter->Key("source_6to4_SLA_ID");
						service_pme->jsonwriter->String("0");
					}
					
					char sip[MAX_STR_IP_LEN] = {0};
					char dip[MAX_STR_IP_LEN] = {0};
					getip(a_stream->pfather->pfather->addr.tuple4_v4->saddr, sip);
					getip(a_stream->pfather->pfather->addr.tuple4_v4->daddr, dip);
					service_pme->jsonwriter->Key("father_layer_source_IPv4");
					service_pme->jsonwriter->String(sip);
					service_pme->jsonwriter->Key("father_layer_destination_IPv4");
					service_pme->jsonwriter->String(dip);
					
				}
				if(strncmp(ipv6_prefix_dip, "2002", 4) == 0)
				{
					char gateway_ip[20], ipv6_str_temp[10], buf1[20], buf2[20], buf3[20], buf4[20];
					int ip_temp_dec1, ip_temp_dec2, ip_temp_dec3, ip_temp_dec4;
					
					strncpy(ipv6_str_temp, dip + 5, 2);
					ip_temp_dec1 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec1, buf1);
					strcpy(gateway_ip, buf1);
					strcat(gateway_ip, ".");

					strncpy(ipv6_str_temp, dip + 7, 2);
					ip_temp_dec2 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec2, buf2);
					strcat(gateway_ip, buf2);
					strcat(gateway_ip, ".");
					
					strncpy(ipv6_str_temp, dip + 10, 2);
					ip_temp_dec3 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec3, buf3);
					strcat(gateway_ip, buf3);
					strcat(gateway_ip, ".");
					
					strncpy(ipv6_str_temp, dip + 12, 2);
					ip_temp_dec4 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec4, buf4);	
					strcat(gateway_ip, buf4);
					
					service_pme->jsonwriter->Key("destination_6to4_gateway_IPv4");
					service_pme->jsonwriter->String(gateway_ip);
					
					strncpy(ipv6_str_temp, dip + 15, 4);
					if(strncmp(ipv6_str_temp, ":", 1) == 0)
					{
						service_pme->jsonwriter->Key("destination_6to4_SLA_ID");
						service_pme->jsonwriter->String("0");
					}
					
					char sip[MAX_STR_IP_LEN] = {0};
					char dip[MAX_STR_IP_LEN] = {0};
					getip(a_stream->pfather->pfather->addr.tuple4_v4->saddr, sip);
					getip(a_stream->pfather->pfather->addr.tuple4_v4->daddr, dip);
					service_pme->jsonwriter->Key("father_layer_source_IPv4");
					service_pme->jsonwriter->String(sip);
					service_pme->jsonwriter->Key("father_layer_destination_IPv4");
					service_pme->jsonwriter->String(dip);
				}
				
				service_pme->jsonwriter->EndObject();
				
				tunnel_judge_flag = 1;
			}		
		
		/*
		strncpy(ipv6_prefix_sip, sip, 7);
		strncpy(ipv6_prefix_dip, dip, 7);
		printf("%s\n", ipv6_prefix_dip);
		if((ipv6_prefix_sip == "2001:0:" || ipv6_prefix_dip == "2001:0:") && a_stream->type == STREAM_TYPE_UDP)
		{
			service_pme->jsonwriter->Key("teredo");
			service_pme->jsonwriter->StartObject();
			if(ipv6_prefix_sip == "2001:0:");
			{
				char server_ip[16], ipv6_str_temp[10];
				int ip_temp_dec;
				
				strncpy(ipv6_str_temp, sip + 7, 2);
				ip_temp_dec = hex_to_dec(ipv6_str_temp);
				//itoa(ip_temp_dec, ipv6_str_temp , 10);
				//server_ip = strcpy((char)(ip_temp_dec));
				server_ip = strcpy((char)(ip_temp_dec));
				server_ip = strcat(":");
				printf("%s\n",server_ip);
				//if(ipv6_str_temp[0] == a)
				
				server_ip = strcpy((char)((int)(ipv6_str_temp[0]) * 16 + (int)(ipv6_str_temp[1])));//abcdef itoa
				server_ip = strcat(":");
				strncpy(ipv6_str_temp, sip + 9, 2);
				server_ip = strcat((char)((int)(ipv6_str_temp[0]) * 16 + (int)(ipv6_str_temp[1])));
				server_ip = strcat(":");
				strncpy(ipv6_str_temp, sip + 12, 2);
				server_ip = strcat((char)((int)(ipv6_str_temp[0]) * 16 + (int)(ipv6_str_temp[1])));
				server_ip = strcat(":");
				strncpy(ipv6_str_temp, sip + 14, 2);
				server_ip = strcat((char)((int)(ipv6_str_temp[0]) * 16 + (int)(ipv6_str_temp[1])));
				service_pme->jsonwriter->Key("source_teredo_server");
				service_pme->jsonwriter->String(server_ip);

				strncpy(ipv6_str_temp, sip + 22, 4);
				
			}
			service_pme->jsonwriter->EndObject();		
			
		}
		*/
		
			//teredo
			strncpy(ipv6_prefix_sip, sip, 7);
			strncpy(ipv6_prefix_dip, dip, 7);
			if((strncmp(ipv6_prefix_sip, "2001:0:", 7) == 0 || strncmp(ipv6_prefix_dip, "2001:0:", 7) == 0) && a_stream->type == STREAM_TYPE_UDP && tunnel_judge_flag == 0)
			{
				service_pme->jsonwriter->Key("teredo");
				service_pme->jsonwriter->StartObject();
				
				if(strncmp(ipv6_prefix_sip, "2001:0:", 7) == 0)
				{
					char server_ip[20], ipv6_str_temp[10], buf1[20], buf2[20], buf3[20], buf4[20];
					int ip_temp_dec1, ip_temp_dec2, ip_temp_dec3, ip_temp_dec4;
					
					strncpy(ipv6_str_temp, sip + 7, 2);
					ip_temp_dec1 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec1, buf1);
					strcpy(server_ip, buf1);
					strcat(server_ip, ".");

					strncpy(ipv6_str_temp, sip + 9, 2);
					ip_temp_dec2 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec2, buf2);
					strcat(server_ip, buf2);
					strcat(server_ip, ".");
					
					strncpy(ipv6_str_temp, sip + 12, 2);
					ip_temp_dec3 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec3, buf3);
					strcat(server_ip, buf3);
					strcat(server_ip, ".");
					
					strncpy(ipv6_str_temp, sip + 14, 2);
					ip_temp_dec4 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec4, buf4);	
					strcat(server_ip, buf4);
					
					service_pme->jsonwriter->Key("source_teredo_server_IPv4");
					service_pme->jsonwriter->String(server_ip);
					
					strncpy(ipv6_str_temp, sip + 22, 4);
					char source_teredo_port_hex[4]; 
					int source_teredo_port_dec;
					char port_buf[20];
					source_teredo_port_hex[0] = 102 - ipv6_str_temp[0];
					source_teredo_port_hex[1] = 102 - ipv6_str_temp[1];
					source_teredo_port_hex[2] = 102 - ipv6_str_temp[2];
					source_teredo_port_hex[3] = 102 - ipv6_str_temp[3];
					source_teredo_port_hex[5] = '\0';
					/*
					sprintf(source_teredo_port_hex[0], "%c", 102 - ipv6_str_temp[0]);//取反
					sprintf(source_teredo_port_hex[1], "%c", 102 - ipv6_str_temp[1]);
					sprintf(source_teredo_port_hex[2], "%c", 102 - ipv6_str_temp[2]);
					sprintf(source_teredo_port_hex[3], "%c", 102 - ipv6_str_temp[3]);
					*/
					source_teredo_port_dec = hex_to_dec(source_teredo_port_hex, 4);
					itoa(source_teredo_port_dec, port_buf);	
					service_pme->jsonwriter->Key("source_teredo_port");
					service_pme->jsonwriter->String(port_buf);
					
					char client_ip[20], buf5[20], buf6[20], buf7[20], buf8[20];
					int ip_temp_dec5, ip_temp_dec6, ip_temp_dec7, ip_temp_dec8;
					
					strncpy(ipv6_str_temp, sip + 27, 2);
					ip_temp_dec5 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec1, buf5);
					strcpy(client_ip, buf5);
					strcat(client_ip, ".");

					strncpy(ipv6_str_temp, sip + 29, 2);
					ip_temp_dec6 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec2, buf6);
					strcat(client_ip, buf6);
					strcat(client_ip, ".");
					
					strncpy(ipv6_str_temp, sip + 32, 2);
					ip_temp_dec7 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec3, buf7);
					strcat(client_ip, buf7);
					strcat(client_ip, ".");
					
					strncpy(ipv6_str_temp, sip + 34, 2);
					ip_temp_dec8 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec4, buf8);	
					strcat(client_ip, buf8);
					service_pme->jsonwriter->Key("source_teredo_client_IPv4");
					service_pme->jsonwriter->String(client_ip);
					
				}
			
				if(strncmp(ipv6_prefix_dip, "2001:0:", 7) == 0)
				{
					char server_ip[20], ipv6_str_temp[10], buf1[20], buf2[20], buf3[20], buf4[20];
					int ip_temp_dec1, ip_temp_dec2, ip_temp_dec3, ip_temp_dec4;
					
					strncpy(ipv6_str_temp, dip + 7, 2);
					ip_temp_dec1 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec1, buf1);
					strcpy(server_ip, buf1);
					strcat(server_ip, ".");

					strncpy(ipv6_str_temp, dip + 9, 2);
					ip_temp_dec2 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec2, buf2);
					strcat(server_ip, buf2);
					strcat(server_ip, ".");
					
					strncpy(ipv6_str_temp, dip + 12, 2);
					ip_temp_dec3 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec3, buf3);
					strcat(server_ip, buf3);
					strcat(server_ip, ".");
					
					strncpy(ipv6_str_temp, dip + 14, 2);
					ip_temp_dec4 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec4, buf4);	
					strcat(server_ip, buf4);
					
					service_pme->jsonwriter->Key("destination_teredo_server_IPv4");
					service_pme->jsonwriter->String(server_ip);
					
					strncpy(ipv6_str_temp, dip + 22, 4);
					char source_teredo_port_hex[4]; 
					int source_teredo_port_dec;
					char port_buf[20];
					source_teredo_port_hex[0] = 102 - ipv6_str_temp[0];
					source_teredo_port_hex[1] = 102 - ipv6_str_temp[1];
					source_teredo_port_hex[2] = 102 - ipv6_str_temp[2];
					source_teredo_port_hex[3] = 102 - ipv6_str_temp[3];
					source_teredo_port_hex[5] = '\0';
					/*
					sprintf(source_teredo_port_hex[0], "%c", 102 - ipv6_str_temp[0]);//取反
					sprintf(source_teredo_port_hex[1], "%c", 102 - ipv6_str_temp[1]);
					sprintf(source_teredo_port_hex[2], "%c", 102 - ipv6_str_temp[2]);
					sprintf(source_teredo_port_hex[3], "%c", 102 - ipv6_str_temp[3]);
					*/
					source_teredo_port_dec = hex_to_dec(source_teredo_port_hex, 4);
					itoa(source_teredo_port_dec, port_buf);	
					service_pme->jsonwriter->Key("destination_teredo_port");
					service_pme->jsonwriter->String(port_buf);
					
					char client_ip[20], buf5[20], buf6[20], buf7[20], buf8[20];
					int ip_temp_dec5, ip_temp_dec6, ip_temp_dec7, ip_temp_dec8;
					
					strncpy(ipv6_str_temp, dip + 27, 2);
					ip_temp_dec5 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec1, buf5);
					strcpy(client_ip, buf5);
					strcat(client_ip, ".");

					strncpy(ipv6_str_temp, dip + 29, 2);
					ip_temp_dec6 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec2, buf6);
					strcat(client_ip, buf6);
					strcat(client_ip, ".");
					
					strncpy(ipv6_str_temp, dip + 32, 2);
					ip_temp_dec7 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec3, buf7);
					strcat(client_ip, buf7);
					strcat(client_ip, ".");
					
					strncpy(ipv6_str_temp, dip + 34, 2);
					ip_temp_dec8 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec4, buf8);	
					strcat(client_ip, buf8);
					service_pme->jsonwriter->Key("destination_teredo_client_IPv4");
					service_pme->jsonwriter->String(client_ip);
					
				
				}
				
				service_pme->jsonwriter->EndObject();
				
				tunnel_judge_flag = 1;
			}
		
			//6over4
			strncpy(ipv6_prefix_sip, sip + strlen(sip) - 11, 7);
			strncpy(ipv6_prefix_dip, dip + strlen(dip) - 11, 7);
			if((strncmp(ipv6_prefix_sip, "::", 2) == 0 || strncmp(ipv6_prefix_dip, "::", 2) == 0) &&  
				a_stream->pfather->pfather->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4 && tunnel_judge_flag == 0)
			{
				service_pme->jsonwriter->Key("6over4");
				service_pme->jsonwriter->StartObject();
				if(strncmp(ipv6_prefix_sip, "::", 2) == 0)
				{
					char gateway_ip[20], ipv6_str_temp[10], buf1[20], buf2[20], buf3[20], buf4[20];
					int ip_temp_dec1, ip_temp_dec2, ip_temp_dec3, ip_temp_dec4;
					
					strncpy(ipv6_str_temp, sip + strlen(sip) - 9, 2);
					ip_temp_dec1 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec1, buf1);
					strcpy(gateway_ip, buf1);
					strcat(gateway_ip, ".");

					strncpy(ipv6_str_temp, sip + strlen(sip) - 7, 2);
					ip_temp_dec2 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec2, buf2);
					strcat(gateway_ip, buf2);
					strcat(gateway_ip, ".");
					
					strncpy(ipv6_str_temp, sip + strlen(sip) - 4, 2);
					ip_temp_dec3 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec3, buf3);
					strcat(gateway_ip, buf3);
					strcat(gateway_ip, ".");
					
					strncpy(ipv6_str_temp, sip + strlen(sip) - 2, 2);
					ip_temp_dec4 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec4, buf4);	
					strcat(gateway_ip, buf4);
					
					service_pme->jsonwriter->Key("source_6over4_gateway_IPv4");
					service_pme->jsonwriter->String(gateway_ip);
					
					char sip[MAX_STR_IP_LEN] = {0};
					char dip[MAX_STR_IP_LEN] = {0};
					getip(a_stream->pfather->pfather->addr.tuple4_v4->saddr, sip);
					getip(a_stream->pfather->pfather->addr.tuple4_v4->daddr, dip);
					service_pme->jsonwriter->Key("father_layer_source_IPv4");
					service_pme->jsonwriter->String(sip);
					service_pme->jsonwriter->Key("father_layer_destination_IPv4");
					service_pme->jsonwriter->String(dip);
				}
				
				if(strncmp(ipv6_prefix_dip, "::", 2) == 0)
				{
					char gateway_ip[20], ipv6_str_temp[10], buf1[20], buf2[20], buf3[20], buf4[20];
					int ip_temp_dec1, ip_temp_dec2, ip_temp_dec3, ip_temp_dec4;
					
					strncpy(ipv6_str_temp, dip + strlen(dip) - 9, 2);
					ip_temp_dec1 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec1, buf1);
					strcpy(gateway_ip, buf1);
					strcat(gateway_ip, ".");

					strncpy(ipv6_str_temp, dip + strlen(dip) - 7, 2);
					ip_temp_dec2 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec2, buf2);
					strcat(gateway_ip, buf2);
					strcat(gateway_ip, ".");
					
					strncpy(ipv6_str_temp, dip + strlen(dip) - 4, 2);
					ip_temp_dec3 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec3, buf3);
					strcat(gateway_ip, buf3);
					strcat(gateway_ip, ".");
					
					strncpy(ipv6_str_temp, dip + strlen(dip) - 2, 2);
					ip_temp_dec4 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec4, buf4);	
					strcat(gateway_ip, buf4);
					
					service_pme->jsonwriter->Key("destination_6over4_gateway_IPv4");
					service_pme->jsonwriter->String(gateway_ip);
					
					char sip[MAX_STR_IP_LEN] = {0};
					char dip[MAX_STR_IP_LEN] = {0};
					getip(a_stream->pfather->pfather->addr.tuple4_v4->saddr, sip);
					getip(a_stream->pfather->pfather->addr.tuple4_v4->daddr, dip);
					service_pme->jsonwriter->Key("father_layer_source_IPv4");
					service_pme->jsonwriter->String(sip);
					service_pme->jsonwriter->Key("father_layer_destination_IPv4");
					service_pme->jsonwriter->String(dip);
				}
				service_pme->jsonwriter->EndObject();
				
				tunnel_judge_flag = 1;
			}
			
			//ISATAP
			char ipv6_prefix_sip1[20], ipv6_prefix_dip1[20];
			strncpy(ipv6_prefix_sip, sip + strlen(sip) - 17, 7);
			strncpy(ipv6_prefix_dip, dip + strlen(dip) - 17, 7);
			strncpy(ipv6_prefix_sip1, sip + strlen(sip) - 16, 7);
			strncpy(ipv6_prefix_dip1, dip + strlen(dip) - 16, 7);
			if((strncmp(ipv6_prefix_sip, ":0:5efe:", 8) == 0 || strncmp(ipv6_prefix_dip, ":0:5efe:", 8) == 0 ||
				strncmp(ipv6_prefix_sip1, "::5efe:", 7) == 0 || strncmp(ipv6_prefix_dip1, "::5efe:", 7) == 0) &&
					a_stream->pfather->pfather->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4 && tunnel_judge_flag == 0)
			{
				service_pme->jsonwriter->Key("ISATAP");
				service_pme->jsonwriter->StartObject();
				if(strncmp(ipv6_prefix_sip, ":0:5efe:", 8) == 0 || strncmp(ipv6_prefix_sip1, "::5efe:", 7) == 0)
				{
					char gateway_ip[20], ipv6_str_temp[10], buf1[20], buf2[20], buf3[20], buf4[20];
					int ip_temp_dec1, ip_temp_dec2, ip_temp_dec3, ip_temp_dec4;
					
					strncpy(ipv6_str_temp, sip + strlen(sip) - 9, 2);
					ip_temp_dec1 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec1, buf1);
					strcpy(gateway_ip, buf1);
					strcat(gateway_ip, ".");

					strncpy(ipv6_str_temp, sip + strlen(sip) - 7, 2);
					ip_temp_dec2 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec2, buf2);
					strcat(gateway_ip, buf2);
					strcat(gateway_ip, ".");
					
					strncpy(ipv6_str_temp, sip + strlen(sip) - 4, 2);
					ip_temp_dec3 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec3, buf3);
					strcat(gateway_ip, buf3);
					strcat(gateway_ip, ".");
					
					strncpy(ipv6_str_temp, sip + strlen(sip) - 2, 2);
					ip_temp_dec4 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec4, buf4);	
					strcat(gateway_ip, buf4);
					
					service_pme->jsonwriter->Key("source_ISATAP_gateway_IPv4");
					service_pme->jsonwriter->String(gateway_ip);
					
					char sip[MAX_STR_IP_LEN] = {0};
					char dip[MAX_STR_IP_LEN] = {0};
					getip(a_stream->pfather->pfather->addr.tuple4_v4->saddr, sip);
					getip(a_stream->pfather->pfather->addr.tuple4_v4->daddr, dip);
					service_pme->jsonwriter->Key("father_layer_source_IPv4");
					service_pme->jsonwriter->String(sip);
					service_pme->jsonwriter->Key("father_layer_destination_IPv4");
					service_pme->jsonwriter->String(dip);	
				}
				
				if(strncmp(ipv6_prefix_dip, ":0:5efe:", 8) == 0 || strncmp(ipv6_prefix_dip1, "::5efe:", 7) == 0)
				{
					char gateway_ip[20], ipv6_str_temp[10], buf1[20], buf2[20], buf3[20], buf4[20];
					int ip_temp_dec1, ip_temp_dec2, ip_temp_dec3, ip_temp_dec4;
					
					strncpy(ipv6_str_temp, dip + strlen(dip) - 9, 2);
					ip_temp_dec1 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec1, buf1);
					strcpy(gateway_ip, buf1);
					strcat(gateway_ip, ".");

					strncpy(ipv6_str_temp, dip + strlen(dip) - 7, 2);
					ip_temp_dec2 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec2, buf2);
					strcat(gateway_ip, buf2);
					strcat(gateway_ip, ".");
					
					strncpy(ipv6_str_temp, dip + strlen(dip) - 4, 2);
					ip_temp_dec3 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec3, buf3);
					strcat(gateway_ip, buf3);
					strcat(gateway_ip, ".");
					
					strncpy(ipv6_str_temp, dip + strlen(dip) - 2, 2);
					ip_temp_dec4 = hex_to_dec(ipv6_str_temp, 2);
					itoa(ip_temp_dec4, buf4);	
					strcat(gateway_ip, buf4);
					
					service_pme->jsonwriter->Key("destination_ISATAP_gateway_IPv4");
					service_pme->jsonwriter->String(gateway_ip);
					
					char sip[MAX_STR_IP_LEN] = {0};
					char dip[MAX_STR_IP_LEN] = {0};
					getip(a_stream->pfather->pfather->addr.tuple4_v4->saddr, sip);
					getip(a_stream->pfather->pfather->addr.tuple4_v4->daddr, dip);
					service_pme->jsonwriter->Key("father_layer_source_IPv4");
					service_pme->jsonwriter->String(sip);
					service_pme->jsonwriter->Key("father_layer_destination_IPv4");
					service_pme->jsonwriter->String(dip);
				}
				service_pme->jsonwriter->EndObject();
				
				tunnel_judge_flag = 1;
			}
			
			//GRE
			if(a_stream->pfather->pfather->addr.addrtype == ADDR_TYPE_GRE && tunnel_judge_flag == 0)
			{
				service_pme->jsonwriter->Key("GRE");
				service_pme->jsonwriter->StartObject();
				
				char sip[MAX_STR_IP_LEN] = {0};
				char dip[MAX_STR_IP_LEN] = {0};
				getip(a_stream->pfather->pfather->pfather->addr.tuple4_v4->saddr, sip);
				getip(a_stream->pfather->pfather->pfather->addr.tuple4_v4->daddr, dip);
				service_pme->jsonwriter->Key("father_layer_source_IPv4");
				service_pme->jsonwriter->String(sip);
				service_pme->jsonwriter->Key("father_layer_destination_IPv4");
				service_pme->jsonwriter->String(dip);
				
				service_pme->jsonwriter->EndObject();
				
				tunnel_judge_flag = 1;
			}
			
			//6in4
			if(a_stream->pfather->pfather->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4 && tunnel_judge_flag == 0)
			{
				service_pme->jsonwriter->Key("6in4");
				service_pme->jsonwriter->StartObject();
				
				char sip[MAX_STR_IP_LEN] = {0};
				char dip[MAX_STR_IP_LEN] = {0};
				getip(a_stream->pfather->pfather->addr.tuple4_v4->saddr, sip);
				getip(a_stream->pfather->pfather->addr.tuple4_v4->daddr, dip);
				service_pme->jsonwriter->Key("father_layer_source_IPv4");
				service_pme->jsonwriter->String(sip);
				service_pme->jsonwriter->Key("father_layer_destination_IPv4");
				service_pme->jsonwriter->String(dip);
				
				service_pme->jsonwriter->EndObject();
			}
		}
	
    *pme=service_pme;

    return 0;
}


void ssl_client_hello( ssl_stream *ssl, void **pme)
{

    st_client_hello_t * client_hello=ssl->stClientHello;
    service_pmeinfo_t* service_pme=(service_pmeinfo_t *)*pme;

    service_pme->jsonwriter->Key("client");
    service_pme->jsonwriter->StartObject();

    service_pme->jsonwriter->Key("record_version");
    service_pme->jsonwriter->String(getversion(ssl->uiSslVersion));

    service_pme->jsonwriter->Key("client_version");
    service_pme->jsonwriter->String(getversion(client_hello->client_ver));

    unsigned int len=0;
    int cut_len=0;
    //static char host[300]={0};
    while(client_hello->server_name[len]!=0 && len<512) len++;//计算主机名长度，协议层中设置SSL主机名长度最大>
    if(len==0)//不存在主机名,只打印版本号
    {
        service_pme->jsonwriter->Key("host_length");
        service_pme->jsonwriter->Uint(0);
        service_pme->jsonwriter->Key("host");
        service_pme->jsonwriter->String("");
    }
    else
    {
        cut_len=(len>MAX_SINGLE_STR_LEN)?(len-MAX_SINGLE_STR_LEN):0;//截断长度,从前截断
        service_pme->jsonwriter->Key("host_length");
        service_pme->jsonwriter->Uint(len-cut_len);

        char host[300]={0};
        sprintf(host,"%s",client_hello->server_name+cut_len);
        //strcpy(service_pme->SNI,host);
        service_pme->jsonwriter->Key("host");
        service_pme->jsonwriter->String(host);
    }

    service_pme->jsonwriter->Key("ciphersuites");
    char cipher[5]={0};

    if(client_hello->ciphersuits.suite_value !=NULL)
    {
        service_pme->jsonwriter->StartArray();
        for(int i=0;i<client_hello->ciphersuits.suite_len;i+=2)
        {
            sprintf(cipher,"%02x%02x",client_hello->ciphersuits.suite_value[i+0],client_hello->ciphersuits.suite_value[i+1]);
            service_pme->jsonwriter->String(cipher);
        }

        service_pme->jsonwriter->EndArray();
    }
    else 
        service_pme->jsonwriter->String("");

    service_pme->jsonwriter->Key("sessionID");
    if(client_hello->session.session_len==0 || client_hello->session.session_value==NULL )
    {
        service_pme->jsonwriter->String("");
    }
    else
    {
        char session[65]={0};
        int sum=0;
        for(int i=0;i<client_hello->session.session_len;i++)
        {
            sum+=sprintf(session+sum,"%02x",client_hello->session.session_value[i]);
        }
        service_pme->jsonwriter->String(session);
    }

    char method[3]={0};
    service_pme->jsonwriter->Key("com_method");
    if(client_hello->com_method.methlen>1 && client_hello->com_method.methods!=NULL)
    {
        service_pme->jsonwriter->StartArray();
        for(int i=0;i<client_hello->com_method.methlen;i++)
        {
            sprintf(method,"%02d",client_hello->com_method.methods[i]);
            service_pme->jsonwriter->String(method);
        }
        service_pme->jsonwriter->EndArray();
    }
    else if (client_hello->com_method.methlen==1) 
        service_pme->jsonwriter->String("00");
    else 
        service_pme->jsonwriter->String("");

    service_pme->jsonwriter->Key("extension");
    service_pme->jsonwriter->StartObject();

    service_pme->jsonwriter->Key("length");
    service_pme->jsonwriter->Uint(client_hello->extlen);
    service_pme->jsonwriter->Key("num");
    service_pme->jsonwriter->Uint(client_hello->ext_num);
    service_pme->jsonwriter->Key("type");
    
    if(client_hello->ext_num==0) service_pme->jsonwriter->String("");
    else
    {
        service_pme->jsonwriter->StartArray();
        char ext[5]={0};
        for(int i=0;i<client_hello->ext_num;i++)
        {
            sprintf(ext,"%04x",client_hello->exts[i].type);
            service_pme->jsonwriter->String(ext);
        }
        service_pme->jsonwriter->EndArray();
    }
    service_pme->jsonwriter->EndObject();

    service_pme->jsonwriter->EndObject();
    //return host;
}


void  ssl_server_hello(ssl_stream *ssl,streaminfo *a_stream,void **pme)
{
    st_server_hello_t * server_hello=ssl->stServerHello;
    service_pmeinfo_t* service_pme=(service_pmeinfo_t *)*pme;

    service_pme->jsonwriter->Key("server");
    service_pme->jsonwriter->StartObject();

    unsigned short ver=(unsigned char)( ((char *)a_stream->ptcpdetail->pdata)[1])*256+(unsigned char)(((char *)a_stream->ptcpdetail->pdata)[2]);
    service_pme->jsonwriter->Key("record_version");
    service_pme->jsonwriter->String(getversion(ver));
    service_pme->jsonwriter->Key("client_version");
    service_pme->jsonwriter->String(getversion(server_hello->client_ver));

    char cipher[5]={0};
    sprintf(cipher,"%02x%02x",server_hello->ciphersuits.suite_value[0],server_hello->ciphersuits.suite_value[1]);
    service_pme->jsonwriter->Key("ciphersuites");
    service_pme->jsonwriter->String(cipher);
    //printf("\n%s\n", service_pme->infoBuffer->GetString());

    service_pme->jsonwriter->Key("sessionID");
    if(server_hello->session.session_len==0 || server_hello->session.session_value==NULL)
    {
        service_pme->jsonwriter->String("");
    }
    else
    {
        char session[65]={0};
        int sum=0;
        for(int i=0;i<server_hello->session.session_len;i++)
        {
            sum+=sprintf(session+sum,"%02x",server_hello->session.session_value[i]);                   
        }
        service_pme->jsonwriter->String(session);
    }

    char method[3]={0};
    service_pme->jsonwriter->Key("com_method");
    if(server_hello->com_method.methlen>1 && server_hello->com_method.methods!=NULL)
    {
        service_pme->jsonwriter->StartArray();
        for(int i=0;i<server_hello->com_method.methlen;i++)
        {
            sprintf(method,"%02d",server_hello->com_method.methods[i]);
            service_pme->jsonwriter->String(method);
        }
        service_pme->jsonwriter->EndArray();
    }
    else if (server_hello->com_method.methlen==1) service_pme->jsonwriter->String("00");
    else service_pme->jsonwriter->String("");

    service_pme->jsonwriter->EndObject();
    //printf("\n%s\n", service_pme->infoBuffer->GetString());
}


void ssl_certificate_detail(ssl_stream *ssl, void **pme,char cert_info[])
{
    st_cert_t * certificate=ssl->stSSLCert;
    service_pmeinfo_t* service_pme=(service_pmeinfo_t *)*pme;
    //service_pme->flag=1;
    service_pme->jsonwriter->Key("cert_detail");
    service_pme->jsonwriter->StartObject();

    service_pme->jsonwriter->Key("totallen");
    service_pme->jsonwriter->Uint(certificate->totallen);

    service_pme->jsonwriter->Key("cert");
    service_pme->jsonwriter->StartObject();

    service_pme->jsonwriter->Key("cert_info");
    service_pme->jsonwriter->String(cert_info);
    service_pme->jsonwriter->Key("certlen");
    service_pme->jsonwriter->Uint(certificate->certlen);
    service_pme->jsonwriter->Key("version");
    service_pme->jsonwriter->String(certificate->SSLVersion);
    service_pme->jsonwriter->Key("SerialNum");
    service_pme->jsonwriter->String(certificate->SSLSerialNum);
    service_pme->jsonwriter->Key("AlgID");
    service_pme->jsonwriter->String(certificate->SSLAgID);
    service_pme->jsonwriter->Key("Issuer");
    service_pme->jsonwriter->String(certificate->SSLIssuer);
    service_pme->jsonwriter->Key("Subject");
    service_pme->jsonwriter->String(certificate->SSLSub);
    service_pme->jsonwriter->Key("From");
    service_pme->jsonwriter->String(certificate->SSLFrom);
    service_pme->jsonwriter->Key("To");
    service_pme->jsonwriter->String(certificate->SSLTo);

    service_pme->jsonwriter->EndObject();

    service_pme->jsonwriter->EndObject();

    //strcpy(service_pme->SCN,certificate->SSLSub);
    //strcpy(service_pme->ICN,certificate->SSLIssuer);
    //strcpy(service_pme->To,certificate->SSLTo);
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
/*
int put_data_in_cert_queue( char *content, int len, char filename[])
{
    if(len<=0)
    {   
        return 0;
    }   
    cert_queue_buffer data;

    char *buf=(char *)calloc(len+1,sizeof(char));
    if(buf==NULL)
    {
        return 0;
    }
    memcpy(buf,content,len);

    data.pdata = buf;
    data.len=len;
    strcpy(data.file_name,filename);

    int succ = MESA_lqueue_join_tail(g_cert_queue, &data, sizeof(data));
    
    if (MESA_QUEUE_RET_OK != succ)
    {
        printf("MESA_lqueue_try_join_tail Failed FLAG:%d May lost data sorry!\n", succ);
        return 0;
    }
    
    return 1;
}
*/

/*void ssl_certificate(ssl_stream *ssl,stSessionInfo* session_info,void **pme)
{
    char filename[255]={0}; 
    char *p=(char *)session_info->buf;
    int cer_len=(((unsigned char)p[0])<< 16) + (((unsigned char)p[1])<<8)+(unsigned char)p[2];
    int totallen=ssl->stSSLCert->totallen;
    char sha1[256]={0};//"1213ljdaslkhdsa";
    //printf("\n%d\t%d\t%d\n%d",p[0],p[1],(unsigned char)p[2],cer_len);
    p=p+3;
    GetFileSHA1(p,cer_len,sha1);

    sprintf(filename,"%s_%d_%d",sha1,totallen,cer_len);

    service_pmeinfo_t* service_pme=(service_pmeinfo_t *)*pme;
    service_pme->jsonwriter->Key("cert_info");
    service_pme->jsonwriter->String(filename);

    //put_data_in_cert_queue(p,cer_len,filename);
}*/

char SSL_CAPTURE_ENTRY(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,void *a_packet)
{
    char cert_info[255]={0};
    //   printf("\n%d\n",session_info->session_state);
    //printf("\n开始处理流信息：%d\n",thread_seq);
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

    ssl_stream *ssl=(ssl_stream *)session_info->app_info;

    if(ssl==NULL||ssl->stClientHello ==NULL)//获取应用层信息失败
    {
		printf("\n1\n1");
        return PROT_STATE_DROPME;
    }

    switch(session_info->prot_flag)
    {
        case SSL_CLIENT_HELLO:
            {
                ssl_client_hello(ssl,pme);
                break;
            }

        case SSL_SERVER_HELLO:
            {
                ssl_server_hello(ssl,a_stream,pme);
                break;
            }
        case SSL_CERTIFICATE:
            {
		        //ssl_certificate(ssl,session_info,pme);
                break;
            }
        case SSL_CERTIFICATE_DETAIL:
            {
                ssl_certificate_detail(ssl,pme,cert_info);
                break;
            }
        default:
            {
                break;
            }
    }
    if(!(session_info->session_state&SESSION_STATE_CLOSE))//会话未结束
    {
        return PROT_STATE_GIVEME;
    }

    service_pmeinfo_t *service_pme=(service_pmeinfo_t *)*pme;
    /*//printf("\n流信息处理完毕，打印：%d\n",thread_seq);
    //printf("\n%s\n",SNI);
    //printf("\n%s\n",SCN);
    //printf("\n%s\n",ICN);
    //printf("\n%s\n",To);
    //进行证书的验证，分别是：验证SNI域和证书持有者是否一致；
    //				验证证书是否过期；
    //				验证证书是否自颁发。
    if (service_pme->flag == 1)
    {
        cert_owner_validation(service_pme->SNI, service_pme->SCN, pme);
        cert_time_validation(service_pme->To, pme);
        self_signed_exam(service_pme->SCN, service_pme->ICN, pme);
    }
    else //cout<<"该握手过程无证书验证"<<endl<<endl;
    {
        service_pme->jsonwriter->Key("cert_match_info");
        service_pme->jsonwriter->String("该握手过程无证书验证");
        service_pme->jsonwriter->Key("cert_time_validation");
        service_pme->jsonwriter->String(""); 
	    service_pme->jsonwriter->Key("cert_signed_exam");
        service_pme->jsonwriter->String("");     
    }*/
    service_pme->jsonwriter->EndObject();
    printf("%s\n\n", service_pme->infoBuffer->GetString());
    put_data_in_log_queue((char *)service_pme->infoBuffer->GetString(),strlen(service_pme->infoBuffer->GetString()));
    iwrite[thread_seq]++;
    delete(service_pme->infoBuffer);
    delete(service_pme->jsonwriter);
    free(*pme);
    *pme = NULL;
    //memset(SNI,'\0',sizeof(SNI));
    //memset(SCN,'\0',sizeof(SCN));
    //memset(ICN,'\0',sizeof(ICN));
    //memset(To,'\0',sizeof(To));
    //flag = 0;
    
    return PROT_STATE_DROPME;
}
int SSL_CAPTURE_INTI()
{

    printf("\nEntry SSL Capture\n");

    g_log_queue = log_writer_init(g_json_path);
    //g_cert_queue = cert_writer_init(g_cert_path);
    if(g_json_path ==NULL)
    {   
        printf("Entry SSL Capture Fail\n");
        return -1; 
    }   
    printf("Entry SSL Capture Success\n");

    g_log_handle=MESA_create_runtime_log_handle(g_log_path,RLOG_LV_INFO);
    if(g_log_handle==NULL)
    {
        printf("create log handle fail");
        return -1;

    }
    return 0;
}

void  SSL_CAPTURE_DESTROY()
{
    MESA_destroy_runtime_log_handle(g_log_handle);
    printf("ssl_demo_destroy success");
}

