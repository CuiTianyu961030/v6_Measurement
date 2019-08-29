#define ENABLE_DEBUG_PRINT
#define ENABLE_INFO_PRINT

#define DEFAULT_BUFFER_LEN 512
#define MAX_BUFFER_LEN 65535
#define DATA_QUEUE_LEN 16000
#define DATA_PATH_LEN 256
#define DATA_FILENAME_LEN DATA_PATH_LEN + 16

#include <sstream>
#include <string>
#include <iostream>
#include <stdlib.h>
#include <math.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_list_queue.h>
#include <MESA/MESA_handle_logger.h>
#include "dns_demo.h"
#include "log_writer.h"

#ifdef ENABLE_PRETTY_PRINT
#define DYNAMIC_WRITER PrettyWriter<StringBuffer>
#else
#define DYNAMIC_WRITER Writer<StringBuffer>
#endif

#define MAX_STR_IP_LEN 64

int count = 0;
extern time_t g_CurrentTime;
MESA_lqueue_head g_log_queue;
char g_json_path[256] = "/home/cuitianyu/dns/dns_log";
long iwrite[128]={0},iread=0;
void *g_log_handle;
char g_log_path[256]="/home/cuitianyu/dns/runtime_log";

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

int init_pmeinfo(dns_response_t* dns_inf, void** pme, streaminfo* a_stream)
{
    service_pmeinfo_t* service_pme = (service_pmeinfo_t*)malloc(sizeof(service_pmeinfo_t));
    if (service_pme == NULL)
    {
        return -1;
    }
    service_pme->infoBuffer = new StringBuffer();
    service_pme->jsonwriter = new DYNAMIC_WRITER(*service_pme->infoBuffer);
	
	//if(a_stream->addr.tuple4_v4->saddr != NULL)
		//printf("%s\n", a_stream->addr.tuple4_v4->saddr);	
	/*
	char sip2[50] = {0};
	getip6(a_stream->addr.tuple4_v6->daddr, sip2);
	printf("%s\n", sip2);
	*/
    service_pme->jsonwriter->StartObject();

    service_pme->jsonwriter->Key("time");
    service_pme->jsonwriter->Uint64(g_CurrentTime);
    service_pme->jsonwriter->Key("create_time");
    service_pme->jsonwriter->Uint64(a_stream->ptcpdetail->createtime);
    service_pme->jsonwriter->Key("last_time");
    service_pme->jsonwriter->Uint64(a_stream->ptcpdetail->lastmtime);

    char sip[MAX_STR_IP_LEN] = {0};
    char dip[MAX_STR_IP_LEN] = {0};
	//printf("%d",a_stream->addr.addrtype);

		if(a_stream->addr.addrtype == ADDR_TYPE_IPV4 || a_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4)
		{
			//printf("1\n");
			getip(a_stream->addr.ipv4->saddr, sip);
			getip(a_stream->addr.ipv4->daddr, dip);
			//count = count +1;
		}
		else if(a_stream->addr.addrtype == ADDR_TYPE_IPV6 || a_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V6 )
		{
			//printf("2\n");
			getip6(a_stream->addr.ipv6->saddr, sip);
			getip6(a_stream->addr.ipv6->daddr, dip);
			//count = count +1;
		}


	
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
	else if(a_stream->addr.addrtype == ADDR_TYPE_IPV6 || a_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V6 )
	{
		service_pme->jsonwriter->Key("sport");
		service_pme->jsonwriter->Uint(ntohs(a_stream->addr.ipv6->source));
		service_pme->jsonwriter->Key("dport");
		service_pme->jsonwriter->Uint(ntohs(a_stream->addr.ipv6->dest));
	}

    service_pme->jsonwriter->Key("info_type");
    service_pme->jsonwriter->Uint64(a_stream->type);
    
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
	
    *pme = service_pme;

    return 0;
}

void dns_query(dns_response_t* dns_inf, streaminfo* a_stream, void** pme)
{
    dns_question_t dns_question = dns_inf->question;
    service_pmeinfo_t* service_pme = (service_pmeinfo_t*)*pme;

    service_pme->jsonwriter->Key("query");
    service_pme->jsonwriter->StartObject();

    service_pme->jsonwriter->Key("transaction_id");
    service_pme->jsonwriter->Uint(dns_question.id);
    
    service_pme->jsonwriter->Key("Flags");    
    service_pme->jsonwriter->StartObject();

    service_pme->jsonwriter->Key("dns_type");
    service_pme->jsonwriter->String("query");

    service_pme->jsonwriter->Key("opcode");
    unsigned short opcode = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[2])&120;
    service_pme->jsonwriter->Uint(opcode);

    service_pme->jsonwriter->Key("truncated");
    unsigned short tc = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[2])&2;
    service_pme->jsonwriter->Uint(tc);

    service_pme->jsonwriter->Key("recursion_desired");
    unsigned short rd = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[2])&1;
    service_pme->jsonwriter->Uint(rd);

    service_pme->jsonwriter->Key("recursion_accept"); 
    unsigned short ra = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[3])&128;
    service_pme->jsonwriter->Uint(ra);

    service_pme->jsonwriter->Key("rcode");
    unsigned short rcode = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[3])&15;
    service_pme->jsonwriter->Uint(rcode);

    service_pme->jsonwriter->EndObject();

    service_pme->jsonwriter->Key("question_num");
    unsigned short question_num = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[4])*256 + (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[5]); 
    service_pme->jsonwriter->Uint(question_num);

    service_pme->jsonwriter->Key("answer_rr");
    unsigned short answer_rr  = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[6])*256 + (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[7]);
    service_pme->jsonwriter->Uint(answer_rr); 

    service_pme->jsonwriter->Key("authority_rr");
    unsigned short authority_rr  = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[8])*256 + (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[9]);
    service_pme->jsonwriter->Uint(authority_rr);

    service_pme->jsonwriter->Key("additional_rr");
    unsigned short additional_rr  = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[10])*256 + (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[11]);
    service_pme->jsonwriter->Uint(additional_rr);

    service_pme->jsonwriter->Key("queries");
    service_pme->jsonwriter->StartObject();

    service_pme->jsonwriter->Key("name");
    service_pme->jsonwriter->String(reinterpret_cast<const char*>(dns_question.qname));
    service_pme->jsonwriter->Key("type");
    service_pme->jsonwriter->Uint(dns_question.qtype);
    service_pme->jsonwriter->Key("class");
    service_pme->jsonwriter->Uint(dns_question.qclass);

    service_pme->jsonwriter->EndObject();
    service_pme->jsonwriter->EndObject();
}
void dns_answer(dns_response_t* dns_inf, streaminfo* a_stream, void** pme)
{
    dns_question_t dns_question = dns_inf->question;
    service_pmeinfo_t* service_pme = (service_pmeinfo_t*)*pme;
    service_pme->jsonwriter->Key("response");
    service_pme->jsonwriter->StartObject();
    
    service_pme->jsonwriter->Key("transaction_id");
    service_pme->jsonwriter->Uint(dns_question.id);
    
    service_pme->jsonwriter->Key("Flags");
    service_pme->jsonwriter->StartObject();

    service_pme->jsonwriter->Key("dns_type");
    service_pme->jsonwriter->String("response");

    service_pme->jsonwriter->Key("opcode");
    unsigned short opcode = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[2])&120;
    service_pme->jsonwriter->Uint(opcode);

    service_pme->jsonwriter->Key("truncated");
    unsigned short tc = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[2])&2;
    service_pme->jsonwriter->Uint(tc);

    service_pme->jsonwriter->Key("recursion_desired");
    unsigned short rd = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[2])&1;
    service_pme->jsonwriter->Uint(rd);

    service_pme->jsonwriter->Key("recursion_accept"); 
    unsigned short ra = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[3]) >> 7;
    service_pme->jsonwriter->Uint(ra);

    service_pme->jsonwriter->Key("rcode");
    unsigned short rcode = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[3])&15;
    service_pme->jsonwriter->Uint(rcode);

    service_pme->jsonwriter->EndObject();

    service_pme->jsonwriter->Key("question_num");
    unsigned short question_num = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[4])*256 + (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[5]); 
    service_pme->jsonwriter->Uint(question_num);

    service_pme->jsonwriter->Key("answer_rr");
    unsigned short answer_rr  = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[6])*256 + (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[7]);
    service_pme->jsonwriter->Uint(answer_rr); 

    service_pme->jsonwriter->Key("authority_rr");
    unsigned short authority_rr  = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[8])*256 + (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[9]);
    service_pme->jsonwriter->Uint(authority_rr);
    
    service_pme->jsonwriter->Key("additional_rr");
    unsigned short additional_rr  = (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[10])*256 + (unsigned char)(((char*)a_stream->ptcpdetail->pdata)[11]);
    service_pme->jsonwriter->Uint(additional_rr);

    service_pme->jsonwriter->Key("queries");
    service_pme->jsonwriter->StartObject();

    service_pme->jsonwriter->Key("name");
    service_pme->jsonwriter->String(reinterpret_cast<const char*>(dns_question.qname));
    service_pme->jsonwriter->Key("type");
    service_pme->jsonwriter->Uint(dns_question.qtype);
    service_pme->jsonwriter->Key("class");
    service_pme->jsonwriter->Uint(dns_question.qclass);

    service_pme->jsonwriter->EndObject();

    service_pme->jsonwriter->Key("answers");
    service_pme->jsonwriter->StartObject();
    
    service_pme->jsonwriter->Key("ipv4");
    service_pme->jsonwriter->StartArray();
    
    int ip4_num = dns_inf->ipv4_num;
    while (ip4_num > 0)
    {
        long int ip4 = ntohl(dns_inf->ipv4[ip4_num-1]);
        std::stringstream ss;
        std::string i1,i2,i3,i4;
        ss << (ip4 >> 24);
        i1 = ss.str();
        ss.str("");
        ss << ((ip4 & 0x00ffffff) >> 16);
        i2 = ss.str();
        ss.str("");
        ss << ((ip4 & 0x0000ffff) >> 8);
        i3 = ss.str();
        ss.str("");
        ss << (ip4 & 0x000000ff);
        i4 = ss.str();
       
        std::string ip = i1 + "." + i2 + "." + i3 + "." + i4;
        service_pme->jsonwriter->String(ip.c_str());
        ip4_num--;
    }
    service_pme->jsonwriter->EndArray();

    service_pme->jsonwriter->Key("ipv6");
    service_pme->jsonwriter->StartArray();

    int ip6_num = dns_inf->ipv6_num;
	int total_num = ip6_num;
    while (ip6_num > 0)
    {
		char sip[IPV6_LEN]  = {0};
		int len;
		getip6(dns_inf->ipv6[ip6_num-1], sip);
        //printf("%s\n",sip);
		//printf("strlen :%d\n",strlen(sip));
		len = strlen(sip);
		//printf("%d\n", len);
		char ipv6[len+1];
		//memset(ipv6, "\0", len);
		strncpy(ipv6, sip, len);
		ipv6[len] = '\0';
		//printf("%s\n", ipv6);
        std::string ip;
		/*
        for (int ipv6_len = 16; ipv6_len > 1; ipv6_len--)
        {
            ip += dns_inf->ipv6[ip6_num-1][ipv6_len-1] + ":";
        }
        ip += dns_inf->ipv6[ip6_num-1][0];
        ip += dns_inf->ipv6[ip6_num-1][0];
		*/
		char *ipv6_p;
		ipv6_p = (char *)malloc(sizeof(char) * len+1);		
		memset(ipv6_p, '\0', len+1);
		strncpy(ipv6_p, ipv6, len);
		//printf("%s",ipv6_p);
        //service_pme->jsonwriter->String(ip.c_str());
		service_pme->jsonwriter->String(ipv6);
        ip6_num--;
    }
    service_pme->jsonwriter->EndArray();

    service_pme->jsonwriter->Key("cname");
    service_pme->jsonwriter->StartArray();

    int cname_num = dns_inf->cname_num;
    while(cname_num > 0)
    {
        service_pme->jsonwriter->String(reinterpret_cast<const char*>(dns_inf->cname[cname_num-1]));
        cname_num--;
    }
    service_pme->jsonwriter->EndArray();

    service_pme->jsonwriter->EndObject();
    service_pme->jsonwriter->EndObject();
        
}
char dns_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
    if(session_info == NULL)
    {
        return PROT_STATE_DROPME;
    }
	/*
    if (session_info->session_state& SESSION_STATE_PENDING)
    {
        if (init_pmeinfo(pme, a_stream) != 0)
        {
            return PROT_STATE_DROPME;
        }
    }
    else
    {
        if (*pme == NULL)
        {
            return PROT_STATE_DROPME;
        }
    }
	*/
    dns_response_t *dns_inf = (dns_response_t*)(session_info->app_info);
    
    if (dns_inf == NULL)
    {
		printf("1\n");
        return PROT_STATE_DROPME;
    }

    if(dns_inf->type == 0)
    {
		init_pmeinfo(dns_inf, pme, a_stream);
        dns_query(dns_inf, a_stream, pme);
    }
    else
    {
		init_pmeinfo(dns_inf, pme, a_stream);
        dns_answer(dns_inf, a_stream, pme);
    }

    if (!session_info->session_state&SESSION_STATE_CLOSE)
    {
        return PROT_STATE_GIVEME;
    }
    
    service_pmeinfo_t* service_pme = (service_pmeinfo_t*) *pme;
    service_pme->jsonwriter->EndObject();
    printf("%s\n\n", service_pme->infoBuffer->GetString());
	put_data_in_log_queue((char *)service_pme->infoBuffer->GetString(),strlen(service_pme->infoBuffer->GetString()));
	iwrite[thread_seq]++;
	//printf("%d",count);
    delete(service_pme->infoBuffer);
    delete(service_pme->jsonwriter);
    free(*pme);
    return PROT_STATE_DROPME;
}



int dns_demo_init()
{
    printf("\nEntry DNS Capture\n");
	g_log_queue = log_writer_init(g_json_path);
    if (g_json_path == NULL)
    {
        printf("Entry DNS Capture Fail\n");
        return -1;
    }
	g_log_handle=MESA_create_runtime_log_handle(g_log_path,RLOG_LV_INFO);
    printf("Entry DNS Capture Success\n");

    return 0;
}

void dns_demo_destroy()
{
	MESA_destroy_runtime_log_handle(g_log_handle);
    printf("dns_demo_destroy success");
}