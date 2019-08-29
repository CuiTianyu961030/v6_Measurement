#define ENABLE_DEBUG_PRINT
#define ENABLE_INFO_PRINT

#include <sstream>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <math.h>
#include "ip_demo.h"
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
char g_json_path[256] = "/home/cuitianyu/ip/ip_log";
long iwrite[128]={0},iread=0;
void *g_log_handle;
char g_log_path[256]="/home/cuitianyu/ip/runtime_log";
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

int init_pmeinfo(const streaminfo* a_stream, int thread_seq)
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
		
		//service_pme->jsonwriter->Key("create_time");
		//service_pme->jsonwriter->Uint64(a_stream->ptcpdetail->createtime);
		//service_pme->jsonwriter->Key("last_time");
		//service_pme->jsonwriter->Uint64(a_stream->ptcpdetail->lastmtime);
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
		if(udp_flag == 1 && ntohs(a_stream->addr.ipv4->dest) == 3544)
		{
			service_pme->jsonwriter->Key("teredo");
			service_pme->jsonwriter->String("teredo UDP tunneling");
			udp_flag = 0;
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
					
					
				}
				char sip[MAX_STR_IP_LEN] = {0};
				char dip[MAX_STR_IP_LEN] = {0};
				getip(a_stream->pfather->pfather->addr.tuple4_v4->saddr, sip);
				getip(a_stream->pfather->pfather->addr.tuple4_v4->daddr, dip);
				service_pme->jsonwriter->Key("father_layer_source_IPv4");
				service_pme->jsonwriter->String(sip);
				service_pme->jsonwriter->Key("father_layer_destination_IPv4");
				service_pme->jsonwriter->String(dip);
				
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
			if((strncmp(ipv6_prefix_sip, "2001:0:", 7) == 0 || strncmp(ipv6_prefix_dip, "2001:0:", 7) == 0) && a_stream->type == STREAM_TYPE_UDP &&
			a_stream->pfather->pfather->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4 && tunnel_judge_flag == 0)
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
					
					
				}
				char sip[MAX_STR_IP_LEN] = {0};
				char dip[MAX_STR_IP_LEN] = {0};
				getip(a_stream->pfather->pfather->addr.tuple4_v4->saddr, sip);
				getip(a_stream->pfather->pfather->addr.tuple4_v4->daddr, dip);
				service_pme->jsonwriter->Key("father_layer_source_IPv4");
				service_pme->jsonwriter->String(sip);
				service_pme->jsonwriter->Key("father_layer_destination_IPv4");
				service_pme->jsonwriter->String(dip);
				
				service_pme->jsonwriter->EndObject();
				
				tunnel_judge_flag = 1;
			}
			
			//ISATAP
			char ipv6_prefix_sip1[20], ipv6_prefix_dip1[20];
			char ipv6_prefix_sip2[20], ipv6_prefix_dip2[20];
			strncpy(ipv6_prefix_sip, sip + strlen(sip) - 17, 7);
			strncpy(ipv6_prefix_dip, dip + strlen(dip) - 17, 7);
			strncpy(ipv6_prefix_sip1, sip + strlen(sip) - 16, 7);
			strncpy(ipv6_prefix_dip1, dip + strlen(dip) - 16, 7);
			strncpy(ipv6_prefix_sip2, sip + strlen(sip) - 19, 10);
			strncpy(ipv6_prefix_dip2, dip + strlen(dip) - 19, 10);
			//printf("%s",ipv6_prefix_sip2);
			if(strncmp(ipv6_prefix_sip2, ":200:5efe:", 10) == 0 || strncmp(ipv6_prefix_dip2, ":200:5efe:", 10) == 0 || 
				(strncmp(ipv6_prefix_sip, ":0:5efe:", 8) == 0 || strncmp(ipv6_prefix_dip, ":0:5efe:", 8) == 0 || 
				strncmp(ipv6_prefix_sip1, "::5efe:", 7) == 0 || strncmp(ipv6_prefix_dip1, "::5efe:", 7) == 0) && 
				a_stream->pfather->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4 && tunnel_judge_flag == 0)
			{
				service_pme->jsonwriter->Key("ISATAP");
				service_pme->jsonwriter->StartObject();
				
				if(strncmp(ipv6_prefix_sip, ":0:5efe:", 8) == 0 || strncmp(ipv6_prefix_sip1, "::5efe:", 7) == 0 || strncmp(ipv6_prefix_dip2, ":200:5efe:", 10) == 0)
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
				}
				
				if(strncmp(ipv6_prefix_dip, ":0:5efe:", 8) == 0 || strncmp(ipv6_prefix_dip1, "::5efe:", 7) == 0 || strncmp(ipv6_prefix_dip2, ":200:5efe:", 10) == 0)
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
					
					
				}
				/*
				char sip[MAX_STR_IP_LEN] = {0};
				char dip[MAX_STR_IP_LEN] = {0};
				getip(a_stream->pfather->pfather->addr.tuple4_v4->saddr, sip);
				getip(a_stream->pfather->pfather->addr.tuple4_v4->daddr, dip);
				service_pme->jsonwriter->Key("father_layer_source_IPv4");
				service_pme->jsonwriter->String(sip);
				service_pme->jsonwriter->Key("father_layer_destination_IPv4");
				service_pme->jsonwriter->String(dip);	
				*/
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
	
	//flag2 = 1;
//	}
     //*pme = service_pme;
	service_pme->jsonwriter->EndObject();
    printf("%s\n\n", service_pme->infoBuffer->GetString());
	put_data_in_log_queue((char *)service_pme->infoBuffer->GetString(),strlen(service_pme->infoBuffer->GetString()));
	iwrite[thread_seq]++;
    delete(service_pme->infoBuffer);
    delete(service_pme->jsonwriter);
	
    return 0;
}


char IPv6_ENTRY(const struct streaminfo *pstream, unsigned char routedir, int thread_seq, const void* raw_pkt)
{
	
	
	if (pstream->opstate == OP_STATE_PENDING)
    {
        if (init_pmeinfo(pstream, thread_seq) != 0)
        {
            return APP_STATE_DROPME;
        }
    }
   
    else
    {
        //if (*pme == NULL)
        //{
            return APP_STATE_DROPME;
        //}
    }
    

//service_pmeinfo_t* service_pme = (service_pmeinfo_t*) *pme;
	//service_pme->jsonwriter->Key("protocol");
	//service_pme->jsonwriter->String("tcp");
	/*
    service_pme->jsonwriter->EndObject();
    printf("%s\n\n", service_pme->infoBuffer->GetString());
	put_data_in_log_queue((char *)service_pme->infoBuffer->GetString(),strlen(service_pme->infoBuffer->GetString()));
	iwrite[thread_seq]++;
    delete(service_pme->infoBuffer);
    delete(service_pme->jsonwriter);
	*/
    //free(*pme);
    return APP_STATE_DROPME;
	
	/*
	int protocol;
	struct ip* ipv6_hdr = (struct ip*)this_hdr;
	
	protocol = ipv6_hdr->ip_p;
	
	printf("ipv4_raw_entry:protocol is %d\n", protocol);
	
	return APP_STATE_GIVEME;
	*/
}

int ip_demo_init()
{
    printf("\nEntry ip Capture\n");
	g_log_queue = log_writer_init(g_json_path);
    if (g_json_path == NULL)
    {
        printf("Entry TCP/UDP Capture Fail\n");
        return -1;
    }
	g_log_handle=MESA_create_runtime_log_handle(g_log_path,RLOG_LV_INFO);
	printf("Entry ip Capture Success\n");
	
    return 0;
}

void ip_demo_destroy()
{
	MESA_destroy_runtime_log_handle(g_log_handle);
    printf("ip_demo_destroy success");
}
