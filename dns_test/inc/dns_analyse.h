#ifndef DNS_ANALYSE_H
#define DNS_ANALYSE_H

#ifndef u_char
#define u_char unsigned char
#endif
#ifndef u_int16_t
#define u_int16_t unsigned short
#endif
#ifndef u_int32_t
#define u_int32_t unsigned int  //adjust by lqy 20070521 long to int
#endif

#define DNS_MAX_UDP_MESSAGE	 512
#define DNS_MAX_NAME		255
#define MAX_IP_NUM 			128
#define MAX_CNAME_NUM		32
#define IPV6_LEN				16

//Build cheat packet
#define DNS_PKT_PARA_QUERY	    0//MUST
#define DNS_PKT_PARA_CNAME	    1//MUST
#define	 DNS_PKT_PARA_A_IP	    2//MUST
#define	 DNS_PKT_PARA_AUTH	    3//OPTION
#define	 DNS_PKT_PARA_ADDI	    4//OPTION


typedef struct {
	u_int16_t qdcount;
	u_int16_t ancount;
	u_int16_t aucount;//authority count
	u_int16_t adcount;//additional count
}dns_pkt_opt_cnt;

typedef struct dns_pkt_opt_unit_t{
	unsigned int opt_len;    /* 本选项opt_value字节长度*/
	unsigned char opt_type;  /* 本选项的类型 */
	char *opt_value; /* 本选项的内容 */
}dns_pkt_opt_unit;

//
typedef struct dns_pkt_type_a_t{
	unsigned int ip;
	unsigned int name_len;
	char *server_name;
}dns_pkt_type_a;

typedef struct dns_pkt_type_aaaa_t{
	unsigned char ip[16];//must be network order
	unsigned int  name_len;
	char *server_name;
}dns_pkt_type_aaaa;

typedef struct dns_pkt_type_cname_t{
	unsigned int query_name_len;
	unsigned int server_name_len;
	char *query_name;//TODO:删除？
	char *server_name;
}dns_pkt_type_cname;

typedef struct dns_pkt_type_ns_t{
	unsigned int query_name_len;
	unsigned int name_server_len;
	char *query_name;
	char *name_server;
}dns_pkt_type_ns;
//Build cheat packet end

typedef struct{
	u_int16_t id;//header id //addby liujunpeng 20141013
	u_int16_t qtype;
	u_int16_t qclass;
	u_char qname[DNS_MAX_NAME + 1];
} dns_question_t;

typedef struct
{
	u_char type;								//0-query, 1-response
	dns_question_t question;		            //query structure
	int ipv4_num;								//number of ipv4s in response
	int ipv6_num;								//number of ipv6s in response
	int cname_num;								//number of cnames in response
	unsigned int ipv4[MAX_IP_NUM];				//list of ips in response for ipv4 (network order)
	unsigned char ipv6[MAX_IP_NUM][IPV6_LEN];	//list of ips in response for ipv6 (network order)
	u_char cname[MAX_CNAME_NUM][DNS_MAX_NAME];	//list of cnames in response
} dns_response_t;

#ifdef __cplusplus
extern "C"
{
#endif

/*
* name:build_dns_payload
* functionality:build dns packet
* param:
*       pay_load_buf:the thread num
*       len:buffer length
*       pkt_para:option parameter
*       opt_cnt:option counts
*
*  returns:
*        >0:build sucess
*       -1:ibuild failed
*
* */
int build_dns_payload(unsigned char *pay_load_buf,int len,dns_pkt_opt_unit* pkt_para,dns_pkt_opt_cnt *opt_cnt);


int read_opt_uint(dns_pkt_opt_unit* opt_array,int opt_cnt,int opt_type);

#ifdef __cplusplus
}
#endif
#endif

