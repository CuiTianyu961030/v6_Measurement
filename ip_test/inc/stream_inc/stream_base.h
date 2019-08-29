#ifndef _APP_STREAM_BASE_H_
#define _APP_STREAM_BASE_H_ 



#include <sys/types.h>
#include <netinet/in.h>            
#include <netinet/ip.h>            
#include <netinet/ip6.h>   
#include <netinet/tcp.h>   
#include <netinet/udp.h>   
#include <stdlib.h>
#include <string.h>

#ifndef UINT8
typedef unsigned char		UINT8;
#endif
#ifndef UCHAR
typedef unsigned char		UCHAR;
#endif
#ifndef UINT16
typedef unsigned short		UINT16;
#endif

#ifndef UINT32
typedef unsigned int			UINT32;
#endif
#ifndef UINT64
typedef unsigned long long	UINT64;
#endif

//���ķ�����
#define DIR_C2S 			0x01
#define DIR_S2C 			0x02
#define DIR_DOUBLE 		0x03

//�����ķ�����
#define DIR_ROUTE_UP		0x00
#define DIR_ROUTE_DOWN 	0x01

//���������Ͷ���
#define PKT_TYPE_NORMAL  			(0x0)
#define PKT_TYPE_IPREBUILD 			(1<<0) //ip��Ƭ���鱨��
#define PKT_TYPE_TCPUNORDER 		(1<<1)  //TCP������

//��ַ���Ͷ���, ��ͨ������ addr_type_to_string() ת���ַ�����ʽ.
enum addr_type_t{
	__ADDR_TYPE_INIT = 0,
	ADDR_TYPE_IPV4,				/* 1, ����IPv4��ַ����Ԫ����Ϣ */
	ADDR_TYPE_IPV6,				/* 2, ����IPv6��ַ����Ԫ����Ϣ */
	ADDR_TYPE_VLAN,				/* 3 */
	ADDR_TYPE_MAC,				/* 4 */
	ADDR_TYPE_ARP = 5,				/* 5 */
	ADDR_TYPE_GRE,					/* 6 */
	ADDR_TYPE_MPLS,				/* 7 */
	ADDR_TYPE_PPPOE_SES,			/* 8 */
	ADDR_TYPE_TCP,					/* 9 */
	ADDR_TYPE_UDP = 10,			/* 10 */
	ADDR_TYPE_L2TP,				/* 11 */
	__ADDR_TYPE_IP_PAIR_V4,		/* 12, ��IPv4��ַ�� */
	__ADDR_TYPE_IP_PAIR_V6,		/* 13, ��IPv6��ַ�� */
	ADDR_TYPE_PPP,					/* 14 */
	__ADDR_TYPE_MAX,				/* 15 */
};

#define TCP_TAKEOVER_STATE_FLAG_OFF	0
#define TCP_TAKEOVER_STATE_FLAG_ON	1


//Ӧ�ò㿴��������״̬����
#define OP_STATE_PENDING   0
#define OP_STATE_REMOVE_ME 1
#define OP_STATE_CLOSE     2
#define OP_STATE_DATA      3

//Ӧ�ò㷵�ؽ������
#define APP_STATE_GIVEME   0x00
#define APP_STATE_DROPME   0x01
#define APP_STATE_FAWPKT   0x00
#define APP_STATE_DROPPKT  0x10

//�������Ͷ���
enum stream_type_t{
	STREAM_TYPE_NON = 0, /* �����ĸ���, ��VLAN, IP��� */
	STREAM_TYPE_TCP,
	STREAM_TYPE_UDP,
	STREAM_TYPE_VLAN,
	STREAM_TYPE_SOCKS4,
	STREAM_TYPE_SOCKS5,
	STREAM_TYPE_HTTP_PROXY,
	STREAM_TYPE_PPPOE,
};



typedef struct raw_ipfrag_list{
    void *frag_packet;
    int pkt_len;
    int type; /* IPv4 or IPv6 */
    struct raw_ipfrag_list *next;
}raw_ipfrag_list_t;




/* 2014-11-19 lijia modify */
#ifndef STRUCT_TUPLE4_DEFINED
#define STRUCT_TUPLE4_DEFINED (1)
/* ����papp */
struct tuple4 {
  u_int saddr;
  u_int daddr;
  u_short source;
  u_short dest;
};
#endif

struct tuple6
{
	UCHAR saddr[16] ;
	UCHAR daddr[16] ;
	UINT16 source;
	UINT16 dest;
};

/* network-order */
struct stream_tuple4_v4{
	UINT32 saddr;	/* network order */
	UINT32 daddr;	/* network order */
	UINT16 source;	/* network order */
	UINT16 dest;		/* network order */
};


#ifndef IPV6_ADDR_LEN
#define IPV6_ADDR_LEN	(sizeof(struct in6_addr))
#endif

struct stream_tuple4_v6
{
	UCHAR saddr[IPV6_ADDR_LEN] ;
	UCHAR daddr[IPV6_ADDR_LEN] ;
	UINT16 source;	/* network order */
	UINT16 dest;		/* network order */
};



#define GRE_TAG_LEN 		(4)
struct layer_addr_gre
{
	UINT16 gre_id;
};


#define VLAN_ID_MASK		(0x0FFF)
#define VLAN_TAG_LEN 		(4)
struct layer_addr_vlan
{
	UINT16 vlan_id;	/* network order */
};

#define VLAN_ID_LEN 4
struct tuplevlan
{
	UCHAR vlan_id[VLAN_ID_LEN];
};

struct layer_addr_pppoe_session
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ver:4;   
	unsigned int type:4;  
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned int type:4; 
	unsigned int ver:4; 
#endif
  	unsigned char code;
	unsigned short session_id;
};

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN		(6)
#endif

struct layer_addr_mac
{
	UCHAR src_mac[MAC_ADDR_LEN]; /* network order */
	UCHAR dst_mac[MAC_ADDR_LEN]; /* network order */
};

struct layer_addr_ipv4
{
	UINT32 saddr; 	/* network order */
	UINT32 daddr; 	/* network order */
	/* 2014-04-21 lijia add, 
	   Ϊ�˿ռ䡢�����ԡ���Ч��, ��ǿ�ư�Э���δ���,
	   IP��洢��������Ԫ����Ϣ, TCP��ֻ��ָ��ָ��˿��ڴ�, 
	   �����ȡ��Ԫ��ʱ, ������Ҫget_tuple4()����.
	   ����������IP, �˿���ϢΪ0;
	*/
	UINT16 source;	/* network order */
	UINT16 dest;		/* network order */
};

struct layer_addr_ipv6
{
	UCHAR saddr[IPV6_ADDR_LEN] ; /* network order */
	UCHAR daddr[IPV6_ADDR_LEN] ; /* network order */
	/* 2014-04-21 lijia add, 
	   Ϊ�˿ռ䡢�����ԡ���Ч��, ��ǿ�ư�Э���δ���,
	   IP��洢��������Ԫ����Ϣ, TCP��ֻ��ָ��ָ��˿��ڴ�, 
	   �����ȡ��Ԫ��ʱ, ������Ҫget_tuple4()����.
	   ����������IP, �˿���ϢΪ0;
	*/
	UINT16 source;/* network order */
	UINT16 dest;/* network order */
};

struct layer_addr_tcp
{
	UINT16 source; /* network order */
	UINT16 dest;    /* network order */
};

struct layer_addr_udp
{
	UINT16 source; /* network order */
	UINT16 dest;    /* network order */
};

struct layer_addr_l2tp
{
	UINT32 tunnelid; /* network order */
	UINT32 sessionid; /* network order */
};

struct layer_addr_mpls
{
	unsigned int mpls_pkt;
};


struct layer_addr
{
	UCHAR addrtype; // ��ַ����, ��� enum addr_type_t 
	UCHAR addrlen;
	UCHAR  pkttype;	   		//�������� ,�μ��궨��PKT_TYPE_xxx
	UCHAR __pad[5]; //����8�ֽڶ���
	// Ϊ�˷���Ӧ�ò��ȡ��ַ, �˴�ʹ��������, ʡȥָ������ǿ��ת������ 
	union
	{
		struct stream_tuple4_v4 *tuple4_v4;
		struct stream_tuple4_v6 *tuple4_v6;
		struct layer_addr_ipv4	*ipv4;
		struct layer_addr_ipv6	*ipv6;
		struct layer_addr_vlan	*vlan;
		struct layer_addr_mac	*mac;
		struct layer_addr_gre	*gre;
		struct layer_addr_tcp	*tcp;
		struct layer_addr_udp	*udp;
		struct layer_addr_pppoe_session *pppoe_ses;		
		struct layer_addr_l2tp	*l2tp;
		void 					*paddr;
	};

};

// �����˽ṹ���ں�papp����, ����ָ��ʱ, ����struct layer_addrǿת. 
struct ipaddr
{
	UCHAR addrtype; // ��ַ����, ��� enum addr_type_t 
	UCHAR addrlen;
	UCHAR  pkttype;	   		//�������� ,�μ��궨��PKT_TYPE_xxx
	UCHAR __pad[5]; //����8�ֽڶ���
	union
	{
		struct stream_tuple4_v4 *v4;
		struct stream_tuple4_v6 *v6;
		void *paddr;
	};

};

struct tcpdetail
{
	void  *pdata;		      //����
	UINT32 datalen;			  //���ݳ���
	UINT32 lostlen;
	UINT32 serverpktnum;
	UINT32 clientpktnum;
	UINT32 serverbytes;
	UINT32 clientbytes;
	UINT64 createtime; 
	UINT64 lastmtime;
};

struct udpdetail
{
 	void *pdata;		      //����
 	UINT32 datalen;			  //���ݳ���
	UINT32 pad;					  //Ԥ����Ϣ
	UINT32 serverpktnum;
	UINT32 clientpktnum;
	UINT32 serverbytes;
	UINT32 clientbytes;
	UINT64 createtime; 
	UINT64 lastmtime;
};

struct streaminfo
{
	struct layer_addr addr;      //����Э���ַ��Ϣ
	struct streaminfo *pfather;//�ϲ����ṹ��
	UCHAR type;				   			// ��������
	UCHAR threadnum;	        // �����߳�
	UCHAR  dir;           //  ��������������Ч, ���ĵ���˫�������0x01:c-->s; 0x02:s-->c;  0x03 c<-->s;  
	UCHAR  curdir;        // ������Ч, ��ǰ�����ϲ������߼�����, 0x01:c-->s;  0x02:s-->c 
	UCHAR  opstate;				 	//��ǰ��������״̬
	UCHAR  pktstate;				//���ӵİ�����
	UCHAR  routedir;	     // ���������, ������Ч, ���˹�ָ��, �����ڷ���ʱ����Ƿ������������Ƿ���ͬ, ��������
	UCHAR  stream_state;	// ÿ������ǰ���ڵĶ���״̬
	UINT32 hash_index;		// ÿ������hash����	      
	UINT32 stream_index;    // ÿ��stream�ڵ��߳�ȫ�ֵ�����	
	union
	{
		struct tcpdetail *ptcpdetail;
		struct udpdetail *pudpdetail;
		void   *pdetail;		//������ϸ��Ϣ
	};
 };



#ifdef __cplusplus
extern "C" {
#endif

//�ڴ������غ���
void *dictator_malloc(int thread_seq,size_t size);
void dictator_free(int thread_seq,void *pbuf);
void *dictator_realloc(int thread_seq, void* pbuf, size_t size);

//��ȡ��ǰϵͳ���еĲ��������߳�����
int get_thread_count(void);

/* ����ַ����ת���ɿɴ�ӡ���ַ�����ʽ */
const char *addr_type_to_string(enum addr_type_t type);

const char *printaddr (struct layer_addr *paddrinfo,int threadindex);

#ifdef __cplusplus
}
#endif

#endif

