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

//流的方向定义
#define DIR_C2S 			0x01
#define DIR_S2C 			0x02
#define DIR_DOUBLE 		0x03

//单包的方向定义
#define DIR_ROUTE_UP		0x00
#define DIR_ROUTE_DOWN 	0x01

//单包的类型定义
#define PKT_TYPE_NORMAL  			(0x0)
#define PKT_TYPE_IPREBUILD 			(1<<0) //ip碎片重组报文
#define PKT_TYPE_TCPUNORDER 		(1<<1)  //TCP乱序报文

//地址类型定义, 可通过函数 addr_type_to_string() 转成字符串形式.
enum addr_type_t{
	__ADDR_TYPE_INIT = 0,
	ADDR_TYPE_IPV4,				/* 1, 基于IPv4地址的四元组信息 */
	ADDR_TYPE_IPV6,				/* 2, 基于IPv6地址的四元组信息 */
	ADDR_TYPE_VLAN,				/* 3 */
	ADDR_TYPE_MAC,				/* 4 */
	ADDR_TYPE_ARP = 5,				/* 5 */
	ADDR_TYPE_GRE,					/* 6 */
	ADDR_TYPE_MPLS,				/* 7 */
	ADDR_TYPE_PPPOE_SES,			/* 8 */
	ADDR_TYPE_TCP,					/* 9 */
	ADDR_TYPE_UDP = 10,			/* 10 */
	ADDR_TYPE_L2TP,				/* 11 */
	__ADDR_TYPE_IP_PAIR_V4,		/* 12, 纯IPv4地址对 */
	__ADDR_TYPE_IP_PAIR_V6,		/* 13, 纯IPv6地址对 */
	ADDR_TYPE_PPP,					/* 14 */
	__ADDR_TYPE_MAX,				/* 15 */
};

#define TCP_TAKEOVER_STATE_FLAG_OFF	0
#define TCP_TAKEOVER_STATE_FLAG_ON	1


//应用层看到的链接状态定义
#define OP_STATE_PENDING   0
#define OP_STATE_REMOVE_ME 1
#define OP_STATE_CLOSE     2
#define OP_STATE_DATA      3

//应用层返回结果定义
#define APP_STATE_GIVEME   0x00
#define APP_STATE_DROPME   0x01
#define APP_STATE_FAWPKT   0x00
#define APP_STATE_DROPPKT  0x10

//流的类型定义
enum stream_type_t{
	STREAM_TYPE_NON = 0, /* 无流的概念, 如VLAN, IP层等 */
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
/* 兼容papp */
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
	   为了空间、易用性、和效率, 不强制按协议层次处理,
	   IP层存储完整的四元组信息, TCP层只需指针指向此块内存, 
	   插件获取四元组时, 不再需要get_tuple4()函数.
	   对于隧道外层IP, 端口信息为0;
	*/
	UINT16 source;	/* network order */
	UINT16 dest;		/* network order */
};

struct layer_addr_ipv6
{
	UCHAR saddr[IPV6_ADDR_LEN] ; /* network order */
	UCHAR daddr[IPV6_ADDR_LEN] ; /* network order */
	/* 2014-04-21 lijia add, 
	   为了空间、易用性、和效率, 不强制按协议层次处理,
	   IP层存储完整的四元组信息, TCP层只需指针指向此块内存, 
	   插件获取四元组时, 不再需要get_tuple4()函数.
	   对于隧道外层IP, 端口信息为0;
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
	UCHAR addrtype; // 地址类型, 详见 enum addr_type_t 
	UCHAR addrlen;
	UCHAR  pkttype;	   		//报文类型 ,参见宏定义PKT_TYPE_xxx
	UCHAR __pad[5]; //整体8字节对齐
	// 为了方便应用插件取地址, 此处使用联合体, 省去指针类型强制转换步骤 
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

// 保留此结构用于和papp兼容, 用作指针时, 可与struct layer_addr强转. 
struct ipaddr
{
	UCHAR addrtype; // 地址类型, 详见 enum addr_type_t 
	UCHAR addrlen;
	UCHAR  pkttype;	   		//报文类型 ,参见宏定义PKT_TYPE_xxx
	UCHAR __pad[5]; //整体8字节对齐
	union
	{
		struct stream_tuple4_v4 *v4;
		struct stream_tuple4_v6 *v6;
		void *paddr;
	};

};

struct tcpdetail
{
	void  *pdata;		      //数据
	UINT32 datalen;			  //数据长度
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
 	void *pdata;		      //数据
 	UINT32 datalen;			  //数据长度
	UINT32 pad;					  //预留信息
	UINT32 serverpktnum;
	UINT32 clientpktnum;
	UINT32 serverbytes;
	UINT32 clientbytes;
	UINT64 createtime; 
	UINT64 lastmtime;
};

struct streaminfo
{
	struct layer_addr addr;      //本层协议地址信息
	struct streaminfo *pfather;//上层流结构体
	UCHAR type;				   			// 链接类型
	UCHAR threadnum;	        // 所属线程
	UCHAR  dir;           //  流的生存期内有效, 流的单、双方向情况0x01:c-->s; 0x02:s-->c;  0x03 c<-->s;  
	UCHAR  curdir;        // 单包有效, 当前来包上层流的逻辑方向, 0x01:c-->s;  0x02:s-->c 
	UCHAR  opstate;				 	//当前链接所处状态
	UCHAR  pktstate;				//链接的包序列
	UCHAR  routedir;	     // 物理包方向, 单包有效, 纯人工指定, 仅用于发包时标记是否与来包方向是否相同, 别无他意
	UCHAR  stream_state;	// 每个流当前所在的队列状态
	UINT32 hash_index;		// 每个流的hash索引	      
	UINT32 stream_index;    // 每个stream在单线程全局的索引	
	union
	{
		struct tcpdetail *ptcpdetail;
		struct udpdetail *pudpdetail;
		void   *pdetail;		//流的详细信息
	};
 };



#ifdef __cplusplus
extern "C" {
#endif

//内存管理相关函数
void *dictator_malloc(int thread_seq,size_t size);
void dictator_free(int thread_seq,void *pbuf);
void *dictator_realloc(int thread_seq, void* pbuf, size_t size);

//获取当前系统运行的并发处理线程总数
int get_thread_count(void);

/* 将地址类型转换成可打印的字符串形式 */
const char *addr_type_to_string(enum addr_type_t type);

const char *printaddr (struct layer_addr *paddrinfo,int threadindex);

#ifdef __cplusplus
}
#endif

#endif

