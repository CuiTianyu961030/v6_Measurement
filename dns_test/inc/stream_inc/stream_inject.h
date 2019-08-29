#ifndef _APP_STREAM_INJECT_H_
#define _APP_STREAM_INJECT_H_ 

#include "stream_base.h"

#ifdef __cplusplus
extern "C" {
#endif

//链接管控相关函数

int MESA_kill_tcp(struct streaminfo *stream, const void *raw_pkt);
int MESA_kill_tcp_synack(struct streaminfo *stream, const void *raw_pkt);

/* 2014-11-15 lijia add, for drop NO-TCP protocol in serial mode. 
    return value:
    >= 0: success.
    -1  : error.
*/
int MESA_kill_connection(struct streaminfo *stream, const void *ext_raw_pkt);

/* 反向route_dir函数,  */
unsigned char MESA_dir_reverse(unsigned char raw_route_dir);

/*
	ARG:
		stream: 流结构体指针;
		payload: 要发送的数据指针;
		payload_len: 要发送的数据负载长度;
		raw_pkt: 原始包指针;
		snd_routedir: 要发送数据的方向, 原始包方向为:stream->routedir , 
			 如果与原始包同向, snd_dir = stream->routedir, 
			 如果与原始包反向, snd_dir = MESA_dir_reverse(stream->routedir).
	return value:
		-1: error.
		>0: 发送的数据包实际总长度(payload_len + 底层包头长度);
*/
int MESA_inject_pkt(struct streaminfo *stream, const char *payload, int payload_len, const void *raw_pkt, UCHAR snd_routedir);


int MESA_sendpacket_ethlayer(int thread_index,const char *buf, int buf_len, unsigned int target_id);//papp online, shuihu

/* 发送已构造好的完整IP包, 校验和等均需调用者计算 */
int MESA_sendpacket_iplayer(int thread_index,const char *buf,  int buf_len, u_int8_t dir);

/* 发送指定参数IP包, 可指定负载内容, 校验和由平台自动计算,
   sip, dip为主机序. */
int MESA_fakepacket_send_ipv4(int thread_index,u_int8_t ttl,u_int8_t protocol,
							u_int32_t sip_host_order, u_int32_t dip_host_order, 
							const char *payload, int payload_len,u_int8_t dir);

/* 发送指定参数TCP包, 可指定负载内容, 校验和由平台自动计算,
   sip, dip,sport,dport,sseq,sack都为主机序. */
int MESA_fakepacket_send_tcp(int thread_index,u_int sip_host_order,u_int dip_host_order,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order,
							u_char control,const char* payload,int payload_len, u_int8_t dir);

/* 发送指定参数UDP包, 可指定负载内容, 校验和由平台自动计算,
   sip, dip,sport,dport都为主机序. */
int MESA_fakepacket_send_udp(int thread_index, u_int sip_host_order, u_int dip_host_order, 
							u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir);
							

#ifdef __cplusplus
}
#endif

#endif

