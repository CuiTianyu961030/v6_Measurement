#ifndef _APP_STREAM_INJECT_H_
#define _APP_STREAM_INJECT_H_ 

#include "stream_base.h"

#ifdef __cplusplus
extern "C" {
#endif

//���ӹܿ���غ���

int MESA_kill_tcp(struct streaminfo *stream, const void *raw_pkt);
int MESA_kill_tcp_synack(struct streaminfo *stream, const void *raw_pkt);

/* 2014-11-15 lijia add, for drop NO-TCP protocol in serial mode. 
    return value:
    >= 0: success.
    -1  : error.
*/
int MESA_kill_connection(struct streaminfo *stream, const void *ext_raw_pkt);

/* ����route_dir����,  */
unsigned char MESA_dir_reverse(unsigned char raw_route_dir);

/*
	ARG:
		stream: ���ṹ��ָ��;
		payload: Ҫ���͵�����ָ��;
		payload_len: Ҫ���͵����ݸ��س���;
		raw_pkt: ԭʼ��ָ��;
		snd_routedir: Ҫ�������ݵķ���, ԭʼ������Ϊ:stream->routedir , 
			 �����ԭʼ��ͬ��, snd_dir = stream->routedir, 
			 �����ԭʼ������, snd_dir = MESA_dir_reverse(stream->routedir).
	return value:
		-1: error.
		>0: ���͵����ݰ�ʵ���ܳ���(payload_len + �ײ��ͷ����);
*/
int MESA_inject_pkt(struct streaminfo *stream, const char *payload, int payload_len, const void *raw_pkt, UCHAR snd_routedir);


int MESA_sendpacket_ethlayer(int thread_index,const char *buf, int buf_len, unsigned int target_id);//papp online, shuihu

/* �����ѹ���õ�����IP��, У��͵Ⱦ�������߼��� */
int MESA_sendpacket_iplayer(int thread_index,const char *buf,  int buf_len, u_int8_t dir);

/* ����ָ������IP��, ��ָ����������, У�����ƽ̨�Զ�����,
   sip, dipΪ������. */
int MESA_fakepacket_send_ipv4(int thread_index,u_int8_t ttl,u_int8_t protocol,
							u_int32_t sip_host_order, u_int32_t dip_host_order, 
							const char *payload, int payload_len,u_int8_t dir);

/* ����ָ������TCP��, ��ָ����������, У�����ƽ̨�Զ�����,
   sip, dip,sport,dport,sseq,sack��Ϊ������. */
int MESA_fakepacket_send_tcp(int thread_index,u_int sip_host_order,u_int dip_host_order,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order,
							u_char control,const char* payload,int payload_len, u_int8_t dir);

/* ����ָ������UDP��, ��ָ����������, У�����ƽ̨�Զ�����,
   sip, dip,sport,dport��Ϊ������. */
int MESA_fakepacket_send_udp(int thread_index, u_int sip_host_order, u_int dip_host_order, 
							u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir);
							

#ifdef __cplusplus
}
#endif

#endif

