#ifndef _APP_STREAM_ENTRY_H_
#define _APP_STREAM_ENTRY_H_ 


//ҵ�����ý�����ʱsession_state״̬
#define SESSION_STATE_PENDING	0x01
#define SESSION_STATE_DATA		0x02
#define SESSION_STATE_CLOSE	0x04

//���������ҵ���ʱ�ķ���ֵ��
#define PROT_STATE_GIVEME   0x01
#define PROT_STATE_DROPME	0x02
#define PROT_STATE_DROPPKT	0x04

//������������ҵ�����ʱ�������
typedef struct _plugin_session_info
{
	unsigned short  plugid;			//plugid��ƽ̨����
	char session_state;	//�Ự״̬��PENDING,DATA,CLOSE
	char _pad_;			//����
	int buflen;			//��ǰ�ֶγ���
	long long prot_flag;	//��ǰ�ֶε�flagֵ
	void *buf;			//��ǰ�ֶ�
	void* app_info;		//��������������Ϣ
}stSessionInfo;




#ifdef __cplusplus
extern "C" {
#endif


typedef char (*STREAM_CB_FUN_T)(const struct streaminfo *pstream,void **pme, int thread_seq,const void *ip_hdr);
typedef char (*IPv4_CB_FUN_T)(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *ipv4_hdr);
typedef char (*IPv6_CB_FUN_T)(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *ipv6_hdr);


typedef char (*SAPP_PKT_CB_FUN_T)(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt);
typedef char (*SAPP_STREAM_FUN_T)(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme);


/*����������
	a_*��		������������Ϣ;
	f_*:		��������Ӧ�ĸ�����Ϣ;
	raw_pkt:	ԭʼ��ָ��, ʵ������Ϊ'raw_pkt_t';
	pme:		˽������ָ�룬������չ�ã���ʱΪNULL;
	thread_seq���߳����;

��������ֵ������Ϊ�����ĸ�ֵ������

	APP_STATE_GIVEME�������򱾺����Ͱ���
	APP_STATE_DROPME�������򱾺����Ͱ���
	APP_STATE_FAWPKT����ע�����ݰ�
	APP_STATE_DROPPKT������ע�����ݰ�
*/
char IPv4_ENTRY_EXAMPLE(const struct streaminfo *f_stream,unsigned char routedir,int thread_seq, const void *raw_pkt);
char IPv6_ENTRY_EXAMPLE(const struct streaminfo *f_stream,unsigned char routedir,int thread_seq,const void *raw_pkt);
char TCP_ENTRY_EXAMPLE(const struct streaminfo *a_tcp,  void **pme, int thread_seq,const void *raw_pkt);
char UDP_ENTRY_EXAMPLE(const struct streaminfo *a_udp,  void **pme, int thread_seq,const void *raw_pkt);

char SAPP_PKT_EXAMPLE(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt);
char SAPP_STREAM_EXAMPLE(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme);


//ҵ���ص��ӿ�
char PROT_PROCESS(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet);




#ifdef __cplusplus
}
#endif


#endif

