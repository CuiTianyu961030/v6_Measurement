#ifndef _STREAM_PROXY_H_
#define _STREAM_PROXY_H_

#include "stream_base.h"




#define PROXY_STATE_SEL 0
#define PROXY_STATE_LINK_IN 1

//	������Ϣ
struct proxydetail
{	
	UINT16 iType;		//	��������, 0 ��ʾ��Ч
	UINT16  uiPort;		//	�������ʵ�������˿�
	UINT16	uiUserLen;
	UINT16  uiPwdLen;
	UINT16  uiApendLen;
	
	UCHAR  pad;		
	UCHAR  dealstate;	//������״̬	
	UINT32  uiIP;		//	�������ʵ������IP��ַv4, �������ֽ���
	UCHAR	*pIpv6;		//	�������ʵ������IP��ַ, v6��ַ
	UCHAR	*pUser;		//    �����û���
	UCHAR   *pPwd;		//    ��������
	UCHAR 	*append;	//   ����������Ϣ������url
	void   *apme;		  //Ӧ�ò�������
	void   *pAllpktpme;   //��״̬��tcp����������
	UINT32 serverpktnum;
	UINT32 clientpktnum;
	UINT32 serverbytes;
	UINT32 clientbytes;
} ;

#ifdef __cplusplus
extern "C" {
#endif

/*��һ���������Ϣ�����һ��fatherstream,���ҹ��ص�stream��*/
void set_proxy_fstream(struct streaminfo *pstream,struct streaminfo *pProxy);

/*�������������Ϣ������ɺ󣬽��� �ڲ� ����*/
int deal_tcp_in_proxy_stream(struct streaminfo *a_tcp,void * a_packet,struct streaminfo *pProxy);

/*�ص��ϲ���Ϣ���ͷŴ�����������Ϣ*/
void free_tcp_proxy_stream(struct streaminfo *pstream,struct streaminfo *pProxy);

#ifdef __cplusplus
}
#endif

#endif
