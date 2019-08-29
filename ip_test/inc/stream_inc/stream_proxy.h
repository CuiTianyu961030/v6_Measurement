#ifndef _STREAM_PROXY_H_
#define _STREAM_PROXY_H_

#include "stream_base.h"




#define PROXY_STATE_SEL 0
#define PROXY_STATE_LINK_IN 1

//	代理信息
struct proxydetail
{	
	UINT16 iType;		//	代理类型, 0 表示无效
	UINT16  uiPort;		//	代理的真实服务器端口
	UINT16	uiUserLen;
	UINT16  uiPwdLen;
	UINT16  uiApendLen;
	
	UCHAR  pad;		
	UCHAR  dealstate;	//代理处理状态	
	UINT32  uiIP;		//	代理的真实服务器IP地址v4, 按网络字节序
	UCHAR	*pIpv6;		//	代理的真实服务器IP地址, v6地址
	UCHAR	*pUser;		//    代理用户名
	UCHAR   *pPwd;		//    代理密码
	UCHAR 	*append;	//   其它附属信息，比如url
	void   *apme;		  //应用层上下文
	void   *pAllpktpme;   //无状态的tcp管理上下文
	UINT32 serverpktnum;
	UINT32 clientpktnum;
	UINT32 serverbytes;
	UINT32 clientbytes;
} ;

#ifdef __cplusplus
extern "C" {
#endif

/*把一个代理的信息虚拟成一个fatherstream,并且挂载到stream上*/
void set_proxy_fstream(struct streaminfo *pstream,struct streaminfo *pProxy);

/*当代理自身的信息处理完成后，进行 内层 调用*/
int deal_tcp_in_proxy_stream(struct streaminfo *a_tcp,void * a_packet,struct streaminfo *pProxy);

/*回调上层信息，释放代理保存的相关信息*/
void free_tcp_proxy_stream(struct streaminfo *pstream,struct streaminfo *pProxy);

#ifdef __cplusplus
}
#endif

#endif
