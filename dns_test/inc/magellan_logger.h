/*
*
*interface:magellan's logger
*the function of magellan_write_log is send the message which contains logrecord
*
*@xj
*@2014-04-30
*************************************************************************
*@xj 2014-06-30
*添加支持目的地址组和负载均衡功能 
*/

#ifndef _SEND_LOG_H
#define _SEND_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/*set type*/
#define MAGELLAN_BALANCE_MAX_NUM 		(1)   //类型int;  ip负载均衡的日志条数，默认50万  
#define MAGELLAN_LOG_INTERVAL_TIME 		(2)  //类型int;  内部统计信息输出的间隔时间，默认1分钟
#define MAGELLAN_TCP_CONNECT_TIME_OUT	(3)  //类型int;  tcp建立连接最大等待时间，默认5s
#define MAGELLAN_KEEP_LIVE_CHECK_TIME	(4)  //类型int;  检测ip是否存在的时间，默认5分钟
#define MAGELLAN_DEBUG_LOG_PATH			(5)  //类型char *;  打开保存发送成功的日志原始信息开关, 保存的路径
#define MAGELLAN_THREAD_AMOUNT			(6)  //类型int;  支持多线程发送

typedef struct _magellan_opt{
	int opt_type;
	int opt_len;
//	const void* opt_value;
	void* opt_value;//modified by yulingjing:delete const
} magellan_opt_t;

typedef struct _addr_list{
	unsigned int ip_nr;  //network  
	unsigned short port_nr; //network
}addr_list_t ;

typedef void * magellan_logger_t;

/*
* arguments:
* 	arg1:	MAGELLAN  handle
* 	arg2:	set type  (MAGELLAN_BALANCE_MAX_NUM ......)
*	arg3：	set value
*  	arg 4: 	value size
* returns:
*    成功时返回0, 失败时返回-1。
*/
int magellan_set (magellan_logger_t handle, int  type, const char *value, int size);

/*
* arguments:
* 	arg1:用户ID
* 	arg2: 库表对应的ID
*	arg3：日志选项数组
*  	arg 4: 选项的个数
*	arg 5:线程ID
 * returns:
 *    成功时返回发送长度，失败时返回小于0的值
 * 	-1, 构造日志信息失败
 *	-2, 发送失败
 *	-3, 发送的长度和真实长度不相等
 *	-4,ip不存在或port未监听
 *	-5,线程ID超过最大值
*/
int32_t magellan_write_log(magellan_logger_t handle, const int user_id,  const int table_id,magellan_opt_t* opt_array,int opt_num, int th_id);

/*
* 
* arguments:
* 	arg1: 目的地址组, ip和port为网络字节序
*    arg2: 目的地址的个数
*	arg3: MESA_run_time_log 的句柄，为NULL时表示不写日志;5分钟统计一次
* returns:
*  ，失败时返回NULL
*/
magellan_logger_t magellan_logger_init(addr_list_t *dst_addr, int dst_addr_num,  void *run_time_log_handle);

void magellan_logger_destroy  (magellan_logger_t handle);

#ifdef __cplusplus
}
#endif

#endif
