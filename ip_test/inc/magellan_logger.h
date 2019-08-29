/*
*
*interface:magellan's logger
*the function of magellan_write_log is send the message which contains logrecord
*
*@xj
*@2014-04-30
*************************************************************************
*@xj 2014-06-30
*���֧��Ŀ�ĵ�ַ��͸��ؾ��⹦�� 
*/

#ifndef _SEND_LOG_H
#define _SEND_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/*set type*/
#define MAGELLAN_BALANCE_MAX_NUM 		(1)   //����int;  ip���ؾ������־������Ĭ��50��  
#define MAGELLAN_LOG_INTERVAL_TIME 		(2)  //����int;  �ڲ�ͳ����Ϣ����ļ��ʱ�䣬Ĭ��1����
#define MAGELLAN_TCP_CONNECT_TIME_OUT	(3)  //����int;  tcp�����������ȴ�ʱ�䣬Ĭ��5s
#define MAGELLAN_KEEP_LIVE_CHECK_TIME	(4)  //����int;  ���ip�Ƿ���ڵ�ʱ�䣬Ĭ��5����
#define MAGELLAN_DEBUG_LOG_PATH			(5)  //����char *;  �򿪱��淢�ͳɹ�����־ԭʼ��Ϣ����, �����·��
#define MAGELLAN_THREAD_AMOUNT			(6)  //����int;  ֧�ֶ��̷߳���

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
*	arg3��	set value
*  	arg 4: 	value size
* returns:
*    �ɹ�ʱ����0, ʧ��ʱ����-1��
*/
int magellan_set (magellan_logger_t handle, int  type, const char *value, int size);

/*
* arguments:
* 	arg1:�û�ID
* 	arg2: ����Ӧ��ID
*	arg3����־ѡ������
*  	arg 4: ѡ��ĸ���
*	arg 5:�߳�ID
 * returns:
 *    �ɹ�ʱ���ط��ͳ��ȣ�ʧ��ʱ����С��0��ֵ
 * 	-1, ������־��Ϣʧ��
 *	-2, ����ʧ��
 *	-3, ���͵ĳ��Ⱥ���ʵ���Ȳ����
 *	-4,ip�����ڻ�portδ����
 *	-5,�߳�ID�������ֵ
*/
int32_t magellan_write_log(magellan_logger_t handle, const int user_id,  const int table_id,magellan_opt_t* opt_array,int opt_num, int th_id);

/*
* 
* arguments:
* 	arg1: Ŀ�ĵ�ַ��, ip��portΪ�����ֽ���
*    arg2: Ŀ�ĵ�ַ�ĸ���
*	arg3: MESA_run_time_log �ľ����ΪNULLʱ��ʾ��д��־;5����ͳ��һ��
* returns:
*  ��ʧ��ʱ����NULL
*/
magellan_logger_t magellan_logger_init(addr_list_t *dst_addr, int dst_addr_num,  void *run_time_log_handle);

void magellan_logger_destroy  (magellan_logger_t handle);

#ifdef __cplusplus
}
#endif

#endif
