#ifndef _APP_STREAM_CONTROL_H_
#define _APP_STREAM_CONTROL_H_ 


#ifdef __cplusplus
extern "C" {
#endif


//���õ������ӵ���ز�����Ϣ
int tcp_set_single_stream(const struct streaminfo *stream,UCHAR optype,void *value,int valuelen);
/*
//���õ������ӣ������������򻺴���Ŀ
����ֵ 0: ���óɹ���-1:����ʧ��
*/
int tcp_set_single_stream_max_unorder(const struct streaminfo *stream, UCHAR dir, unsigned short unorder_num);
int tcp_set_single_stream_needack(const struct streaminfo *pstream);
int tcp_set_single_stream_takeoverflag(const struct streaminfo *pstream,int flag);

int stream_set_single_stream_timeout(const struct streaminfo *pstream,unsigned short timeout);



#ifdef __cplusplus
}
#endif

#endif

