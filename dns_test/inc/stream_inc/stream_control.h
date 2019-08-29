#ifndef _APP_STREAM_CONTROL_H_
#define _APP_STREAM_CONTROL_H_ 


#ifdef __cplusplus
extern "C" {
#endif


//设置单个链接的相关参数信息
int tcp_set_single_stream(const struct streaminfo *stream,UCHAR optype,void *value,int valuelen);
/*
//设置单个链接，单侧的最大乱序缓存数目
返回值 0: 设置成功，-1:设置失败
*/
int tcp_set_single_stream_max_unorder(const struct streaminfo *stream, UCHAR dir, unsigned short unorder_num);
int tcp_set_single_stream_needack(const struct streaminfo *pstream);
int tcp_set_single_stream_takeoverflag(const struct streaminfo *pstream,int flag);

int stream_set_single_stream_timeout(const struct streaminfo *pstream,unsigned short timeout);



#ifdef __cplusplus
}
#endif

#endif

