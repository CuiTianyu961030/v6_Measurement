#ifndef _APP_STREAM_RAWPKT_H_
#define _APP_STREAM_RAWPKT_H_ 

enum{
	RAW_PKT_GET_DATA	= 1,			//value type: void *, out_value should be void **
	RAW_PKT_GET_RAW_PKT_TYPE,	//value type: enum addr_type_t in stream_base.h, out_value should be enum addr_type_t*
	RAW_PKT_GET_TOT_LEN,			//value type: int , out_value should be int *
	RAW_PKT_GET_TIMESTAMP,		//value type: struct timeval , out_value should be struct timeval *
	RAW_PKT_GET_THIS_LAYER_HDR,	//value type: void *, out_value should be void **
	RAW_PKT_GET_THIS_LAYER_REMAIN_LEN, //value type: int , out_value should be int *
};

#ifdef __cplusplus
extern "C" {
#endif

/*
for example:
	获取原始包总长度:
	int tot_len;
	get_opt_from_rawpkt(voidpkt, RAW_PKT_GET_TOT_LEN, &tot_len);
	 
	获取本层包头起始地址:
	void *this_layer_hdr;
	get_opt_from_rawpkt(voidpkt, RAW_PKT_GET_THIS_LAYER_HDR, &this_layer_hdr); 

	获取原始包时间戳:
	struct timeval pkt_stamp;
	get_opt_from_rawpkt(voidpkt, RAW_PKT_GET_TIMESTAMP, &pkt_stamp); 

	return value:
		0:success;
		-1:error, or not support.
*/
int get_opt_from_rawpkt(const void *rawpkt, int type, void *out_value);


/* 	获取本层流在原始包中对应的头部地址,
	假设本层流类型为TCP, 调用此函数后, 得到原始包中对应的TCP头部地址.
*/
const void *get_this_layer_header(const struct streaminfo *pstream);

/*
	原始包头部偏移函数.

	参数:
		raw_data: 当前层的头部指针;
		raw_layer_type: 当前层的地址类型;
		expect_layer_type: 期望跳转到的地址类型;

	返回值:
		NULL: 无此地址;
		NON-NULL: 对应层的头部地址.
	

	举例:
		假设当前层为Ethernet, 起始包头地址为this_layer_hdr, 想跳转到IPv6层头部:
		struct ip6_hdr *ip6_header;
		ip6_header = MESA_net_jump_to_layer(this_layer_hdr, ADDR_TYPE_MAC, ADDR_TYPE_IPV6);
*/
const void *MESA_net_jump_to_layer(const void *raw_data,  int raw_layer_type, int expect_layer_type);


#ifdef __cplusplus
}
#endif

#endif

