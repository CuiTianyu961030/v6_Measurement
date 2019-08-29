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
	��ȡԭʼ���ܳ���:
	int tot_len;
	get_opt_from_rawpkt(voidpkt, RAW_PKT_GET_TOT_LEN, &tot_len);
	 
	��ȡ�����ͷ��ʼ��ַ:
	void *this_layer_hdr;
	get_opt_from_rawpkt(voidpkt, RAW_PKT_GET_THIS_LAYER_HDR, &this_layer_hdr); 

	��ȡԭʼ��ʱ���:
	struct timeval pkt_stamp;
	get_opt_from_rawpkt(voidpkt, RAW_PKT_GET_TIMESTAMP, &pkt_stamp); 

	return value:
		0:success;
		-1:error, or not support.
*/
int get_opt_from_rawpkt(const void *rawpkt, int type, void *out_value);


/* 	��ȡ��������ԭʼ���ж�Ӧ��ͷ����ַ,
	���豾��������ΪTCP, ���ô˺�����, �õ�ԭʼ���ж�Ӧ��TCPͷ����ַ.
*/
const void *get_this_layer_header(const struct streaminfo *pstream);

/*
	ԭʼ��ͷ��ƫ�ƺ���.

	����:
		raw_data: ��ǰ���ͷ��ָ��;
		raw_layer_type: ��ǰ��ĵ�ַ����;
		expect_layer_type: ������ת���ĵ�ַ����;

	����ֵ:
		NULL: �޴˵�ַ;
		NON-NULL: ��Ӧ���ͷ����ַ.
	

	����:
		���赱ǰ��ΪEthernet, ��ʼ��ͷ��ַΪthis_layer_hdr, ����ת��IPv6��ͷ��:
		struct ip6_hdr *ip6_header;
		ip6_header = MESA_net_jump_to_layer(this_layer_hdr, ADDR_TYPE_MAC, ADDR_TYPE_IPV6);
*/
const void *MESA_net_jump_to_layer(const void *raw_data,  int raw_layer_type, int expect_layer_type);


#ifdef __cplusplus
}
#endif

#endif

