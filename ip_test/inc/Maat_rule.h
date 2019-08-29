
/*
*****************Maat Network Flow Rule Manage Framework********
*	Maat is the of Goddess of truth and justice in ancient Egyptian concept.
*	Her feather was the measure that determined whether the souls (considered 
*	to reside in the heart) of the departed would reach the paradise of afterlife
*	successfully.
*	Author: zhengchao@iie.ac.cn
*	Date:   2014-11-05
*	All right reserved by Institute of Engineer,Chinese Academic of Science 2014~2018
*********************************************************
*/
#ifndef H_MAAT_RULE_H_INCLUDE
#define H_MAAT_RULE_H_INCLUDE
#include "stream.h"

#ifdef __cplusplus
extern "C"
{
#endif

enum MAAT_CHARSET
{
	CHARSET_NONE=0,
	CHARSET_GBK,
	CHARSET_BIG5,
	CHARSET_UNICODE,
	CHARSET_UTF8,	// 4
	CHARSET_BIN	//5
};
enum MAAT_ACTION
{
	MAAT_ACTION_BLOCK=0,
	MAAT_ACTION_MONIT,
	MAAT_ACTION_WHITE
};
enum MAAT_POS_TYPE
{
	MAAT_POSTYPE_EXPR=0,
	MAAT_POSTYPE_REGEX
};
typedef	void*	scan_status_t;
typedef	void*	stream_para_t;
typedef	void*	Maat_feather_t;
#define	MAX_SERVICE_DEFINE_LEN	128
struct Maat_rule_t
{
	int 	config_id;
	int		service_id;
	char 	do_log;
	char 	do_blacklist;//捕包个数(返回原始包时使用)，0:不限个数
	char	action;//捕包方向(返回原始包时使用)，1:C2S;2:S2 3:DOUBLE
	char	resevered;
	int		serv_def_len;
	char 	service_defined[MAX_SERVICE_DEFINE_LEN];
};
#define	MAAT_RULE_UPDATE_TYPE_FULL	1
#define	MAAT_RULE_UPDATE_TYPE_INC	2
typedef void Maat_start_callback_t(int update_type,void* u_para);
typedef void Maat_update_callback_t(int table_id,const char* table_line,void* u_para);
typedef void Maat_finish_callback_t(void* u_para);







#define	MAAT_MAX_HIT_RULE_NUM		8
#define MAAT_MAX_EXPR_ITEM_NUM		8
#define	MAAT_MAX_HIT_POS_NUM		8
#define	MAAT_MAX_REGEX_GROUP_NUM	8
//--------------------HITTING DETAIL DESCRIPTION BEGIN
//NOTE position buffer as hitting_regex_pos and hit_pos,are ONLY valid before next scan or Maat_stream_scan_string_end
struct regex_pos_t
{
	int group_num;//当前子表达式的分组个数
	int hitting_regex_len;//当前子表达式的命中长度(我暂时不用这个字段)
	const char* hitting_regex_pos;//当前子表达式的命中部分的起始位置集合
	int grouping_len[MAAT_MAX_REGEX_GROUP_NUM];//当前扫描字段对于每个命中的正则分组的长度
	const char* grouping_pos[MAAT_MAX_REGEX_GROUP_NUM];//当前扫描字段对于每个命中的正则分组的起始位置
};
/*
struct str_pos_t
{
	int hit_cnt;
	int hit_len[MAAT_MAX_HIT_POS_NUM];
	const char* hit_pos[MAAT_MAX_HIT_POS_NUM];
};*/
struct str_pos_t
{
	int hit_len;
	const char* hit_pos;
};
struct sub_item_pos_t
{
	enum MAAT_POS_TYPE ruletype;
	int hit_cnt;//表示该域配置的当前子表达式命中了多少次
	union
	{
		struct regex_pos_t	regex_pos[MAAT_MAX_HIT_POS_NUM];
		struct str_pos_t substr_pos[MAAT_MAX_HIT_POS_NUM];
	};
};

struct Maat_region_pos_t
{
	
	int region_id;
	int sub_item_num;//表示该域配置由几个子表达式
	struct sub_item_pos_t sub_item_pos[MAAT_MAX_EXPR_ITEM_NUM];	
};

struct Maat_hit_detail_t
{
	int config_id;//set <0 if half hit;
	/*int hit_region_cnt;//表示当前扫面的域有多少个域配置命中*/
	int hit_region_cnt;
	struct Maat_region_pos_t region_pos[MAAT_MAX_HIT_RULE_NUM];	
};
//--------------------HITTING DETAIL DESCRIPTION END
Maat_feather_t Maat_summon_feather(int max_thread_num,
								const char* table_info_path,
								const char* ful_cfg_dir,
								const char* inc_cfg_dir,
								void*logger);//
void Maat_burn_feather(Maat_feather_t feather);

//return table_id(>=0) if success,otherwise return -1;
int Maat_table_register(Maat_feather_t feather,const char* table_name);
//return 1 if success,otherwise return -1 incase invalid table_id or registed function number exceed 32;
int Maat_table_callback_register(Maat_feather_t feather,short table_id,
									Maat_start_callback_t *start,//MAAT_RULE_UPDATE_TYPE_*,u_para
									Maat_update_callback_t *update,//table line ,u_para
									Maat_finish_callback_t *finish,//u_para
									void* u_para);



//Return hit rule number, return -1 when error occurs,return -2 when hit current region
int Maat_scan_intval(Maat_feather_t feather,int table_id
						,unsigned int intval
						,struct Maat_rule_t*result,int rule_size
						,scan_status_t *mid,int thread_num);
int Maat_scan_addr(Maat_feather_t feather,int table_id
						,struct ipaddr* addr
						,struct Maat_rule_t*result,int rule_size
						,scan_status_t *mid,int thread_num);
int Maat_scan_proto_addr(Maat_feather_t feather,int table_id
                         ,struct ipaddr* addr,unsigned short int proto
                         ,struct Maat_rule_t*result,int rule_num
                         ,scan_status_t *mid,int thread_num);
int Maat_full_scan_string(Maat_feather_t feather,int table_id
						,enum MAAT_CHARSET charset,const char* data,int data_len
						,struct Maat_rule_t*result,int* found_pos,int rule_size
						,scan_status_t* mid,int thread_num);
int Maat_full_scan_string_detail(Maat_feather_t feather,int table_id
						,enum MAAT_CHARSET charset,const char* data,int data_len
						,struct Maat_rule_t*result,int rule_size,struct Maat_hit_detail_t *hit_detail,int detail_num
						,int* detail_ret,scan_status_t* mid,int thread_num);

stream_para_t Maat_stream_scan_string_start(Maat_feather_t feather,int table_id,int thread_num);
int Maat_stream_scan_string(stream_para_t* stream_para
									,enum MAAT_CHARSET charset,const char* data,int data_len
									,struct Maat_rule_t*result,int* found_pos,int rule_size
									,scan_status_t* mid);
int Maat_stream_scan_string_detail(stream_para_t* stream_para
									,enum MAAT_CHARSET charset,const char* data,int data_len
									,struct Maat_rule_t*result,int rule_num,struct Maat_hit_detail_t *hit_detail,int detail_num
									,int* detail_ret,scan_status_t* mid);
void Maat_stream_scan_string_end(stream_para_t* stream_para);

void Maat_clean_status(scan_status_t* mid);

#ifdef __cplusplus
}
#endif

#endif	//	H_MAAT_RULE_H_INCLUDE


