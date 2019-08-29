#ifndef HTTP_H_
#define HTTP_H_

#define    HTTP_H_VERSION_3_20141209     	0

#ifndef uchar
typedef unsigned char      		uchar;
#endif
#ifndef int64
typedef long long 		   		int64;
#endif
#ifndef uint8
typedef unsigned char      		uint8;
#endif
#ifndef uint64
typedef unsigned long long 		uint64;
#endif
#ifndef uint32
typedef unsigned int       		uint32;
#endif
#ifndef uint16
typedef unsigned short     		uint16;
#endif

/*interest region*/
typedef enum
{
	/*#http_special1*/
	HTTP_INTEREST_KEY_MASK=0,		
	HTTP_ALL_MASK,
	HTTP_OTHER_REGIONS_MASK,
	HTTP_STATE_MASK,
	HTTP_REQ_LINE_MASK,
	HTTP_RES_LINE_MASK,	
	HTTP_CONTENT_MASK,             
	HTTP_UNGZIP_CONTENT_MASK,
	HTTP_MESSAGE_URL_MASK,
	HTTP_URI_MASK,

	/*#http_request*/
	HTTP_HOST_MASK,	
	HTTP_REFERER_MASK,
	HTTP_USER_AGENT_MASK,
	HTTP_COOKIE_MASK,
	HTTP_PROXY_AUTHORIZATION_MASK,
	HTTP_AUTHORIZATION_MASK,
	
	/*#http_response*/	
	HTTP_LOCATION_MASK,
	HTTP_SERVER_MASK,
	HTTP_ETAG_MASK,

	/*#http_general*/	
	HTTP_DATE_MASK,
	HTTP_TRAILER_MASK,
	HTTP_TRANSFER_ENCODING_MASK,
	HTTP_VIA_MASK,
	HTTP_PRAGMA_MASK,
	HTTP_CONNECTION_MASK,

	/*#http_content*/	
	HTTP_CONT_ENCODING_MASK,
	HTTP_CONT_LANGUAGE_MASK,
	HTTP_CONT_LOCATION_MASK,	
	HTTP_CONT_DISPOSITION_MASK,
	HTTP_CONT_RANGE_MASK,
	HTTP_CONT_LENGTH_MASK,
	HTTP_CONT_TYPE_MASK,
	HTTP_CHARSET_MASK,
	HTTP_EXPIRES_MASK,
	HTTP_X_FLASH_VERSION_MASK,	
	HTTP_TRANSFER_LENGTH_MASK,

	HTTP_REGION_NUM,	
}interested_region_mask;
/*HTTP_REGION_NUM=36*/
#define HTTP_INTEREST_KEY				((long long)1<<HTTP_INTEREST_KEY_MASK)
#define HTTP_ALL						((long long)1<<HTTP_ALL_MASK)
#define HTTP_OTHER_REGIONS			((long long)1<<HTTP_OTHER_REGIONS_MASK)
#define HTTP_STATE						((long long)1<<HTTP_STATE_MASK)
#define HTTP_REQ_LINE					((long long)1<<HTTP_REQ_LINE_MASK)
#define HTTP_RES_LINE					((long long)1<<HTTP_RES_LINE_MASK)
#define HTTP_CONTENT					((long long)1<<HTTP_CONTENT_MASK)
#define HTTP_UNGZIP_CONTENT			((long long)1<<HTTP_UNGZIP_CONTENT_MASK)
#define HTTP_MESSAGE_URL				((long long)1<<HTTP_MESSAGE_URL_MASK)
#define HTTP_URI						((long long)1<<HTTP_URI_MASK)

#define HTTP_HOST						((long long)1<<HTTP_HOST_MASK)
#define HTTP_REFERER					((long long)1<<HTTP_REFERER_MASK)
#define HTTP_USER_AGENT				((long long)1<<HTTP_USER_AGENT_MASK)
#define HTTP_COOKIE					((long long)1<<HTTP_COOKIE_MASK)
#define HTTP_PROXY_AUTHORIZATION		((long long)1<<HTTP_PROXY_AUTHORIZATION_MASK)
#define HTTP_AUTHORIZATION			((long long)1<<HTTP_AUTHORIZATION_MASK)

#define HTTP_LOCATION					((long long)1<<HTTP_LOCATION_MASK)
#define HTTP_SERVER					((long long)1<<HTTP_SERVER_MASK)
#define HTTP_ETAG 						((long long)1<<HTTP_ETAG_MASK)

#define HTTP_DATE 						((long long)1<<HTTP_DATE_MASK)
#define HTTP_TRAILER 					((long long)1<<HTTP_TRAILER_MASK)
#define HTTP_TRANSFER_ENCODING		((long long)1<<HTTP_TRANSFER_ENCODING_MASK)
#define HTTP_VIA						((long long)1<<HTTP_VIA_MASK)
#define HTTP_PRAGMA					((long long)1<<HTTP_PRAGMA_MASK)
#define HTTP_CONNECTION 				((long long)1<<HTTP_CONNECTION_MASK)

#define HTTP_CONT_ENCODING 			((long long)1<<HTTP_CONT_ENCODING_MASK)
#define HTTP_CONT_LANGUAGE 			((long long)1<<HTTP_CONT_LANGUAGE_MASK)
#define HTTP_CONT_LOCATION 			((long long)1<<HTTP_CONT_LOCATION_MASK)
#define HTTP_CONT_RANGE 				((long long)1<<HTTP_CONT_RANGE_MASK)
#define HTTP_CONT_LENGTH 				((long long)1<<HTTP_CONT_LENGTH_MASK)
#define HTTP_CONT_TYPE 				((long long)1<<HTTP_CONT_TYPE_MASK)
#define HTTP_CONT_DISPOSITION			((long long)1<<HTTP_CONT_DISPOSITION_MASK)
#define HTTP_CHARSET 					((long long)1<<HTTP_CHARSET_MASK)
#define HTTP_EXPIRES 					((long long)1<<HTTP_EXPIRES_MASK)
#define HTTP_X_FLASH_VERSION 			((long long)1<<HTTP_X_FLASH_VERSION_MASK)
#define HTTP_TRANSFER_LENGTH 			((long long)1<<HTTP_TRANSFER_LENGTH_MASK)

/*http_state*/
#define HTTP_STATE_UNKNOWN 			0x00
#define HTTP_START_LINE				0x01 
#define HTTP_REGION 					0x02 
#define HTTP_DATA_BEGIN 				0x03 /*header over*/
#define HTTP_DATA 						0x04 /*have entity*/
#define HTTP_DATA_END 					0x05

/*内容编码方式cont_encoding*/
#define HTTP_CONT_ENCOD_UNKNOWN 	0X00//初始状态
#define HTTP_CONT_ENCOD_DEFAULT 		0X01
#define HTTP_CONT_ENCOD_GZIP 			0X02
#define HTTP_CONT_ENCOD_COMPRESS 	0X03
#define HTTP_CONT_ENCOD_DEFLATE 		0X04
#define HTTP_CONT_ENCOD_OTHERS 		0X05

/*传输编码方式tran_encoding*/
#define HTTP_TRANS_ENCOD_UNKNOWN 	0X00//初始状态
#define HTTP_TRANS_ENCOD_CHUNKED 	0X01//chunked编码13
#define HTTP_TRANS_ENCOD_DEFAULT 	0X02//default
#define HTTP_TRANS_ENCOD_OTHERS 		0X03//其他状态

/*请求方法method*/
#define HTTP_METHOD_UNKNOWN			0X00//初始状态
#define HTTP_METHOD_GET 				0X01
#define HTTP_METHOD_POST 				0X02
#define HTTP_METHOD_CONNECT			0X03
#define HTTP_METHOD_HEAD				0X04
#define HTTP_METHOD_PUT				0X05
#define HTTP_METHOD_OPTIONS			0X06
#define HTTP_METHOD_DELETE			0X07
#define HTTP_METHOD_TRACE				0X08


typedef struct _cont_range_t
{
	uint64 	start;
	uint64 	end;
	uint64 	len;
}cont_range_t;

typedef struct _append_infor_t
{	
	char* 					content;   //data: origin data when ungzip;     region:all complete line when enpand region
	uint32 					contlen;
}append_infor_t;

typedef struct http_infor_t
{	
	char*					p_url;		
	uint32 					url_len;	
	uint32 					http_session_seq;			
	uint64 					cont_length;			
	cont_range_t* 			cont_range;	
	
	uchar					curdir;	
	uchar 					http_state;		    
	uchar 					cont_encoding;
	uchar 					trans_encoding;  
	
	uchar					method;	
	uchar 					_pad_;	
	uint16 					res_code;
	append_infor_t			append_infor;	
}http_infor;

#ifdef __cplusplus
extern "C" {
#endif

long long http_region2proto_flag(const char *region, uint32 region_len);
const char* http_proto_flag2region(long long proto_flag);
const char* http_get_method(uchar method);
char* http_url_decode(char *data,  int* data_len);


#ifdef __cplusplus
}
#endif

#endif 
