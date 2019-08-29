#ifndef _PROJECT_REQUIREMENT_H_
#define _PROJECT_REQUIREMENT_H_

#include "stream_base.h"

#ifdef __cplusplus
extern "C" {
#endif


#define PROJECT_REQ_NAME_MAX_LEN		(64)

typedef void (project_req_free_t)(int thread_seq, void *project_req_value);

#define PROJECT_VAL_TYPE_CHAR				"char"
#define PROJECT_VAL_TYPE_SHORT			"short"
#define PROJECT_VAL_TYPE_INT				"int"
#define PROJECT_VAL_TYPE_LONG				"long"
#define PROJECT_VAL_TYPE_STRUCT			"struct"


int project_requirement_global_init(void);

/*	
	must call this function in initialization, only one times,
	the 'free_cb' should be NULL if 'project_req_val_type' is simple type,
	otherwise please implement it by youself.

	args:
		project_req_name: for example, "terminal_tag", "stream_id".
		project_req_val_type: support "char","short","int","long","struct".
		free_cb: used to free resource when 'project_req_val_type' is "struct".
	
 
	return value: 'project_req_id' of this project_req_name, must use this id in following functions.
		>= 0 : success;
		-1   : error.
*/
int project_producer_register(const char *project_req_name, const char *project_req_val_type, project_req_free_t *free_cb);

/* args and return value same with project_producer_register() */
int project_customer_register(const char *project_req_name, const char *project_req_val_type);

/*	
	Function project_req_add_struct: 'project_req_value' must be a pointer to heap memory(obtain by malloc).
	
	return value:
		0 : success;
		-1: error.
*/
int project_req_add_char(struct streaminfo *stream, int project_req_id, char project_req_value);
int project_req_add_short(struct streaminfo *stream, int project_req_id, short project_req_value);
int project_req_add_int(struct streaminfo *stream, int project_req_id, int project_req_value);
int project_req_add_long(struct streaminfo *stream, int project_req_id, long project_req_value);

int project_req_add_uchar(struct streaminfo *stream, int project_req_id, unsigned char project_req_value);
int project_req_add_ushort(struct streaminfo *stream, int project_req_id, unsigned short project_req_value);
int project_req_add_uint(struct streaminfo *stream, int project_req_id, unsigned int project_req_value);
int project_req_add_ulong(struct streaminfo *stream, int project_req_id, unsigned long project_req_value);


int project_req_add_struct(struct streaminfo *stream, int project_req_id, const void *project_req_value);


/*
	return value:
		-1(or all bit is '1' in Hex mode, 0xFF, 0xFFFF): 
			maybe error, maybe the actual project_req_value is -1 indeed, 
			must check tht 'errno' in this case, 
			the 'errno' will be set to 'ERANGE' indicate an error.
		others: success.    

	for example:
		int value = project_req_get_int(stream, req_id);
		if((-1 == value) && (ERANGE == errno)){
			error_handle();
		}else{
			do_somgthing();
		}
		
	for example2:
		unsigned short value = project_req_get_ushort(stream, req_id);
		if((0xFF == value) && (ERANGE == errno)){
			error_handle();
		}else{
			do_somgthing();
		}
		
*/
char project_req_get_char(const struct streaminfo *stream, int project_req_id);
short project_req_get_short(const struct streaminfo *stream, int project_req_id);
int project_req_get_int(const struct streaminfo *stream, int project_req_id);
long project_req_get_long(const struct streaminfo *stream, int project_req_id);

unsigned char project_req_get_uchar(const struct streaminfo *stream, int project_req_id);
unsigned short project_req_get_ushort(const struct streaminfo *stream, int project_req_id);
unsigned int project_req_get_uint(const struct streaminfo *stream, int project_req_id);
unsigned long project_req_get_ulong(const struct streaminfo *stream, int project_req_id);

/*
	return value:
		NULL  : error;
		others: success.    
*/
const void *project_req_get_struct(const struct streaminfo *stream, int project_req_id);

#ifdef __cplusplus
}
#endif

#endif

