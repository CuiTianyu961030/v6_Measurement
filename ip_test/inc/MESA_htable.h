#ifndef _MESA_HASH_V3_H_
#define _MESA_HASH_V3_H_
#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

/*
 * general purpose hash table implementation.
 *
 * xiang hong
 * 2002-07-28
 *History:
 * 2012-03-23 zhengchao add thread safe option and link expire feature;
 * 2014-01-27 lijia add reentrant feature.
 */

#define MESA_HASH_DEBUG			(0)

#define ELIMINATE_TYPE_NUM			(1)
#define ELIMINATE_TYPE_TIME			(2)

typedef void * MESA_htable_handle;


#define HASH_MALLOC(_n_)		malloc(_n_)
#define HASH_FREE(_p_)			free(_p_)


#if 1
#define HASH_TIME_NOW()        	time(NULL) 
#else
extern volatile time_t g_CurrentTime; /* 此变量在另一个线程中每隔1秒自增一次 */
#define HASH_TIME_NOW()        	(time_t)g_CurrentTime  
#endif

#ifndef uchar
#define uchar	unsigned char
#endif
#ifndef uint
#define uint	unsigned int
#endif

/* eliminate algorithm */
#define HASH_ELIMINATE_ALGO_FIFO		(0) /* by default */
#define HASH_ELIMINATE_ALGO_LRU		(1)

/*
 * hash key compare function prototype, see hash_key_comp().
 * return value:
 *      0:key1 and key2 are equal;
 *  other:key1 and key2 not equal. 
 */
typedef int key_comp_fun_t(const uchar * key1, uint size1, const uchar * key2, uint size2);

/*
 * hash key->index computing function prototype, see hash_key2index().
 */
typedef uint key2index_fun_t(const MESA_htable_handle table, const uchar * key, uint size);

typedef long hash_cb_fun_t(void *data, const uchar *key, uint size, void *user_arg);

/*
 *	thread_safe: 0:create hashtable without thread safe features; 
 *                positive:the bigger number has more performance, but less timeout accuracy.
 *                         max number is 1024.
 *   recursive: 0:can't recursive call MESA_htable_xxx series function
 *			  1:can recursive call MESA_htable_xxx series function.
 * 	hash_slot_size: how big do you want the table to be, must be 2^N;
 *   max_elem_num: the maximum elements of the HASH-table,0 means infinite;
 * 	key_comp: hash key compare function, use default function if NULL;
 *			suggest implement by yourself.
 *  key2index: hash key->index computing function, use default function if NULL;
 *			suggest use MESA_htable built-in function.
 *  data_free: release resources function, only free attached data pointer if NULL;
 *  data_expire_with_condition: if expire_time > 0, call this function when a element expire, eliminate always if NULL;
 *				args:
 *					data: pointer to attached data;
 *					type: eliminate reason, ELIMINATE_TYPE_NUM or ELIMINATE_TYPE_TIME;
 *				return value of 'data_expire_with_condition':
 *					1: can be eliminated;
 *					0: can't be eliminated, renew the item.
 *  eliminate_type: the algorithm of elimanate a expired element, 0:FIFO; 1:LRU.
 *  expire_time: the element expire time in second, 0 means infinite.
 */
typedef struct{
	unsigned int thread_safe;
	int recursive;
	unsigned int hash_slot_size;
	unsigned int max_elem_num;
	int eliminate_type;
	int expire_time;
	key_comp_fun_t * key_comp; 
	key2index_fun_t * key2index;
	void (* data_free)(void *data);
	int (*data_expire_with_condition)(void *data, int type);
}MESA_htable_create_args_t;

/*
 * name: MESA_htable_create
 *	functionality: allocats memory for hash slots, and initialize hash structure;
 * param:
 *	args: argments set;
 *	args_len: length of argment set;
 * returns:
 * 	NULL 	: error;
 * 	Non-NULL : success;
 */
MESA_htable_handle MESA_htable_create(const MESA_htable_create_args_t *args, int args_struct_len);

/*
 * get total number of HASH element.
*/
unsigned int MESA_htable_get_elem_num(const MESA_htable_handle table);

/*
 * name: MESA_htable_destroy
 * functionality: cleans up hash structure, frees memory occupied;
 * param:
 * 	table: who is the victim;
 * 	func: callback function to clean up data attached to hash items;
 * returns:
 * 	always returns 0;
 */
int MESA_htable_destroy(MESA_htable_handle table, void (* func)(void *));

/*
 * name: MESA_htable_add
 * functionality: adds item to table, call hash_expire() if elem_count gets
 * 	bigger than threshold_hi, and adjust threshold;
 * param:
 * 	table: to which table do you want to add;
 * 	key: what is the label;
 * 	size: how long is the label;
 * 	data: what data do you want to attach;
 * returns:
 *	>0 success,return hash elems' linklist size
 * 	-1, duplicates found and can't add this one;
 * 	-2, memory failure;
 *   -3, other errors.
 */
int MESA_htable_add(MESA_htable_handle table, const uchar * key, uint size, const void *data);
#if 0
/*
 * name: hash_add_with_expire
 * functionality: adds item to table, than call hash_expire() on its list
 * param:
 * 	table: to which table do you want to add;
 * 	key: what is the label;
 * 	size: how long is the label;
 * 	data: what data do you want to attach;
 * returns:
 *	>0 success,return hash elems' linklist size
 * 	-1, duplicates found and can't add this one;
 * 	-2, memory failure;
 */
int MESA_hash_add_with_expire_v3(MESA_htable_inner_t * table, uchar * key, uint size, void * data);

#endif


/*
 * name: MESA_htable_del
 * functionality: deletes item from table.
 * param:
 * 	table: from which table do you want to delete;
 * 	key  : what is the label;
 * 	size : how long is the label;
 * 	func : callback function to clean up data attached to hash items,
 	       if this pointer is NULL will call "data_free" in MESA_hash_create(),
 * returns:
 * 	0, success;
 * 	-1, no such thing;
 */
int MESA_htable_del(MESA_htable_handle table, const uchar * key, uint size,
                                void (* func)(void *));

/*
 * name: MESA_htable_search
 * functionality: selects item from table;
 * param:
 * 	table: from which table do you want to select;
 * 	key  : what is the label;
 * 	size : how long is the label;
 *
 * return:
 *  not NULL :pointer to attached data;
 *  NULL 	 :not found(thus be careful if you are attaching NULL data on purpose).
 */
void *MESA_htable_search(const MESA_htable_handle table, const uchar * key, uint size);

/*
 * name: MESA_htable_search_cb
 * functionality: selects item from table, and then call 'cb', reentrant;
 * in param:
 * 	table: from which table do you want to select;
 * 	key  : what is the label;
 * 	size : how long is the label;
 *  cb   : call this function when found the attached data;
 *  arg  : the argument of "cb" function.
 * out param:
 *  cb_ret: the return value of the function "cb".
 * return:
 *  not NULL :pointer to attached data;
 *  NULL 	 :not found(thus be careful if you are attaching NULL data on purpose).
 */
void *MESA_htable_search_cb(const MESA_htable_handle table, const uchar * key, uint size,
                                                  hash_cb_fun_t *cb, void *arg, long *cb_ret);

/*
 * name: hash_iterate
 * functionality: iterates each hash item;
 * params:
 * 	table: what table is to be iterated;
 * 	func: what do you want to do to each attached data item;
 * returns:
 * 	0: iterates all items;
 * -1: error;
 */
int MESA_htable_iterate(MESA_htable_handle table, void (* func)(const uchar * key, uint size, void * data, void *user), void * user);

#if 0
/*
 * name: hash_expire
 * functionality: iterates each item and deletes those that are expired;
 * params:
 * 	table: what table do you want to check;
 * returns:
 * 	always 0;
 */
int MESA_hash_expire(MESA_htable_inner_t * table);
#endif


#ifdef __cplusplus
}
#endif

#endif	/* _LIB_HASH_H_INCLUDED_ */


