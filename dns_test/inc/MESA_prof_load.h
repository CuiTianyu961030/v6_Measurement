#ifndef SLIB_LOADPROF_H
#define SLIB_LOADPROF_H
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif


// Read in specified integer value
//
// Return:
//	   0 : success
//	<  0 : error, val is set to default
int MESA_load_profile_int_def(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	const char *key,	// [IN] keyword name in initialization file
	int *val,	// [OUT] returned value
	const int dval);	// [IN] default value



// Read in specified integer value
//
// Return:
//	0 : success
//	-1 : failed to get the key,may be have no thie section, key or the val which the key pointed error
//	-2 : error ,the val if out of range
int MESA_load_profile_int_nodef(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	const char *key,	// [IN] keyword name in initialization file
	int *val);	// [OUT] returned value




// Read in specified unsigned integer value
//
// Return:
//	   0 : success
//	<  0 : error, val is set to default
int MESA_load_profile_uint_def(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	const char *key,	// [IN] keyword name in initialization file
	unsigned int *val,	// [OUT] returned value
	const unsigned int dval);	// [IN] default value



// Read in specified unsigned integer value
//
// Return:
//	0 : success
//	-1 : failed to get the key,may be have no thie section, key or the val which the key pointed error
//	-2 : error ,the val if out of range
int MESA_load_profile_uint_nodef(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	const char *key,	// [IN] keyword name in initialization file
	unsigned int *val);	// [OUT] returned value



// Read in specified short integer value
//
// Return:
//	   0 : success
//	<  0 : error, val is set to default
int MESA_load_profile_short_def(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	const char *key,	// [IN] keyword name in initialization file
	short *val,	// [OUT] returned value
	const short dval);    // [IN] default value


 
// Read in specified short integer value
//
// Return:
//	0 : success
//	-1 : failed to get the key,may be have no thie section, key or the val which the key pointed error
//	-2 : error ,the val if out of range
int MESA_load_profile_short_nodef(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	const char *key,	// [IN] keyword name in initialization file
	short *val);	// [OUT] returned value



// Read in specified string value,
// if value string is too long to return, extra chars truncated.
// prefix/postfix space chars cutted,
// space chars: ' ', '\t' '\n' '\r'
//
// Return:
//	>= 0 : length of val
//	  -1 : failed to get the key,may be have no thie section, key or the val which the key pointed error

int MESA_load_profile_string_nodef(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	const char *key,	// [IN] keyword name in initialization file
	char *str,	// [OUT] returned string
	const size_t size);	// [IN] buffer size(bytes)



// Read in specified string value,
// if value string is too long to return, extra chars truncated.
// prefix/postfix space chars cutted,
// space chars: ' ', '\t' '\n' '\r'
//
// Return:
//	>= 0 : length of val
//	<  0 : error, str is set to default
int MESA_load_profile_string_def(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	const char *key,	// [IN] keyword name in initialization file
	char *str,	// [OUT] returned string
	const size_t size,	// [IN] buffer size(bytes)
	const char *dstr);	// [IN] default string



//read ips from config file
//return :
// 	>=0 : success,return the number of ip read from file successfully
// 	-1  : failed to get the key,may be have no thie section, key or the val which the key pointed error
//	-2  : error,invalid ip

#if 0
int MESA_load_profile_ipset(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	const char *key,	// [IN] keyword name in initialization file
	const size_t size,  // [IN] the size of memory ips point,it must equel or greater than ip_num*sizeof(unsigned int)
	unsigned int *ipset); 	// [OUT] return ipset network bytes order

// Write the a int into specified position of the config file,the position is decided by section and key
// Return:
//	>= 0 : success
//	  -1 : failed to write profile,maybe fopen failed, or malloc failed 
int MESA_write_profile_int(
	const char *file,	// [IN] initialization file path
	const char *section,  // [IN] section name in initialization file
	const char *key,   // [IN] keyword name in initialization file
	const int value);    // [IN] the integer need write 

// Write the a float into specified position of the config file,the position is decided by section and key
// Return:
//	>= 0 : success
//	  -1 : failed to write profile,maybe fopen failed, or malloc failed 
int MESA_write_profile_float(
	const char *file,	// [IN] initialization file path
	const char *section,  // [IN] section name in initialization file
	const char *key,   // [IN] keyword name in initialization file
	const float value);    // [IN] the float need write 

// Write the a string into specified position of the config file,the position is decided by section and key
// Return:
//	>= 0 : success
//	  -1 : failed to write profile,maybe fopen failed, or malloc failed 
int MESA_write_profile_string(
	const char *file,	// [IN] initialization file path
	const char *section,  // [IN] section name in initialization file
	const char *key,   // [IN] keyword name in initialization file
	const char *value);    // [IN] the string need write 
#endif
#ifdef __cplusplus
}
#endif

#endif /* #ifndef SLIB_LOADPROF_H */
