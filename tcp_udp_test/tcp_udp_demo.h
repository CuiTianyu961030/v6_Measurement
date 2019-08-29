
#include "MESA_prof_load.h"
#include "MESA_handle_logger.h"
#include "MAGELLAN_OPT.h"
#include "magellan_logger.h"
#include "MESA_htable.h"
#include "stream.h"
#include <arpa/inet.h>
#include <math.h>
#include <stdio.h>
#include <pthread.h>
#include "stream_inc/stream_project.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include<iostream>
#include "http.h"
using namespace std;
using namespace rapidjson;

#ifdef __cplusplus
extern "C"
{
#endif

int tcp_udp_demo_init();
void tcp_udp_demo_destroy();
char tcp_entry(const struct streaminfo* a_tcp,  void** pme, int thread_seq, const void* raw_pkt);
char udp_entry(const struct streaminfo* a_tcp,  void** pme, int thread_seq, const void* raw_pkt);
//char test_udp_entry(const struct streaminfo * a_udp, void ** pme, int thread_seq, void *raw_pkt);
#ifdef __cplusplus
}
#endif

