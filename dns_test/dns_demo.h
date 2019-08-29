
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
#include "dns_analyse.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include<iostream>

using namespace rapidjson;
#ifdef __cplusplus
extern "C"
{
#endif

int dns_demo_init();
void dns_demo_destroy();
char dns_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet);
//char test_udp_entry(const struct streaminfo * a_udp, void ** pme, int thread_seq, void *raw_pkt);
#ifdef __cplusplus
}
#endif

