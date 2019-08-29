#ifndef _APP_STREAM_H_
#define _APP_STREAM_H_           

#include "stream_inc/stream_base.h"
#include "stream_inc/stream_proxy.h"
#include "stream_inc/stream_project.h"
#include "stream_inc/stream_inject.h"
#include "stream_inc/stream_control.h"
#include "stream_inc/stream_entry.h"
#include "stream_inc/stream_rawpkt.h"

#define STREAM_H_VERSION		(20150104)

#define STREAM_BASE_MD5		"a0b1401145663b3079c9d0c25044ae70"
#define STREAM_CONTROL_MD5 	"ccdb2d8089a9d2568f9269f3b4aef751"
#define STREAM_ENTRY_MD5		"4247a86972abd02ecbbe4cc960323bd2"
#define STREAM_INJECT_MD5		"182f48639cbd340ec26321b960e29e46"
#define STREAM_PROJECT_MD5	"75a0d392850e7fd963e6cee993fe0dd1"
#define STREAM_PROXY_MD5		"2261f41264098f9a83475a6e8ef01e1a"
#define STREAM_RAWPKT_MD5	"c9c517ca0593f9c9df95928e5cef4c7d"

#endif

/***********************************************************************************
	Update log:
	2015-01-04 lijia, 
		�޸�stream_base.h, ��pkttype�ƶ���struct layer_addr�ṹ��, 
		��routedir��չΪuchar����;
		����MESA_dir_reverse()����, ���ڷ���ʱ����routedir.
		stream.h���Ӱ汾�ź�MD5��ֵ֤.

	2014-12-30 lqy,
		��ԭstream.h�����������Ϊ7��stream_xxx.h, 
		��ƽ̨�ڲ���������, public���ͶԲ���ɼ�, privateΪ�ڲ�ʹ�ö��ⲻ�ɼ�.
*************************************************************************************/

