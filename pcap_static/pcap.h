/**
 *�ļ���pcap.h
 *���ܣ�����pcap�ļ����ͣ�ͳ�����������ͷ����б�Ŀǰֻ֧����̫����IPv4�����ݰ�ͳ��
 *���ߣ�����
 *��ϵ��zeng_xiax@163.com
 *ʱ�䣺2013-8-4 21:49:37
 */
#ifndef __PCAP_H__
#define __PCAP_H__

#include <stdio.h>
#include "type.h"


#define LINKTYPE_ETHERNET 1
/**
 *pcap�ļ�ͷ��ʽ
 */
#define PCAP_FILE_HEADER_LEN 24
typedef struct pcap_file_header{
	uint magic;
	ushort version_major;
	ushort version_minor;
	uint timezone;
	uint sigfigs;
	uint snaplen;//ץ������󳤶�
	uint linktype;
}PCAP_FILE_HEADER;

/**
 *pcap�ļ������ݰ�ͷ��ʽ
 */
typedef struct timestamp
{
	uint sec;
	uint microsec;
}TIMESTAMP;
typedef struct pcap_packet_header{
	TIMESTAMP time;
	uint pcaplen; //ץ���İ��ĳ���
	uint len;//ʵ�ʰ��ĳ���
}PCAP_PACKET_HEADER;

/**
 *
 */
#define MACADDR_LEN 6
#define MACHEAD_LEN 14
#define TYPE_IP 0x0800
typedef struct mac_header
{
	uchar dest_mac[MACADDR_LEN];
	uchar src_mac[MACADDR_LEN];
	ushort type;
}MAC_HEADER;
/**
 *������Ҫ��IPԪ������Ϣ
 */
#define IPADDR_BYTES 4
#define PACKET_IN 1
#define PACKET_OUT 2
#define PACKET_LOCAL 3
#define MIN_IP_HEAD_LEN 20
#define IP_DATALEN_OFFSET 2
#define IP_SLICE_OFFSET 2
#define IP_PROTOCAL_OFFSET 1
#define IP_SRCIP_OFFSET 2
typedef struct ip_packet{
	TIMESTAMP time;
	short direct;
	ushort ip_len;
	ushort offset;
	ushort type;
	uchar src_ip[IPADDR_BYTES];
	uchar dest_ip[IPADDR_BYTES];
	struct ip_packet *next;
}IP_PACKET;
typedef struct ip_packet_list{
	IP_PACKET *pHead;
	IP_PACKET **pptail;
}IP_PACKET_LIST;

int parseCapFile(IN char *pFilename, OUT IP_PACKET_LIST *pPackets);
void releasePackets(IP_PACKET_LIST *packList);

void testPackList(IP_PACKET_LIST packList);
void testHton();
#endif
