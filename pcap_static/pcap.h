/**
 *�ļ���pcap.h
 *���ܣ�����pcap�ļ����ͣ�ͳ�����������ͷ����б�Ŀǰֻ֧����̫����IPv4�����ݰ�ͳ��
 *���ߣ�����
 *��ϵ��zeng_xiax@163.com
 *ʱ�䣺2013-8-4 21:49:37
 */

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
typedef struct pcap_packet_header{
	TIMESTAMP time;
	uint pcaplen; //ץ���İ��ĳ���
	uint len;//ʵ�ʰ��ĳ���
}PCAP_PACKET_HEADER;
typedef struct timestamp
{
	uint sec;
	uint microsec;
}TIMESTAMP;

/**
 *
 */
#define MACADDR_LEN 6
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

int parseCapFile(IN char *pFilename, OUT IP_PACKET **pPackets);