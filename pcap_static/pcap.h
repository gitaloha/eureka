/**
 *文件：pcap.h
 *功能：解析pcap文件类型，统计网络流量和服务列表，目前只支持以太网和IPv4的数据包统计
 *作者：曾夏
 *联系：zeng_xiax@163.com
 *时间：2013-8-4 21:49:37
 */

#include <stdio.h>
#include "type.h"


#define LINKTYPE_ETHERNET 1
/**
 *pcap文件头格式
 */
#define PCAP_FILE_HEADER_LEN 24
typedef struct pcap_file_header{
	uint magic;
	ushort version_major;
	ushort version_minor;
	uint timezone;
	uint sigfigs;
	uint snaplen;//抓包的最大长度
	uint linktype;
}PCAP_FILE_HEADER;

/**
 *pcap文件的数据包头格式
 */
typedef struct pcap_packet_header{
	TIMESTAMP time;
	uint pcaplen; //抓到的包的长度
	uint len;//实际包的长度
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
 *分析需要的IP元数据信息
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