/**
 *文件：pcap.h
 *功能：解析pcap文件类型，统计网络流量和服务列表，目前只支持以太网和IPv4的数据包统计
 *作者：曾夏
 *联系：zeng_xiax@163.com
 *时间：2013-8-4 21:49:37
 */
#ifndef __PCAP_H__
#define __PCAP_H__

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
typedef struct timestamp
{
	uint sec;
	uint microsec;
}TIMESTAMP;
typedef struct pcap_packet_header{
	TIMESTAMP time;
	uint pcaplen; //抓到的包的长度
	uint len;//实际包的长度
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
 *收集需要的TCP包头数据
 */
#define TCP_MIN_LEN 14
#define TCP_FIRST_FLAG 0x02
#define TCP_SECOND_FLAG 0x12
#define TCP_THIRD_FLAG 0x10
#define IS_FIRST_HANDING(flag)  (uchar)flag & TCP_FIRST_FLAG
#define IS_SECOND_HANDING(flag) (uchar)flag & TCP_SECOND_FLAG
#define IS_THIRD_HANDING(flag) (uchar)flag & TCP_THIRD_FLAG
#define TCP_FLAG_OFFSET 1
typedef struct tcp_packet{
	ushort src_port;
	ushort dest_port;
	uint seq_num;
	uint ack_num;
	uchar flag;
}TCP_PACKET;
/**
 *收集需要的IP数据信息
 */
#define IPv4 0X40
#define IPv6 0x60
#define IPADDR_BYTES 4
#define IPADDRv6_BYTES 16
#define PACKET_IN 1
#define PACKET_OUT 2
#define PACKET_LOCAL 3
#define MIN_IP_HEAD_LEN 20
#define MIN_IPv6_HEAD_LEN 40
#define IP_DATALEN_OFFSET 1
#define IP_SLICE_OFFSET 2
#define IP_PROTOCAL_OFFSET 1
#define IP_SRCIP_OFFSET 2
#define IPv6_DATALEN_OFFSET 3
#define IPv6_SRC_OFFSET 1
#define IP_TYPE_TCP 6
typedef union ip_addr{
	uchar ip4[IPADDR_BYTES];
	ushort ip6[IPADDRv6_BYTES/2];
}IP_ADDR;
typedef struct ip_packet{
	TIMESTAMP time;
	short direct;
	ushort ip_len;
	ushort offset;
	ushort type;
	uchar ip_version;
	IP_ADDR src_ip;
	IP_ADDR dest_ip;
	struct ip_packet *next;
	TCP_PACKET *pTcpPacket;
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
