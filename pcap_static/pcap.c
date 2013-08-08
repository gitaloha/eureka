#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pcap.h"
#include "type.h"


/**
 * @brief isBigEnd 判断系统是否是大端系统
 *
 * @return 
 */
static int isBigEnd()
{
	short s = 0x1234;
	char *pc = (char *)&s;
	if(*pc == 0x12){
		return TRUE;
	}
	else{
		return FALSE;
	}
}


inline static ushort hton16(IN ushort us){
	if(isBigEnd())
	{
		return us;
	}
	return ((us & 0xFF00)>>8) | ((us & 0x00FF) << 8);
}
inline static uint hton32(IN uint ui)
{
	if(isBigEnd())
	{
		return ui;
	}

	return ((ui & 0xFF000000) >> 24) |
		((ui & 0x00FF0000) >> 8) |
		((ui & 0x0000FF00) << 8) |
		((ui & 0x000000FF) << 24);
}

/**
 * @brief parseCapFile 解析pcap文件，提取IP数据包的元数据到pPacketList链表中
 *
 * @param pFilename pcap文件的路径
 * @param pPacketList  解析结果存放的链表
 *
 * @return 成功返回ERROR_SUCCESS,失败返回ERROR_FAILED
 */
int parseCapFile(IN char *pFilename, OUT IP_PACKET_LIST *pPacketList)
{
	FILE *pIn =  NULL;
	int result;
	long lTemp;
	long fileLength;
	uchar ucTemp;
	ushort usTemp;
	uint uiTemp;
	uint packLen;
	uchar ipHeadLen;
	uchar tcpHeadLen;
	IP_PACKET *pPrePacket;


	if(!(pIn = fopen(pFilename, "r")))
	{
		return ERROR_FAILED;
	}
	fseek(pIn, 0, SEEK_SET);
	fseek(pIn, 0, SEEK_END);
	fileLength = ftell(pIn);

	fseek(pIn, PCAP_FILE_HEADER_LEN, SEEK_SET);

	IP_PACKET *pPacket = (IP_PACKET *)malloc(sizeof(IP_PACKET));
	if(NULL == pPacket)
	{
		DEBUGPRINT("malloc error!\r\n");
		return ERROR_FAILED;
	}
	memset(pPacket, 0, sizeof(IP_PACKET));

	pPacketList->pHead = pPacket;
	pPacket->next = NULL;
	pPacket->pTcpPacket = NULL;
	pPacketList->pptail =  &pPacket->next;
	pPrePacket = NULL;

	int i, j;
	do
	{
		++j;
		result = 1;
		if(ftell(pIn) > fileLength)
		{
			DEBUGPRINT("ftell error\r\n");
			result = 0;
		}
		//读取包头
		result *= fread(&uiTemp, sizeof(uiTemp), 1, pIn);
		pPacket->time.sec = uiTemp;
		//pPacket->time.sec = hton32(uiTemp);
		result *= fread(&uiTemp, sizeof(uiTemp), 1, pIn);
		pPacket->time.microsec = uiTemp;
		//pPacket->time.microsec = hton32(uiTemp);
		result *= fread(&uiTemp, sizeof(uiTemp), 1, pIn);
		//packLen = hton32(uiTemp);
		packLen = uiTemp;
		result *= fread(&uiTemp, sizeof(uiTemp), 1, pIn);

		if(packLen < MIN_IP_HEAD_LEN+MACHEAD_LEN)
		{
			DEBUGPRINT("ftell.\r\n");
			result = 0;
		}

		//跳过MAC头部
		fseek(pIn, MACHEAD_LEN, SEEK_CUR);

		//读取IP数据
		result *=fread(&ucTemp, sizeof(ucTemp), 1, pIn);
		if(IPv6 == (ucTemp & 0xF0)){
			pPacket->ip_version = IPv6;
			fseek(pIn, IPv6_DATALEN_OFFSET, SEEK_CUR);
			result *= fread(&usTemp, sizeof(usTemp), 1, pIn);
			pPacket->ip_len = hton16(usTemp);
			result *= fread(&ucTemp, sizeof(ucTemp), 1, pIn);
			pPacket->type = ucTemp;
			fseek(pIn, IPv6_SRC_OFFSET, SEEK_CUR);
			result *= fread(pPacket->src_ip.ip6, sizeof(pPacket->src_ip.ip6), 1, pIn);	
			result *= fread(pPacket->dest_ip.ip6, sizeof(pPacket->dest_ip.ip6), 1, pIn);
			for(i=0; i<IPADDRv6_BYTES/2; i++)
			{
				pPacket->src_ip.ip6[i] = hton16(pPacket->src_ip.ip6[i]);
				pPacket->dest_ip.ip6[i] = hton16(pPacket->dest_ip.ip6[i]);
			}
			ipHeadLen = MIN_IPv6_HEAD_LEN;
		}else if(IPv4 == (ucTemp & 0xF0)){
			pPacket->ip_version = IPv4;
			ipHeadLen = (ucTemp & 0x0F) * 4;
			fseek(pIn, IP_DATALEN_OFFSET, SEEK_CUR);
			result *= fread(&usTemp, sizeof(usTemp), 1, pIn);
			pPacket->ip_len = hton16(usTemp);
			fseek(pIn, IP_SLICE_OFFSET, SEEK_CUR);
			result *= fread(&usTemp, sizeof(usTemp), 1, pIn);
			usTemp = usTemp & 0x1FFF;
			pPacket->offset = hton16(usTemp);
			fseek(pIn, IP_PROTOCAL_OFFSET, SEEK_CUR);
			result *= fread(&ucTemp, sizeof(ucTemp), 1, pIn);
			pPacket->type = ucTemp;
			fseek(pIn, IP_SRCIP_OFFSET, SEEK_CUR);
			result *= fread(pPacket->src_ip.ip4, sizeof(pPacket->src_ip.ip4), 1, pIn);
			result *= fread(pPacket->dest_ip.ip4, sizeof(pPacket->dest_ip.ip4), 1, pIn);
			fseek(pIn, ipHeadLen - MIN_IP_HEAD_LEN, SEEK_CUR);
		}else{
			fseek(pIn, packLen-MACHEAD_LEN-1, SEEK_CUR);
			if(fileLength < ftell(pIn))
			{
				DEBUGPRINT("ftell \r\n");
				result = 0;
			}
			DEBUGPRINT("no ip packet!\r\n");
			if(result){
				continue;
			}
		}

		//读取TCP数据
		if(IP_TYPE_TCP == pPacket->type  &&  0!=result){
			TCP_PACKET *pTcpPacket = (TCP_PACKET *)malloc(sizeof(TCP_PACKET));
			if(NULL == pTcpPacket){
				releasePackets(pPacketList);
				DEBUGPRINT("malloc error!\r\n");

				return ERROR_FAILED;
			}
			result *= fread(&usTemp, sizeof(usTemp), 1, pIn);
			pTcpPacket->src_port = hton16(usTemp);
			result *= fread(&usTemp, sizeof(usTemp), 1, pIn);
			pTcpPacket->dest_port = hton16(usTemp);
			result *= fread(&uiTemp, sizeof(uiTemp), 1, pIn);
			pTcpPacket->seq_num = hton32(uiTemp);
			result *= fread(&uiTemp, sizeof(uiTemp), 1, pIn);
			pTcpPacket->ack_num = hton32(uiTemp);
			result *= fread(&ucTemp, sizeof(ucTemp), 1, pIn);
			tcpHeadLen = ucTemp & 0xF0;
			tcpHeadLen *= 4;
			result *= fread(&ucTemp, sizeof(ucTemp), 1, pIn);
			pTcpPacket->flag = ucTemp & 0x0F;
			pPacket->pTcpPacket = pTcpPacket;

			fseek(pIn, packLen-MACHEAD_LEN-ipHeadLen-TCP_MIN_LEN, SEEK_CUR);
		}else
		{
			fseek(pIn, packLen-MACHEAD_LEN-ipHeadLen, SEEK_CUR);
			if(fileLength < ftell(pIn))
			{
				result = 0;
			}
		}

		//文件格式错误，丢弃最后一个错误的包
		if(!result){
			DEBUGPRINT("dump a error packet!!\r\n");
			if(NULL == pPrePacket)
			{
				pPacketList->pHead = NULL;
				pPacketList->pptail = &pPacketList->pHead;
			}else{
				pPacketList->pptail = &pPrePacket->next;
			}
			free(pPacket);
			break;
		}

		pPrePacket = pPacket;
		pPacket = (IP_PACKET *)malloc(sizeof(IP_PACKET));
		if(NULL == pPacket){
			releasePackets(pPacketList);
			DEBUGPRINT("malloc error!\r\n");

			return ERROR_FAILED;
		}
		memset(pPacket, 0, sizeof(IP_PACKET));
		*pPacketList->pptail = pPacket;
		pPacket->next = NULL;
		pPacket->pTcpPacket = NULL;
		pPacketList->pptail = &pPacket->next;
	}while (!feof(pIn));
	printf("count:%d\r\n", j);

	fclose(pIn);

	return ERROR_SUCCESS;
}


/**
 * @brief releasePackets 释放packList内存
 *
 * @param packList
 *
 * @return 
 */
void releasePackets(IP_PACKET_LIST *pPacketList)
{
	IP_PACKET *pPacket = pPacketList->pHead;
	testPackList(*pPacketList);
	while(pPacket != *pPacketList->pptail){
		pPacketList->pHead = pPacket->next;
		if(NULL != pPacket->pTcpPacket)
		{
			free(pPacket->pTcpPacket);
			pPacket->pTcpPacket = NULL;
		}
		free(pPacket);
		pPacket = pPacketList->pHead;
	}
	pPacketList->pHead = NULL;
	pPacketList->pptail = &pPacketList->pHead;
}

void testPackList(IP_PACKET_LIST packList){
	int i;
	FILE *pOut = fopen("ip.txt", "w");
	FILE *pOut3 = fopen("ipv6.txt", "w");
	FILE *pOut2 = fopen("tcp.txt", "w");
	if(NULL == pOut || NULL == pOut2){
		printf("fopen error\r\n");
		return ;
	}

	IP_PACKET *pPacket = packList.pHead;
	while(pPacket != *packList.pptail){

		if(IPv4 == pPacket->ip_version)
		{
			fprintf(pOut, "%d:%d  %3d.%3d.%3d.%3d to %3d.%3d.%3d.%3d %5d %d\r\n", 
					pPacket->time.sec,pPacket->time.microsec, pPacket->src_ip.ip4[0], 
					pPacket->src_ip.ip4[1], pPacket->src_ip.ip4[2], pPacket->src_ip.ip4[3], 
					pPacket->dest_ip.ip4[0], pPacket->dest_ip.ip4[1],pPacket->dest_ip.ip4[2], 
					pPacket->dest_ip.ip4[3], pPacket->ip_len, pPacket->type);
			if(pPacket->pTcpPacket)
			{
				fprintf(pOut2, "%3d.%3d.%3d.%3d:%d => %3d.%3d.%3d.%3d:%d\r\n",pPacket->src_ip.ip4[0],
						pPacket->src_ip.ip4[1], pPacket->src_ip.ip4[2], pPacket->src_ip.ip4[3], 
						pPacket->pTcpPacket->src_port, pPacket->dest_ip.ip4[0], pPacket->dest_ip.ip4[1], 
						pPacket->dest_ip.ip4[2], pPacket->dest_ip.ip4[3],pPacket->pTcpPacket->dest_port);
			}
		}else
		{	
			fprintf(pOut3, "%d:%d \t", pPacket->time.sec, pPacket->time.microsec);
			for(i=0; i<IPADDRv6_BYTES/2-1; i++)
			{
				fprintf(pOut3, "%X.", pPacket->src_ip.ip6[i]);
			}
			fprintf(pOut3, "%X => ", pPacket->src_ip.ip6[i]);
			for(i=0; i<IPADDRv6_BYTES/2-1; i++)
			{
				fprintf(pOut3, "%X.", pPacket->dest_ip.ip6[i]);
			}
			fprintf(pOut3, "%X\r\n", pPacket->dest_ip.ip6[i]);
			/*
			   fprintf(pOut3, "%d:%d  %X.%X.%X.%X.%X.%X to %X.%X.%X.%X.%X.%X %5d %d\r\n", pPacket->time.sec,
			   pPacket->time.microsec, pPacket->src_ip.ip6[0], pPacket->src_ip.ip6[1],
			   pPacket->src_ip.ip6[2], pPacket->src_ip.ip6[3], pPacket->src_ip.ip6[4], 
			   pPacket->src_ip.ip6[5], pPacket->dest_ip.ip4[0], pPacket->dest_ip.ip4[1],
			   pPacket->dest_ip.ip4[2], pPacket->dest_ip.ip4[3], pPacket->dest_ip.ip6[4], 
			   pPacket->src_ip.ip6[5], pPacket->ip_len, pPacket->type);
			   */
			if(pPacket->pTcpPacket)
			{
				for(i=0; i<IPADDRv6_BYTES/2; i++)
				{
					fprintf(pOut3, "%X.", pPacket->src_ip.ip6[i]);
				}
				fprintf(pOut3, "%X:%d => ", pPacket->src_ip.ip6[i], pPacket->pTcpPacket->src_port);
				for(i=0; i<IPADDRv6_BYTES/2; i++)
				{
					fprintf(pOut3, "%X.", pPacket->dest_ip.ip6[i]);
				}
				fprintf(pOut3, "%X:%d => ", pPacket->dest_ip.ip6[i], pPacket->pTcpPacket->dest_port);
				/*
				   fprintf(pOut2, " %X.%X.%X.%X.%X.%X:%d to %X.%X.%X.%X.%X.%X:%d\r\n",pPacket->src_ip.ip6[0], 
				   pPacket->src_ip.ip4[1], pPacket->src_ip.ip4[2], pPacket->src_ip.ip4[3], 
				   pPacket->src_ip.ip4[4], pPacket->src_ip.ip4[5], pPacket->pTcpPacket->src_port,
				   pPacket->dest_ip.ip6[0], pPacket->dest_ip.ip6[1], pPacket->dest_ip.ip6[2], 
				   pPacket->dest_ip.ip6[3], pPacket->dest_ip.ip6[4], pPacket->dest_ip.ip6[5],
				   pPacket->pTcpPacket->dest_port);*/
			}
		}
		pPacket = pPacket->next;
	}
	fclose(pOut);
}
void testHton()
{
	ushort us = 0x3412;
	uint ui = 0x78563412;
	printf("%X\r\n", hton16(us));
	printf("%x\n", hton32(ui));
	return ;
}
