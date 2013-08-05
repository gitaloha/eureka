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
	uchar ucTemp;
	ushort usTemp;
	uint uiTemp;
	uint packLen;
	IP_PACKET *pPrePacket;

	
	if(!(pIn = fopen(pFilename, "r")))
	{
		return ERROR_FAILED;
	}
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
	pPacketList->pptail =  &pPacket->next;
	pPrePacket = NULL;

	do
	{
		result = ERROR_FAILED;
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
			continue;
		}
		
		fseek(pIn, MACHEAD_LEN, SEEK_CUR);
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
		result *= fread(pPacket->src_ip, sizeof(pPacket->src_ip), 1, pIn);
		result *= fread(pPacket->dest_ip, sizeof(pPacket->dest_ip), 1, pIn);

		fseek(pIn, packLen-MACHEAD_LEN-MIN_IP_HEAD_LEN, SEEK_CUR);


		if(!result){
			DEBUGPRINT("dump a error packet\r\n");
			if(pPacketList->pHead == pPacket)
			{
				pPacketList->pHead = NULL;
				pPacketList->pptail = &pPacketList->pHead;
			}else{
				pPacketList->pptail = &pPrePacket->next;
			}
			free(pPacket);
			return ERROR_SUCCESS;
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
		pPacketList->pptail = &pPacket->next;
	}while (!feof(pIn));

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
		free(pPacket);
		pPacket = pPacketList->pHead;
	}
	pPacketList->pHead = NULL;
	pPacketList->pptail = &pPacketList->pHead;
}

void testPackList(IP_PACKET_LIST packList){
	FILE *pOut = fopen("ouput.txt", "w");
	if(NULL == pOut){
		printf("fopen error\r\n");
		return ;
	}

	IP_PACKET *pPacket = packList.pHead;
	while(pPacket != *packList.pptail){
		printf("%d:%d  %3d:%3d:%3d:%3d to %3d:%3d:%3d:%3d %5d %d\r\n", pPacket->time.sec,
				pPacket->time.microsec, pPacket->src_ip[0], pPacket->src_ip[1],
				pPacket->src_ip[2], pPacket->src_ip[3], pPacket->dest_ip[0], pPacket->dest_ip[1],
				pPacket->dest_ip[2], pPacket->dest_ip[3], pPacket->ip_len, pPacket->type);
		fprintf(pOut, "%d:%d  %3d:%3d:%3d:%3d to %3d:%3d:%3d:%3d %5d %d\r\n", pPacket->time.sec,
				pPacket->time.microsec, pPacket->src_ip[0], pPacket->src_ip[1],
				pPacket->src_ip[2], pPacket->src_ip[3], pPacket->dest_ip[0], pPacket->dest_ip[1],
				pPacket->dest_ip[2], pPacket->dest_ip[3], pPacket->ip_len, pPacket->type);
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
