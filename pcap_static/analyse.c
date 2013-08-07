#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap.h"
#include "analyse.h"


/**
 * @brief statTotalFlow 统计总流量变化
 *
 * @param pIpList 从pcap文件解析得到的数据结果
 * @param pTotalList
 *
 * @return 
 */
int statTotalFlow(IN IP_PACKET_LIST *pIpList, OUT TOTAL_FLOW_LIST *pTotalList)
{
	IP_PACKET *pPacket = NULL;
	TOTAL_FLOW *pOnePacket;

	if(NULL == pIpList || NULL == pTotalList)
	{
		DEBUGPRINT("NULL parameters\r\n");
		return ERROR_FAILED;
	}

	pTotalList->pHead = NULL;
	pTotalList->ppTail = &pTotalList->pHead;
	//处理第一个节点
	pPacket = pIpList->pHead;
	if(pPacket != *pIpList->pptail)
	{
		pOnePacket = (TOTAL_FLOW *)malloc(sizeof(TOTAL_FLOW));
		if(NULL == pOnePacket){
			DEBUGPRINT("malloc error.\r\n");
			return ERROR_FAILED;
		}
		memset(pOnePacket, 0, sizeof(TOTAL_FLOW));
		pOnePacket->next = NULL;
		pOnePacket->time = pPacket->time.sec;
		pOnePacket->bytes = pPacket->ip_len;
		pTotalList->pHead = pOnePacket;
		pTotalList->ppTail = &pOnePacket->next;
		pPacket = pPacket->next;
	}

	while(pPacket != *pIpList->pptail)
	{
		//单位是秒，同一秒内的数据合并在一起
		if(pOnePacket->time == pPacket->time.sec){
			pOnePacket->bytes += pPacket->ip_len;
		}else{
			pOnePacket = (TOTAL_FLOW *)malloc(sizeof(TOTAL_FLOW));
			if(NULL == pOnePacket){
				DEBUGPRINT("malloc error.\r\n");
				releaseTotalFlowList(pTotalList);
				
				return ERROR_FAILED;
			}
			memset(pOnePacket, 0, sizeof(TOTAL_FLOW));
			pOnePacket->next = NULL;
			pOnePacket->time = pPacket->time.sec;
			pOnePacket->bytes = pPacket->ip_len;
			*pTotalList->ppTail = pOnePacket;
			pTotalList->ppTail = &pOnePacket->next;
		}

		pPacket = pPacket->next;
	}

	return ERROR_SUCCESS;
}


/**
 * @brief releaseTotalFlowList 释放TOTAL_FLOW_LIST 类型链表的内存
 *
 * @param pTotalList
 */
void releaseTotalFlowList(INOUT TOTAL_FLOW_LIST *pTotalList){
	TOTAL_FLOW *pTotal = NULL;
	TOTAL_FLOW *pTemp = NULL;

	if(NULL == pTotalList){
		return;
	}

	pTotal = pTotalList->pHead;
	while(pTotal != *pTotalList->ppTail)
	{
		pTemp = pTotal->next;
		free(pTotal);
		pTotal = pTemp;
	}

	pTotalList->pHead = NULL;
	pTotalList->ppTail = &pTotalList->pHead;
}

void testTotalFlow(IN TOTAL_FLOW_LIST *pTotalList){
	TOTAL_FLOW *pTotal = NULL;

	FILE *pOut = fopen("totalflow.txt", "w");
	if(NULL == pOut){
		DEBUGPRINT("open file error.\r\n");
		return;
	}
	
	pTotal = pTotalList->pHead;
	while(pTotal != *pTotalList->ppTail)
	{
		fprintf(pOut, "%d\t%lu\r\n", pTotal->time, pTotal->bytes);
		printf("%d\t%lu\r\n", pTotal->time, pTotal->bytes);
		pTotal = pTotal->next;
	}
}
