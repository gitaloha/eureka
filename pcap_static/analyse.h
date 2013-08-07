#ifndef __ANALYSE_H__
#define __ANALYSE_H__

#include "type.h"
#include "pcap.h"
/*总流量统计结果的数据结构*/
typedef struct total_flow{
	unsigned int time;			//单位为：秒
	unsigned long bytes;
	struct total_flow *next;
}TOTAL_FLOW;
typedef struct total_flow_list{
	TOTAL_FLOW *pHead;
	TOTAL_FLOW **ppTail;
}TOTAL_FLOW_LIST;

int statTotalFlow(IN IP_PACKET_LIST *pIpList, OUT TOTAL_FLOW_LIST *pTotalList);
void releaseTotalFlowList(IN TOTAL_FLOW_LIST *pTotalList);
void testTotalFlow(IN TOTAL_FLOW_LIST *pTotalList);

#endif
