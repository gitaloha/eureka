#include "pcap.h"
#include "analyse.h"

int main()
{
	IP_PACKET_LIST list;
	TOTAL_FLOW_LIST totals;
	
	if(ERROR_FAILED == parseCapFile("test", &list))
	{
		printf("parse failed\r\n");
		return -1;
	}
	testPackList(list);
	//printf("%X\r\n", (int)list.pHead->next);
	statTotalFlow(&list, &totals);
	testTotalFlow(&totals);
	releaseTotalFlowList(&totals);
	releasePackets(&list);

	return 0;
}
