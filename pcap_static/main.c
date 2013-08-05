#include "pcap.h"

int main()
{
	IP_PACKET_LIST list;
	
	testHton();
	if(ERROR_FAILED == parseCapFile("network.cap", &list))
	{
		printf("parse failed\r\n");
		return -1;
	}
	releasePackets(&list);

	return 0;
}
