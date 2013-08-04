#include <stdio.h>

#include "pcap.h"


/**
 *pPackets
 */
int parseCapFile(IN char *pFilename, OUT IP_PACKET **pPackets)
{
	FILE *pIn =  NULL;

	
	if(!(pIn = fopen(pFilename, "r")))
	{
		return ERROR_FALSE;
	}
	fseek(pIn, PCAP_FILE_HEADER_LEN, SEEK_SET);
	while (!feof(pIn))
	{
		fseek(pIn, MACADDR_LEN, SEEK_CUR);
	}
}