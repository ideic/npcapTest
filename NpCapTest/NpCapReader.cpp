#include "pch.h"
#include "NpCapReader.h"
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string>
#include <tchar.h>
#include <iostream>

NpCapReader::NpCapReader()
{
}


NpCapReader::~NpCapReader()
{
}

void NpCapReader::ReadFile(std::string fileName)
{
	if (!LoadNpcapDlls())
	{
		std::cerr << "Couldn't load Npcap\n" << std::endl;
		return;
	}

	//char source[PCAP_BUF_SIZE];
	char errbuf[PCAP_ERRBUF_SIZE];


	///*This function is required to create a source string that begins with a marker used to tell Npcap the type of the source, e.g. "rpcap://" if we are going to open an adapter, or "file://" if we are going to open a file.*/
	///* Create the source string according to the new Npcap syntax */
	//if (pcap_createsrcstr(source,			// variable that will keep the source string
	//	PCAP_SRC_FILE,	// we want to open a file
	//	NULL,			// remote host
	//	NULL,			// port on the remote host
	//	fileName,		// name of the file we want to open
	//	errbuf			// error buffer
	//) != 0)
	//{
	//	std:cerr << "\nError creating a source string\n" << std :: endl;
	//	return;
	//}

	pcap_t *pcap = pcap_open_offline(fileName.c_str(), errbuf);

	if (pcap == NULL) {
		std::cerr << "Error opening stream from :" <<  errbuf << std::endl;
		return;
	}

	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	while ((res = pcap_next_ex(pcap, &header, &pkt_data)) >= 0)
	{
		/* print pkt timestamp and pkt len */
		std::cout << header->ts.tv_sec << ":"<< header->ts.tv_usec << "len:" << header->len <<std::endl;

		///* Print the packet */
		//for (u_int i = 1; (i < header->caplen + 1); i++)
		//{
		//	std::cout << std::hex<< pkt_data[i - 1] << std::endl;
		//}
	}

	// clean up
	pcap_close(pcap);
}

bool NpCapReader::LoadNpcapDlls()
{
	TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return false;
	}
	_tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return false;
	}
	return true;
}
