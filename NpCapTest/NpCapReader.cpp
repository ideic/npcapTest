#include "pch.h"
#include "NpCapReader.h"
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string>
#include <tchar.h>
#include <iostream>
#include <vector>
#include "NpCapFile.h"
#include <algorithm>

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

	char errbuf[PCAP_ERRBUF_SIZE];

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
		std::cout << header->ts.tv_sec << ":"<< header->ts.tv_usec << " header len:" << header->len  <<" capture Len:" << header->caplen <<std::endl;

		///* Print the packet */
		//for (u_int i = 1; (i < header->caplen + 1); i++)
		//{
		//	std::cout << std::hex<< pkt_data[i - 1] << std::endl;
		//}
	}

	// clean up
	pcap_close(pcap);
}

bool NpCapReader::Compare(std::initializer_list<std::string> files)
{
	if (!LoadNpcapDlls())
	{
		std::cerr << "Couldn't load Npcap\n" << std::endl;
		return false;
	}

	std::vector<NpCapFile> npcapFiles;

	std::for_each(begin(files), end(files), [&](const auto &file) {
		npcapFiles.emplace_back(NpCapFile(file));
	});

	std::for_each(begin(npcapFiles), end(npcapFiles), [&](NpCapFile &npcapFile) {
		npcapFile.PrepareForRead();
	});

	auto result = true;
	for (size_t i = 0; i < npcapFiles.size()-1; ++i) {
		const u_char *pkt_data1 = nullptr;
		const u_char *pkt_data2 = nullptr;;

		bpf_u_int32 size1, size2;

	
		while ( npcapFiles[i].NextData(&pkt_data1, size1) && npcapFiles[i+1].NextData(&pkt_data2, size2)){
			if (size1 != size2 || memcmp(pkt_data1, pkt_data2, size1)) {
				result = false;
				break;
			}
		}
	};


	std::for_each(begin(npcapFiles), end(npcapFiles), [&](auto &reader) {
		reader.FinishRead();
	});

	return result;
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
