#include "pch.h"
#include "NpCapFile.h"
#include <pcap.h>
#include <iostream>


NpCapFile::NpCapFile(std::string file): file(file)
{
}

NpCapFile::NpCapFile(const NpCapFile & from): file(from.file)
{

}

NpCapFile NpCapFile::operator=(const NpCapFile & from)
{
	return NpCapFile(file);
}


NpCapFile::~NpCapFile()
{
}

bool NpCapFile::PrepareForRead()
{
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap = { pcap_open_offline(file.c_str(), errbuf), [](auto *pcapParam) {
		std::cout << "Close Pcap" << std::endl;
		pcap_close(pcapParam); 
	} };

	if (pcap.get() == nullptr) {
		std::cerr << "Error opening stream from :" << errbuf << std::endl;
		return false;
	}

	return true;
}

void NpCapFile::FinishRead()
{
	pcap.reset();
}

const bool NpCapFile::NextData(const u_char **pkt_data, bpf_u_int32 &size)
{
	struct pcap_pkthdr *header;
	size = 0;
	int res;
	if (res = (pcap_next_ex(pcap.get(), &header, pkt_data)) >= 0)
	{
		size = header->caplen;
		return true;
	}
	if (res < 0) {
		std::cerr << "Error reading the packets: " << pcap_geterr(pcap.get()) << std::endl;
	}
	return false;
}
