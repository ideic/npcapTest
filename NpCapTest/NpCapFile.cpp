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

bool NpCapFile::SetFilter(std::string filter)
{
	bpf_u_int32 NetMask = 0xffffff;
	struct bpf_program fcode;

	//compile the filter
	if (pcap_compile(pcap.get(), &fcode, filter.c_str(), 1, NetMask) < 0)
	{
		std::cerr << "Error compiling filter: wrong syntax." << std::endl;
		return false;
	}

	//set the filter
	if (pcap_setfilter(pcap.get(), &fcode) < 0)
	{
		std::cerr << "Error setting the filter" << std::endl;
		return false;
	}
	return false;
}
