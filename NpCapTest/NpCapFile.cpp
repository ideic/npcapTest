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

	pcap = { pcap_open_offline(file.c_str(), errbuf), [](auto *pcapParam) {pcap_close(pcapParam); } };

	if (pcap.get() == nullptr) {
		std::cerr << "Error opening stream from :" << errbuf << std::endl;
		return false;
	}

	return true;
}

void NpCapFile::FinishRead()
{
	pcap.release();
}
