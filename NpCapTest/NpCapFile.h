#pragma once
#include <string>
#include <functional>
#include <pcap.h>
class NpCapFile
{
public:
	NpCapFile() = default;
	NpCapFile(std::string file);
	NpCapFile(const NpCapFile& from);
	NpCapFile operator=(const NpCapFile& from);

	~NpCapFile();

	bool PrepareForRead();
	void FinishRead();

private:
	std::string file{};
	std::unique_ptr<pcap_t, std::function<void(pcap_t*)>> pcap;
};

