#include "pch.h"
#include "NpCapReader.h"
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string>
#include <tchar.h>

NpCapReader::NpCapReader()
{
}


NpCapReader::~NpCapReader()
{
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
