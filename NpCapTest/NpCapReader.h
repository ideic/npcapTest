#pragma once
#include <string>
class NpCapReader
{
	public:
		NpCapReader();
		~NpCapReader();
		void ReadFile(std::string fileName);
	private:
		bool LoadNpcapDlls();
};

