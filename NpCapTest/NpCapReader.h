#pragma once
#include <string>
class NpCapReader
{
	public:
		NpCapReader();
		~NpCapReader();
		void ReadFile(std::string fileName);

		bool Compare(std::initializer_list<std::string> files);
	private:
		bool LoadNpcapDlls();
};

