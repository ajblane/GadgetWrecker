#include <sstream>
#include <locale>
#include <codecvt>
#include <string>
#include <fstream>
#include <algorithm>
#include <thread>
#include <random>
#include <experimental\filesystem>

#include <Windows.h>

#include "cUtilities.hpp"

#define fs std::experimental::filesystem

inline std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems)
{
	std::stringstream ss(s);
	std::string item;
	while (std::getline(ss, item, delim)) {
		elems.push_back(item);
	}
	return elems;
}

inline std::vector<std::string> split(const std::string &s, char delim)
{
	std::vector<std::string> elems;
	split(s, delim, elems);
	return elems;
}

std::wstring cUtilities::StringToWideString(const std::string & Input)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(Input);
}

std::string cUtilities::WideStringToString(const std::wstring & Input)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(Input);
}

std::vector<std::string> cUtilities::SplitString(std::string str, char Delim)
{
	return split(str, Delim);
}

void cUtilities::WriteFileToDisk(const std::string & Path, const std::vector<uint8_t> Data)
{
	std::fstream f(Path, std::ios::binary | std::ios::out);

	if (f.good())
	{
		f.write((char*)Data.data(), Data.size());

		f.close();
	}
}

std::vector<uint8_t> cUtilities::ReadFileFromDisk(const std::string & Path)
{
	std::vector<uint8_t> Result;

	std::fstream f(Path, std::ios::binary | std::ios::in);

	if (f.good())
	{
		f.seekg(0, SEEK_END);
		size_t Length = f.tellg();
		f.seekg(0, SEEK_SET);

		Result.resize(Length);
		f.read((char*)Result.data(), Result.size());

		f.close();
	}

	return Result;
}

std::map<std::string, std::string> cUtilities::ParseArguments(int argc, char ** argv)
{
	std::map<std::string, std::string> Result;

	if(argc % 2 != 1)
		throw FormatExceptionString("cUtilities", "argc % 2 != 1");

	for (int i = 1; i < argc; i+=2)
		Result[argv[i]] = argv[i + 1];

	return Result;
}

std::string cUtilities::StringReplace(std::string &s, const std::string &toReplace, const std::string &replaceWith)
{
	return(s.replace(s.find(toReplace), toReplace.length(), replaceWith));
}

std::string cUtilities::ReplaceAll(std::string s, const std::string &toReplace, const std::string &replaceWith)
{
	while (s.find(toReplace) != std::string::npos)
		s = StringReplace(s, toReplace, replaceWith);

	return s;
}

std::string cUtilities::FormatExceptionString(const std::string & File, const std::string Expression, eExceptionType ExceptionType)
{
	if (ExceptionType == eWarning)
		return "Warning: " + File + " " + Expression + ": " + std::to_string(GetLastError());
	else if (ExceptionType == eError)
		return "Error: " + File + " " + Expression + ": " + std::to_string(GetLastError());
	else if(ExceptionType == eCriticalError)
		return "Critical Error: " + File + " " + Expression + ": " + std::to_string(GetLastError());

	return "Unkown error";
}

std::map<std::string, std::string> cUtilities::ParseArguments(char ** argv, int argc)
{
	std::map<std::string, std::string> Result;

	for (int i = 1; i + 1< argc; i += 2)
		Result[argv[i]] = argv[i + 1];

	return Result;
}

std::random_device Random;

std::string cUtilities::GenerateRandomData(std::vector<uint8_t> Bytes, int Length)
{
	std::string Result;
	
	std::uniform_int_distribution<size_t> aDistr(0, Bytes.size() - 1);

	for (int i = 0; i < Length; i++)
		Result += (char)Bytes[aDistr(Random)];

	return Result;
}

std::string cUtilities::GenerateRandomData(std::string Characters, int Length)
{
	return GenerateRandomData(std::vector<uint8_t>(Characters.begin(), Characters.end()), Length);
}

std::vector<std::string> cUtilities::GetAllFilesInDirectory(std::string Directory, std::vector<std::string> Extensions)
{
	std::vector<std::string> Result;

	fs::directory_iterator EndIterator;

	for (fs::directory_iterator aIt(Directory); aIt != EndIterator; aIt++)
	{
		if (fs::is_regular_file(*aIt))
		{
			if (Extensions.size() == 0)
				Result.push_back(aIt->path().string());
			else
			{
				for (auto x : Extensions)
				{
					if (aIt->path().extension().string() == x)
					{
						Result.push_back(aIt->path().string());
						break;
					}
				}
			}
		}
	}
	return Result;
}

