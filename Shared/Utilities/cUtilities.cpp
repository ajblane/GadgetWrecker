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

static inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

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

std::string cUtilities::Base64Encode(const std::string & Data)
{
	return Base64Encode(std::vector<uint8_t>(Data.begin(), Data.end()));
}

std::string cUtilities::Base64Encode(const std::vector<uint8_t>& Data)
{
	static const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";


	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	size_t in_len = Data.size();
	uint8_t *bytes_to_encode = (uint8_t*)Data.data();

	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i <4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';

	}

	return ret;
}

std::string cUtilities::Base64Decode(std::string const & s)
{
	static const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";


	int in_len = s.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;

	while (in_len-- && (s[in_] != '=') && is_base64(s[in_])) {
		char_array_4[i++] = s[in_]; in_++;
		if (i == 4) {
			for (i = 0; i <4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret += char_array_3[i];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j <4; j++)
			char_array_4[j] = 0;

		for (j = 0; j <4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	}

	return ret;
}

std::string cUtilities::Implode(std::vector<std::string> Data, std::string Delim)
{
	std::string Result = "";

	for (auto s : Data)
		Result += Base64Encode(s) + Delim;

	if (Result.size() > Delim.size() + 1)
		Result = Result.substr(0, Result.size() - Delim.size());

	return Result;
}

std::vector<std::string> cUtilities::Explode(std::string Data, std::string Delim)
{
	std::vector<std::string> Result;

	std::string TempData = "";

	for (size_t i = 0; i < Data.size();)
	{
		if (Data.substr(i, Delim.size()) == Delim)
		{
			Result.push_back(TempData);
			TempData = "";
			i += Delim.size();
		}
		else
		{
			TempData += Data[i];
			i++;
		}
	}

	if (TempData.size() > 0)
		Result.push_back(TempData);

	std::vector<std::string> RealResult;

	for (auto x : Result)
		RealResult.push_back(Base64Decode(x));

	return RealResult;
}

std::string cUtilities::ImplodeDict(std::map<std::string, std::string> Data, std::string Delim)
{
	if (Delim == " ")
		throw std::exception(cUtilities::FormatExceptionString("cUtilities", "Error: Illegal delimiter").c_str());

	std::string Result = "";

	for (auto s : Data)
		Result += Base64Encode(s.first) + " " + Base64Encode(s.second) + Delim;

	if (Result.size() > Delim.size() + 1)
		Result = Result.substr(0, Result.size() - Delim.size());

	return Result;
}

std::map<std::string, std::string> cUtilities::ExplodeDict(std::string Data, std::string Delim)
{
	if (Delim == " ")
		throw std::exception(cUtilities::FormatExceptionString("cUtilities", "Error: Illegal delimiter").c_str());

	std::map<std::string, std::string> Result;
		
	std::string TempPair = "";

	for (size_t i = 0; i < Data.size();)
	{
		if (Data.substr(i, Delim.size()) == Delim)
		{
			std::string Item1 = "";
			std::string Item2 = "";

			size_t Offset = TempPair.find(" ");

			if (Offset == std::string::npos)
				throw std::exception(cUtilities::FormatExceptionString("cUtilities", "Error: Offset == std::string::npos").c_str());

			Item1 = TempPair.substr(0, Offset);
			Item2 = TempPair.substr(Offset + 1);

			Result[cUtilities::Base64Decode(Item1)] = cUtilities::Base64Decode(Item2);
			TempPair = "";
			i += Delim.size();
		}
		else
		{
			TempPair += Data[i];
			i++;
		}
	}

	if (TempPair.size() > 1)
	{
		size_t Offset = TempPair.find(" ");

		if (Offset == std::string::npos)
			throw std::exception(cUtilities::FormatExceptionString("cUtilities", "Error: Offset == std::string::npos").c_str());

		std::string Item1 = TempPair.substr(0, Offset);
		std::string Item2 = TempPair.substr(Offset + 1);

		Result[cUtilities::Base64Decode(Item1)] = cUtilities::Base64Decode(Item2);
		TempPair = "";
	}


	return Result;
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

