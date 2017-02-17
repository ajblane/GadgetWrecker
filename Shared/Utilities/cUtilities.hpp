

#ifndef C_UTILITIES_HPP
#define C_UTILITIES_HPP

#include <string>
#include <vector>
#include <map>

enum eExceptionType
{
	eWarning,
	eError,
	eCriticalError
};

class cUtilities
{
public:
	static std::wstring StringToWideString(const std::string& Input);
	static std::string WideStringToString(const std::wstring& Input);

	static std::vector<std::string> SplitString(std::string str, char Delim = ' ');

	static void WriteFileToDisk(const std::string& Path, const std::vector<uint8_t> Data);
	static std::vector<uint8_t> ReadFileFromDisk(const std::string& Path);

	static std::map<std::string, std::string> ParseArguments(int argc, char** argv);

	static std::string StringReplace(std::string &s, const std::string &toReplace, const std::string &replaceWith);
	static std::string ReplaceAll(std::string s, const std::string &toReplace, const std::string &replaceWith);

	static std::string FormatExceptionString(const std::string& File, const std::string Expression, eExceptionType ExceptionType = eError);

	static std::map<std::string, std::string> ParseArguments(char** argv, int argc);

	static std::string GenerateRandomData(std::vector<uint8_t> Bytes, int Length);
	static std::string GenerateRandomData(std::string Characters, int Length);

	static std::vector<std::string> GetAllFilesInDirectory(std::string Directory, std::vector<std::string> Extensions);
};

#endif
