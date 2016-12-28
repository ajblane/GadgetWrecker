
#ifndef C_NASM_WRAPPER_HPP
#define C_NASM_WRAPPER_HPP

#include <string>
#include <vector>
#include <map>

class cNasmWrapper
{
private:
	static std::vector<uint8_t> ReadFileFromDisk(const std::string & Filename);
	static bool WriteFileToDisk(const std::string & Filename, const std::vector<uint8_t>& FileData);
	static uint32_t AssembleData(const std::string& NasmPath, const std::string SourcePath, const std::string OutPath);

public:
	static std::string ConvertBinToNasmSource(const std::vector<uint8_t>& BinaryData);
	static std::vector<uint8_t> AssembleASMSource(const std::string Path, const std::string& Source);
};

#endif