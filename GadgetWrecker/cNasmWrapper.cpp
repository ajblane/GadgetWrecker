
#include <fstream>

#include <Windows.h>

#include "cNasmWrapper.hpp"

std::vector<uint8_t> cNasmWrapper::ReadFileFromDisk(const std::string & Filename)
{
	std::vector<uint8_t> Result;

	std::fstream f(Filename, std::ios::binary | std::ios::in);

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

bool cNasmWrapper::WriteFileToDisk(const std::string & Filename, const std::vector<uint8_t>& FileData)
{
	std::fstream f(Filename, std::ios::binary | std::ios::out);

	if (f.good())
	{
		f.write((char*)FileData.data(), FileData.size());
		f.close();

		return true;
	}

	return false;
}

uint32_t cNasmWrapper::AssembleData(const std::string & NasmPath, const std::string SourcePath, const std::string OutPath)
{
	HANDLE _hProcess = INVALID_HANDLE_VALUE;

	PROCESS_INFORMATION PI = {};
	STARTUPINFOA SI = {};
	SECURITY_ATTRIBUTES SA = {};

	SA.bInheritHandle = TRUE;
	SA.lpSecurityDescriptor = NULL;
	SA.nLength = sizeof(SECURITY_ATTRIBUTES);

	SI.cb = sizeof(STARTUPINFOA);
	SI.dwFlags |= STARTF_USESHOWWINDOW;
	SI.wShowWindow = 0;

	std::string  CommandLine = "nasm.exe -o \"" + OutPath + "\" \"" + SourcePath + "\"";

	if (!CreateProcessA(NasmPath.c_str(), (LPSTR)CommandLine.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &SI, &PI))
		throw "Error: !CreateProcessA: " + std::to_string(GetLastError());

	_hProcess = PI.hProcess;
	CloseHandle(PI.hThread);

	WaitForSingleObject(_hProcess, INFINITE);

	uint32_t ExitCode = 0;

	GetExitCodeProcess(_hProcess, (LPDWORD)&ExitCode);

	CloseHandle(_hProcess);

	return ExitCode;
}

std::string cNasmWrapper::ConvertBinToNasmSource(const std::vector<uint8_t>& BinaryData)
{
	char Buffer[50] = {};
	std::string Result = "db ";

	size_t Counter = 1;

	for (auto x : BinaryData)
	{
		if (Counter++ == 32)
		{
			Counter = 1;
			sprintf_s(Buffer, "0x%.2x\ndb ", x);
		}
		else
		{
			sprintf_s(Buffer, "0x%.2x, ", x);
		}

		Result += Buffer;
	}

	Result = Result.substr(0, Result.size() - 2);

	return Result;
}

inline std::string GetTempFile()
{
	char Buffer[MAX_PATH] = {};
	char PathBuffer[MAX_PATH] = {};

	GetTempPathA(MAX_PATH, PathBuffer);

	std::string Result = PathBuffer;

	GetTempFileNameA(Result.c_str(), NULL, NULL, Buffer);

	return Buffer;
}

std::vector<uint8_t> cNasmWrapper::AssembleASMSource(const std::string Path, const std::string & Source)
{
	std::vector<uint8_t> Result;

	std::string TempSourcePath = GetTempFile();
	std::string TempOutputPath = GetTempFile();

	if (!WriteFileToDisk(TempSourcePath + ".asm", std::vector<uint8_t>(Source.begin(), Source.end())))
		throw std::string("Error: Failed to write source to: ") + TempSourcePath + ".asm";

	AssembleData(Path, TempSourcePath + ".asm", TempOutputPath);

	Result = ReadFileFromDisk(TempOutputPath);

	remove((TempSourcePath + ".asm").c_str());
	remove(TempSourcePath.c_str());
	remove(TempOutputPath.c_str());

	return Result;
}
