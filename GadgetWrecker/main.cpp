

#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <random>

#include "cProcess.hpp"
#include "cNasmWrapper.hpp"

#include "../Shared/Utilities/cUtilities.hpp"

#include <capstone.h>

#pragma comment(lib, "capstone.lib")

// To lazy to build capstone myself, solve some lib problems here...
int (WINAPIV * __vsnprintf)(char *, size_t, const char*, va_list) = _vsnprintf;
int (WINAPIV* _sprintf)(char*, const char*,...) = sprintf;

std::string NasmPath = "./Dependencies/nasm.exe";

class cReferenceCounter
{
private:
	static std::map<uint64_t, std::vector<uint64_t>> _ReferenceMap;

public:
	
	static void AddReference(uint64_t ReferenceLocation, uint64_t ReferenceTarget)
	{
		if (_ReferenceMap.find(ReferenceTarget) != _ReferenceMap.end())
			_ReferenceMap[ReferenceTarget] = std::vector<uint64_t>();

		_ReferenceMap[ReferenceTarget].push_back(ReferenceLocation);
	}
	
	static bool IsReferenced(uint64_t ReferenceTarget)
	{
		return _ReferenceMap.find(ReferenceTarget) != _ReferenceMap.end();
	}

	static std::vector<uint64_t> GetReferenceLocations(uint64_t ReferenceTarget)
	{
		if (IsReferenced(ReferenceTarget))
			return _ReferenceMap[ReferenceTarget];
		else
			return std::vector<uint64_t>();
	}
};

std::map<uint64_t, std::vector<uint64_t>> cReferenceCounter::_ReferenceMap;

bool IsPageExecutable(HANDLE hProcess, uint64_t pPage, uint64_t PageSize)
{
	MEMORY_BASIC_INFORMATION aInfo = {};

	if (VirtualQueryEx(hProcess, (void*)pPage, &aInfo, PageSize) == false)
		return false;

	return
		(aInfo.Protect & PAGE_EXECUTE)
		| (aInfo.Protect & PAGE_EXECUTE_READ)
		| (aInfo.Protect & PAGE_EXECUTE_READWRITE)
		| (aInfo.Protect & PAGE_EXECUTE_WRITECOPY); // Why does this one even exist???
}

size_t GetPageSize()
{
	SYSTEM_INFO aInfo = {};

	GetSystemInfo(&aInfo);

	return aInfo.dwPageSize;
}

class cRemoteMemory
{
private:
	static uint64_t _CurrentPointer;
	static uint64_t _CurrentIndex;
	static uint64_t _SizeOfRemoteMemory;

public:
	static uint64_t GetPointer(uint32_t RequestedSize, std::shared_ptr<cProcessInformation> pProcess)
	{
		if (_CurrentIndex + RequestedSize < _SizeOfRemoteMemory)
		{
			uint64_t ResultPointer = _CurrentPointer;

			_CurrentPointer += RequestedSize + 1;
			_CurrentIndex += RequestedSize + 1;

			return ResultPointer;
		}
		else
		{
			_SizeOfRemoteMemory = GetPageSize();
			_CurrentIndex = 0;
			_CurrentPointer = (uint64_t)pProcess->AllocateMemoryInProcess(_SizeOfRemoteMemory);

			if(!_CurrentPointer)
				throw cUtilities::FormatExceptionString(__FILE__, "!_CurrentPointer");

			return GetPointer(RequestedSize, pProcess);
		}
	}
};

uint64_t cRemoteMemory::_CurrentPointer = 0;
uint64_t cRemoteMemory::_CurrentIndex = 0;
uint64_t cRemoteMemory::_SizeOfRemoteMemory = 0;

std::vector<uint64_t> SearchForRet(std::shared_ptr<cProcessInformation> pProcess, cModuleWrapper aModule)
{
	csh handle;
	cs_insn *insn;

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		throw cUtilities::FormatExceptionString(__FILE__, "cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)");

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON

	std::vector<uint64_t> Result;

	auto CurrentPageSize = (uint32_t)GetPageSize();

	uint64_t pRemotePointer = (uint64_t)aModule.hModule;
	uint64_t pRemoteEndPointer = (uint64_t)aModule.hModuleEnd;

	size_t NumberOfInstructions = 0;

	for (pRemotePointer; pRemotePointer + CurrentPageSize < pRemoteEndPointer; pRemotePointer += CurrentPageSize)
	{
		if (IsPageExecutable(pProcess->ProcessHandle->hHandle, pRemotePointer, CurrentPageSize))
		{
			auto Memory = pProcess->ReadMemoryInprocess((void*)pRemotePointer, CurrentPageSize);

			if (Memory.size() == 0)
				continue;

			for (size_t i = 0; i < Memory.size(); i++)
			{
				if (Memory[i] == 0xc3)
				{
					Result.push_back(pRemotePointer + i);
				}
			}

			size_t NumberOfInstructions = cs_disasm(handle, Memory.data(), Memory.size(), pRemotePointer, 0, &insn);

			if (NumberOfInstructions == -1)
				continue;

			for (size_t i = 0; i < NumberOfInstructions; i++)
			{
				
				cs_detail *detail = insn[i].detail;
				if (detail->groups_count > 0)
				{
					for (size_t x = 0; x < detail->groups_count; x++)
					{
						if (detail->groups[x] == X86_GRP_JUMP)
						{
							auto pOperands = detail->x86.operands;

							if (pOperands->type == X86_OP_IMM)
								cReferenceCounter::AddReference(insn[i].address, pOperands->imm);
						}
						else if (detail->groups[x] == X86_GRP_CALL)
						{
							auto pOperands = detail->x86.operands;

							if (pOperands->type == X86_OP_IMM)
								cReferenceCounter::AddReference(insn[i].address, pOperands->imm);
						}
					}
				}

				for (size_t x = 0; x < detail->x86.op_count; x++)
				{
					if (detail->x86.operands[x].type == X86_OP_MEM)
					{
						auto pOperands = detail->x86.operands[x];
						cReferenceCounter::AddReference(insn[i].address, pOperands.mem.base);
					}
				}
			}

			cs_free(insn, NumberOfInstructions);
		}
	}

	cs_close(&handle);

	return Result;
}

void ChangeRetInstruction(std::shared_ptr<cProcessInformation> pProcess, uint64_t pPointer)
{
	size_t PageSize = GetPageSize();

	uint64_t PageOffset = (pPointer % PageSize);
	uint64_t BasePage = pPointer - PageOffset;

	auto Memory = pProcess->ReadMemoryInprocess((void*)BasePage, PageSize);

	if (Memory.size() == 0)
		throw cUtilities::FormatExceptionString(__FILE__, "Memory.size() == 0");

	csh handle = NULL;
	size_t NumberOfInstructions = 0;
	cs_insn *insn = NULL;

	auto CleanException = [&](const std::string& Message)
	{
		if (insn != NULL && NumberOfInstructions != 0)
			cs_free(insn, NumberOfInstructions);

		if (handle != NULL)
			cs_close(&handle);

		NumberOfInstructions = 0;
		insn = NULL;
		handle = NULL;

		throw cUtilities::FormatExceptionString(__FILE__, Message);
	};

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		CleanException("cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)");

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON

	NumberOfInstructions = cs_disasm(handle, Memory.data(), Memory.size(), BasePage, 0, &insn);

	if (NumberOfInstructions <= 0)
		CleanException("NumberOfInstructions <= 0");

	size_t InstructionOffset = 0;
	bool IsAligned = false;
	bool IsReferenced = false;


	for (size_t i = 0; i < NumberOfInstructions; i++)
	{
		if (insn[i].address == pPointer)
		{
			IsAligned = true;
			InstructionOffset = i;
			break;
		}
	}

	if (InstructionOffset >= 5)
	{
		std::string CurrentSource = "";


		uint64_t PatchedLocation = insn[InstructionOffset - 5].address;
		uint64_t PatchedSize = 0;

		for (size_t i = InstructionOffset - 5; i < InstructionOffset + 5; i++)
		{
			//std::cout << "0x" << std::hex << insn[i].address << ": " << insn[i].mnemonic << " " << insn[i].op_str << " "
			//	<< "referenced: " << (cReferenceCounter::IsReferenced(insn[i].address) ? "yes" : "no");
			//std::getline(std::cin, std::string());

			if (i <= InstructionOffset)
			{
				CurrentSource += insn[i].mnemonic + std::string(" ") + insn[i].op_str + "\n";

				PatchedSize += insn[i].size;

				if (cReferenceCounter::IsReferenced(insn[i].address))
					IsReferenced = true;
			}
		}

		std::vector<uint8_t> ReplacementBuffer;
		for (size_t i = 0; i < PatchedSize; i++)
			ReplacementBuffer.push_back(0xcc);

		//				Expansion possible: 2 -> 5 = 4x3 extra bytes = 12 padding bytes, assuming 4 instructions previous to the ret that expand from 2 to 5 bytes
		// TODO parse instructions to see if any branches or free branches are present and add padding accordingly.
		size_t RemoteReplacementPageIndex = cRemoteMemory::GetPointer(PatchedSize + 12, pProcess);

		ReplacementBuffer[0] = 0xe9;
		*(uint32_t*)&ReplacementBuffer[1] = (uint32_t)RemoteReplacementPageIndex - PatchedLocation - 5;   // Only for x86 PATCH ME!

		CurrentSource = cUtilities::ReplaceAll(CurrentSource, "ptr", "");

		if (!IsReferenced)
		{
			CurrentSource = "ORG " + std::to_string(RemoteReplacementPageIndex) + "\n" + CurrentSource;
			CurrentSource = "bits 32\n" + CurrentSource ;

			//std::cout << "Assembling: " << CurrentSource << std::endl;

			auto ReplacementData = cNasmWrapper::AssembleASMSource(NasmPath, CurrentSource);

			std::cout << "Patching: " << ReplacementData.size() << " bytes at: 0x" << std::hex << PatchedLocation << std::endl;
			std::cout << "Redirecting function exit to: 0x" << std::hex << RemoteReplacementPageIndex << std::endl;
		//	std::getline(std::cin, std::string());

			if (ReplacementData.size() == 0)
				throw cUtilities::FormatExceptionString(__FILE__, "ReplacementData.size() == 0");

			if (pProcess->WriteMemoryInProcess((void*)RemoteReplacementPageIndex, ReplacementData))
			{
				if (!pProcess->WriteMemoryInProcess((void*)PatchedLocation, ReplacementBuffer))
				{
					std::cout << "Failed to write jump to new exitcode at: 0x" << std::hex << PatchedLocation << std::endl;
				}
			}
			else
			{
				std::cout << "Failed to write replaced function exit at: 0x" << std::hex << RemoteReplacementPageIndex << std::endl;
			}
		}
	}

	cs_free(insn, NumberOfInstructions);

	cs_close(&handle);
}

void Usage(char* Arg0)
{
	std::cout << "Usage: " << Arg0 << std::endl
		<< "Required arguments: " << std::endl
		<< "\t--target <process name> ; the process to open and patch gadgets in" << std::endl
		<< "\t--number <number> ; The number of gadgets to patch" << std::endl
		<< "Example: " << std::endl
		<< Arg0 << " --target <process name> --number <number of returns to patch>" << std::endl
		<< "Optional arguments: " << std::endl
		<< "\t --nasm </path/to/nasm> ; defaults to: ./Dependencies/nasm.exe" << std::endl;

	exit(0);
}

int main(int argc, char** argv)
{
	auto Parameters = cUtilities::ParseArguments(argv, argc);

	if (Parameters.size() == 0)
		Usage(argv[0]);

	if (Parameters.find("help") != Parameters.end()
		|| Parameters.find("--h") != Parameters.end() || Parameters.find("-h") != Parameters.end() || Parameters.find("h") != Parameters.end()
		|| Parameters.find("/h") != Parameters.end() || Parameters.find("?") != Parameters.end() || Parameters.find("/?") != Parameters.end()
		|| Parameters.find("--target") == Parameters.end() || Parameters.find("--number") == Parameters.end()
		)
		Usage(argv[0]);

	
	std::string Target = Parameters["--target"];

	if (Parameters.find("--nasm") != Parameters.end())
		NasmPath = Parameters["--nasm"];
	
	auto pProcessInfo = cProcess::OpenProcess(cUtilities::StringToWideString(Target));

	std::cout << "Wrecking ROP gadgets in: " << Target << " [" << pProcessInfo->ProcessId << "]" << std::endl;

	auto LoadedModules = cProcessInformation::GetProcessModules(pProcessInfo->ProcessId);

	std::cout << "Scanning memory space of: " << LoadedModules.size() << " modules" << std::endl;

	std::vector<uint64_t> ReturnPointers;

	size_t Counter = 0;

	for (auto aModule : LoadedModules)
	{
		auto TempResult = SearchForRet(pProcessInfo, aModule);

		ReturnPointers.insert(ReturnPointers.end(), TempResult.begin(), TempResult.end());

		if (Counter++ % 10 == 0)
			std::cout << "Progress: " << Counter << "/" << LoadedModules.size() << std::endl;
	}

	std::cout << "Found: " << ReturnPointers.size() << " possible gadgets" << std::endl;

	std::cout << "Shuffeling pointers" << std::endl;

	std::shuffle(ReturnPointers.begin(), ReturnPointers.end(), std::random_device());

	std::cout << "Suspending process" << std::endl;

	if (pProcessInfo->SuspendProcess())
		std::cout << "Warning: One or more threads are not suspended, process is not completely suspended" << std::endl;

	std::cout << "Patching: " << Parameters["--number"] << " random pointers" << std::endl;

	size_t PatchCounter = strtol(Parameters["--number"].c_str(), NULL, 10);

	for (auto pPointer: ReturnPointers)
	{
		if (PatchCounter-- == 0)
			break;
		try
		{
			ChangeRetInstruction(pProcessInfo, pPointer);
		}
		catch (std::exception e)
		{
			std::cout << "Exception: " << e.what() << std::endl;
		}
		catch (std::string e)
		{
			std::cout << "Exception: " << e << std::endl;
		}
		catch (...)
		{
			std::cout << "Unhandled exception" << std::endl;
		}
	}

	std::cout << "Resuming process" << std::endl;

	if (pProcessInfo->ResumeProcess() == false)
		std::cout << "Warning: One or more threads are not resumed, process is not completely resumed" << std::endl;

	return 0;
}