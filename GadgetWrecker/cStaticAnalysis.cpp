#include <iostream>

#include "cStaticAnalysis.hpp"
#include "cNasmWrapper.hpp"

#include "../shared/Utilities/cUtilities.hpp"

extern bool Useint3hHack;

void cStaticReferenceCounter::AddReference(uint64_t ReferenceLocation, uint64_t ReferenceTarget)
{
	if (_ReferenceMap.find(ReferenceTarget) != _ReferenceMap.end())
		_ReferenceMap[ReferenceTarget] = std::vector<uint64_t>();

	_ReferenceMap[ReferenceTarget].push_back(ReferenceLocation);
}

bool cStaticReferenceCounter::IsReferenced(uint64_t ReferenceTarget)
{
	return _ReferenceMap.find(ReferenceTarget) != _ReferenceMap.end();
}

std::vector<uint64_t> cStaticReferenceCounter::GetReferenceLocations(uint64_t ReferenceTarget)
{
	if (IsReferenced(ReferenceTarget))
		return _ReferenceMap[ReferenceTarget];
	else
		return std::vector<uint64_t>();
}

std::map<uint64_t, std::vector<uint64_t>> cStaticReferenceCounter::_ReferenceMap;

bool cSystemMemoryInformation::IsPageExecutable(HANDLE hProcess, uint64_t pPage, uint64_t PageSize)
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

size_t cSystemMemoryInformation::GetPageSize()
{
	SYSTEM_INFO aInfo = {};

	GetSystemInfo(&aInfo);

	return aInfo.dwPageSize;
}

uint64_t cRemoteMemoryManager::GetPointer(uint32_t RequestedSize, std::shared_ptr<cProcessInformation> pProcess)
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
		_SizeOfRemoteMemory = cSystemMemoryInformation::GetPageSize();
		_CurrentIndex = 0;
		_CurrentPointer = (uint64_t)pProcess->AllocateMemoryInProcess(_SizeOfRemoteMemory);

		if (!_CurrentPointer)
			throw cUtilities::FormatExceptionString(__FILE__, "!_CurrentPointer");

		return GetPointer(RequestedSize, pProcess);
	}
}

uint64_t cRemoteMemoryManager::_CurrentPointer = 0;
uint64_t cRemoteMemoryManager::_CurrentIndex = 0;
uint64_t cRemoteMemoryManager::_SizeOfRemoteMemory = 0;

cDisassembledPage::cDisassembledPage(uint64_t pBasePointer, const std::vector<uint8_t>& Memory)
	: _NumberOfInstructions(0), _CapstoneHandle(0), _DisasembledInstructions(NULL), _BasePointer(pBasePointer)
{
	auto CleanException = [&](const std::string& Message)
	{
		if (_DisasembledInstructions != NULL && _NumberOfInstructions != 0)
			cs_free(_DisasembledInstructions, _NumberOfInstructions);

		if (_CapstoneHandle != NULL)
			cs_close(&_CapstoneHandle);

		_NumberOfInstructions = 0;
		_DisasembledInstructions = NULL;
		_CapstoneHandle = NULL;

		throw cUtilities::FormatExceptionString(__FILE__, Message);
	};

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &_CapstoneHandle) != CS_ERR_OK)
		CleanException("cs_open(CS_ARCH_X86, CS_MODE_32, &_CapstoneHandle) != CS_ERR_OK");

	cs_option(_CapstoneHandle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON

	_NumberOfInstructions = cs_disasm(_CapstoneHandle, Memory.data(), Memory.size(), _BasePointer, 0, &_DisasembledInstructions);
}

cDisassembledPage::~cDisassembledPage()
{
	if (_DisasembledInstructions != NULL && _NumberOfInstructions != 0)
		cs_free(_DisasembledInstructions, _NumberOfInstructions);

	if (_CapstoneHandle != NULL)
		cs_close(&_CapstoneHandle);

	_NumberOfInstructions = 0;
	_DisasembledInstructions = NULL;
	_CapstoneHandle = NULL;
}

bool cDisassembledPage::IsInstructionAtAddressAligned(uint64_t Address)
{
	for (size_t i = 0; i < _NumberOfInstructions; i++)
		if (_DisasembledInstructions[i].address == Address)
			return true;
		else if (_DisasembledInstructions[i].address > Address)
			return false;

	return false;
}

cs_insn* cDisassembledPage::GetInstructionAtAddress(uint64_t Address)
{
	cs_insn* pResult = NULL;

	for (size_t i = 0; i < _NumberOfInstructions; i++)
		if (_DisasembledInstructions[i].address == Address)
			return &_DisasembledInstructions[i];

	return pResult;
}

size_t cDisassembledPage::GetNumInstructions()
{
	return _NumberOfInstructions;
}

cs_insn * cDisassembledPage::GetAllInstructions()
{
	return _DisasembledInstructions;
}

cDisassembledPage cStaticAnalysis::DisassemblePageAroundPointer(std::shared_ptr<cProcessInformation> pProcess, uint64_t UnalignedPointer)
{
	size_t PageSize = cSystemMemoryInformation::GetPageSize();

	uint64_t PageOffset = (UnalignedPointer % PageSize);
	uint64_t BasePage = UnalignedPointer - PageOffset;

	auto Memory = pProcess->ReadMemoryInprocess((void*)BasePage, PageSize);

	if (Memory.size() == 0)
		throw cUtilities::FormatExceptionString(__FILE__, "Memory.size() == 0");

	return cDisassembledPage(BasePage, Memory);
}

std::vector<uint64_t> cStaticAnalysis::AnalyseModule(std::shared_ptr<cProcessInformation> pProcess, cModuleWrapper aModule)
{
	std::vector<uint64_t> Result;

	auto CurrentPageSize = (uint32_t)cSystemMemoryInformation::GetPageSize();

	uint64_t pRemotePointer = (uint64_t)aModule.hModule;
	uint64_t pRemoteEndPointer = (uint64_t)aModule.hModuleEnd;

	size_t NumberOfInstructions = 0;

	for (pRemotePointer; pRemotePointer + CurrentPageSize < pRemoteEndPointer; pRemotePointer += CurrentPageSize)
	{
		if (cSystemMemoryInformation::IsPageExecutable(pProcess->ProcessHandle->hHandle, pRemotePointer, CurrentPageSize))
		{
			auto PageData = cStaticAnalysis::DisassemblePageAroundPointer(pProcess, pRemotePointer);

			size_t NumberOfInstructions = PageData.GetNumInstructions();

			if (NumberOfInstructions == 0 || NumberOfInstructions == -1)
				continue;

			/*
			for (size_t i = 0; i < Memory.size(); i++)
			{
				if (Memory[i] == 0xc3)
				{
					This woul also count unaligned instructions, we won't deal with those for now.
					Result.push_back(pRemotePointer + i);
				}
			}
			*/

			cs_insn* insn = PageData.GetAllInstructions();

			for (size_t i = 0; i < NumberOfInstructions; i++)
			{
				cs_detail *detail = insn[i].detail;

				if (insn[i].id == X86_INS_RET)
				{
					Result.push_back(insn[i].address);
				}

				if (detail->groups_count > 0)
				{
					for (size_t x = 0; x < detail->groups_count; x++)
					{
						if (detail->groups[x] == X86_GRP_JUMP)
						{
							auto pOperands = detail->x86.operands;

							if (pOperands->type == X86_OP_IMM)
								cStaticReferenceCounter::AddReference(insn[i].address, pOperands->imm);
							else
								cFreeBranchReferenceCounter::AddFreeBranch(insn[i].address, insn[i].size);
						}
						else if (detail->groups[x] == X86_GRP_CALL)
						{
							auto pOperands = detail->x86.operands;

							if (pOperands->type == X86_OP_IMM)
								cStaticReferenceCounter::AddReference(insn[i].address, pOperands->imm);
							else
								cFreeBranchReferenceCounter::AddFreeBranch(insn[i].address, insn[i].size);
						}
					}
				}

				/*
				for (size_t x = 0; x < detail->x86.op_count; x++)
				{
					if (detail->x86.operands[x].type == X86_OP_MEM)
					{
						auto pOperands = detail->x86.operands[x];
						cStaticReferenceCounter::AddReference(insn[i].address, pOperands.mem.disp);
					}
				}
				*/
			}
		}
	}

	return Result;
}

uint64_t cStaticAnalysis::PatchAlignedRetInstruction(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess, uint64_t pPointer)
{
	// The new location of the RET instruction
	uint64_t Result = 0;

	size_t PageSize = cSystemMemoryInformation::GetPageSize();

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

	auto Cleanup = [&](uint64_t aResult) -> uint64_t
	{
		if (insn != NULL && NumberOfInstructions != 0)
			cs_free(insn, NumberOfInstructions);

		if (handle != NULL)
			cs_close(&handle);

		NumberOfInstructions = 0;
		insn = NULL;
		handle = NULL;
		
		return aResult;
	};

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		CleanException("cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)");

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON

	NumberOfInstructions = cs_disasm(handle, Memory.data(), Memory.size(), BasePage, 0, &insn);

	if (NumberOfInstructions <= 0)
		CleanException("NumberOfInstructions <= 0");

	size_t InstructionOffset = 0;
	bool IsReferenced = false;

	for (size_t i = 0; InstructionOffset == 0 && i < NumberOfInstructions; i++)
	{
		if (insn[i].address == pPointer)
			InstructionOffset = i;
		else if (insn[i].address > pPointer)
			return Cleanup(Result);
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

			std::string CurrentLine = insn[i].mnemonic + std::string(" ") + insn[i].op_str + "\n";

			if (Useint3hHack)
				if (insn[i].id == X86_INS_INT3)
					continue;

			if (i <= InstructionOffset)
			{
				if (CurrentLine.find("lea") != std::string::npos)
				{
					CurrentLine = cUtilities::ReplaceAll(CurrentLine, "dword", "");
					CurrentLine = cUtilities::ReplaceAll(CurrentLine, "word", "");
					CurrentLine = cUtilities::ReplaceAll(CurrentLine, "byte", "");
				}

				CurrentLine = cUtilities::ReplaceAll(CurrentLine, "ptr", "");

				CurrentSource += CurrentLine;

				PatchedSize += insn[i].size;

				if (cStaticReferenceCounter::IsReferenced(insn[i].address))
					IsReferenced = true;
			}
		}

		if (IsReferenced == true)
			return Cleanup(Result);

		// We need at least 5 bytes to place a jump.
		if(PatchedSize < 5)
			return Cleanup(Result);

		std::vector<uint8_t> ReplacementBuffer;
		for (size_t i = 0; i < PatchedSize; i++)
			ReplacementBuffer.push_back(0xcc);

		//				Expansion possible: 2 -> 5 = 4x3 extra bytes = 12 padding bytes, assuming 4 instructions previous to the ret that expand from 2 to 5 bytes
		// TODO parse instructions to see if any branches or free branches are present and add padding accordingly.
		size_t RemoteReplacementPageIndex = cRemoteMemoryManager::GetPointer(PatchedSize + 12, pProcess);

		ReplacementBuffer[0] = 0xe9;
		*(uint32_t*)&ReplacementBuffer[1] = (uint32_t)RemoteReplacementPageIndex - PatchedLocation - 5;   // Only for x86 PATCH ME!


		CurrentSource = "ORG " + std::to_string(RemoteReplacementPageIndex) + "\n" + CurrentSource;
		CurrentSource = "bits 32\n" + CurrentSource;

		//std::cout << "Assembling: " << CurrentSource << std::endl;

		auto ReplacementData = cNasmWrapper::AssembleASMSource(NasmPath, CurrentSource);

		std::cout << "Patching: " << ReplacementData.size() << " bytes at: 0x" << std::hex << PatchedLocation << std::endl;
		std::cout << "Redirecting function exit to: 0x" << std::hex << RemoteReplacementPageIndex << std::endl;
		//	std::getline(std::cin, std::string());

		if (ReplacementData.size() == 0)
		{
			std::cout << "Error source: " << CurrentSource << std::endl;
			CleanException("ReplacementData.size() == 0");
		}

		if (pProcess->WriteMemoryInProcess((void*)RemoteReplacementPageIndex, ReplacementData))
		{
			if (!pProcess->WriteMemoryInProcess((void*)PatchedLocation, ReplacementBuffer))
			{
				std::cout << "Failed to write jump to new exitcode at: 0x" << std::hex << PatchedLocation << std::endl;
			}
			else
			{
				Result = RemoteReplacementPageIndex;
			}
		}
		else
		{
			std::cout << "Failed to write replaced function exit at: 0x" << std::hex << RemoteReplacementPageIndex << std::endl;
		}
	}

	return Cleanup(Result);
}

void cFreeBranchReferenceCounter::AddFreeBranch(uint64_t BranchLocation, uint8_t InstructionLength)
{
	_FreeBranches[BranchLocation] = InstructionLength;
}

bool cFreeBranchReferenceCounter::IsLocationFreeBranch(uint64_t PotentialBranchLocation)
{
	return _FreeBranches.find(PotentialBranchLocation) != _FreeBranches.end();
}

std::map<uint64_t, uint8_t> cFreeBranchReferenceCounter::GetAllFreeBranches()
{
	return _FreeBranches;
}

std::map<uint64_t, uint8_t> cFreeBranchReferenceCounter::_FreeBranches;

