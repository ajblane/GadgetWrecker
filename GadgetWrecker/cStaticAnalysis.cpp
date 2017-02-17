#include <iostream>
#include <filesystem>

#include "cStaticAnalysis.hpp"
#include "cNasmWrapper.hpp"
#include "cGenASM.hpp"

#include "../shared/Utilities/cUtilities.hpp"

extern bool Useint3hHack;

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

		_CurrentPointer += RequestedSize;
		_CurrentIndex += RequestedSize;

		if (_CurrentPointer % 2 == 1)
		{
			_CurrentPointer++;
			_CurrentIndex++;
		}

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

size_t cDisassembledPage::GetInstructionIdAtAddress(uint64_t Address)
{
	for (size_t i = 0; i < _NumberOfInstructions; i++)
		if (_DisasembledInstructions[i].address == Address)
			return i;

	return 0;
}

cs_insn * cDisassembledPage::GetInstructionAtIndex(size_t Index)
{
	return &_DisasembledInstructions[Index];
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

tBranchEntries cStaticAnalysis::AnalyseModule(std::shared_ptr<cProcessInformation> pProcess, cModuleWrapper aModule)
{
	tBranchEntries Result;

	auto CurrentPageSize = (uint32_t)cSystemMemoryInformation::GetPageSize();

	uint64_t pRemotePointer = (uint64_t)aModule.hModule;
	uint64_t pRemoteEndPointer = (uint64_t)aModule.hModuleEnd;

	size_t NumberOfInstructions = 0;

	for (pRemotePointer; pRemotePointer + CurrentPageSize < pRemoteEndPointer; pRemotePointer += CurrentPageSize)
	{
		if (cSystemMemoryInformation::IsPageExecutable(pProcess->ProcessHandle->hHandle, pRemotePointer, CurrentPageSize) == false)
			continue;

		auto DisassembledPage = cStaticAnalysis::DisassemblePageAroundPointer(pProcess, pRemotePointer);
		
		size_t NumberOfInstructions = DisassembledPage.GetNumInstructions();

		if (NumberOfInstructions == 0 || NumberOfInstructions == -1)
			continue;

		cs_insn* pCurrentInstructions = DisassembledPage.GetAllInstructions();

		for (size_t i = 0; i < NumberOfInstructions; i++)
		{
			cs_detail* pDetails = pCurrentInstructions[i].detail;

			if (pCurrentInstructions[i].id == X86_INS_RET)
			{
				Result[cUtilities::GenerateRandomData("abcdefghijklmnopqrstuvwxyz0123456789", 15)] = cBranchEntry(pCurrentInstructions[i].address, pCurrentInstructions[i].size, 0, true);
			}
			else
			{
				if (pDetails->groups_count <= 0)
					continue;

				for (size_t x = 0; x < pDetails->groups_count; x++)
				{
					if (pDetails->groups[x] == X86_GRP_JUMP)
					{
						auto pOperands = pDetails->x86.operands;

						if (pOperands->type == X86_OP_IMM || pOperands->type == X86_GRP_CALL)
							Result[cUtilities::GenerateRandomData("abcdefghijklmnopqrstuvwxyz0123456789", 15)] = cBranchEntry(pCurrentInstructions[i].address, pCurrentInstructions[i].size, pOperands->imm, false);
						else
							Result[cUtilities::GenerateRandomData("abcdefghijklmnopqrstuvwxyz0123456789", 15)] = cBranchEntry(pCurrentInstructions[i].address, pCurrentInstructions[i].size, 0, true);
					}
				}
			}
		}
	}

	return Result;
}

cAnalysisResult cStaticAnalysis::AnalyseProcess(std::shared_ptr<cProcessInformation> pProcess, std::vector<std::string> TargetModules)
{
	cAnalysisResult Result(pProcess);

	std::vector<cModuleWrapper> CurrentlyLoadedModules = cProcessInformation::GetProcessModules(Result.ptrProcess->ProcessId);
	std::vector<cModuleWrapper> TargetedModules;

	if (TargetModules.size() != 0)
	{
		for (auto x : CurrentlyLoadedModules)
		{
			std::string ModuleName = cUtilities::WideStringToString(x.ModuleName);

			ModuleName = std::experimental::filesystem::path(ModuleName).filename().string();

			if (std::find(TargetModules.begin(), TargetModules.end(), ModuleName) != TargetModules.end())
				TargetedModules.push_back(x);
		}
	}
	else
	{
		TargetedModules = CurrentlyLoadedModules;
	}

	if (TargetedModules.size() == 0)
		throw cUtilities::FormatExceptionString(__FILE__, "TargetedModules.size() == 0");

	for (auto CurrentModule: TargetedModules)
	{
		auto BranchEntries = AnalyseModule(Result.ptrProcess, CurrentModule);
		Result.AddBranches(BranchEntries);
	}

	return Result;
}

void cStaticAnalysis::PatchAlignedRetInstruction(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess, uint64_t pPointer)
{
	auto OriginalPage = DisassemblePageAroundPointer(pProcess, pPointer);

	if (OriginalPage.IsInstructionAtAddressAligned(pPointer) == false)
		return;

	size_t ReturnInstructionIndex = OriginalPage.GetInstructionIdAtAddress(pPointer);

	if (ReturnInstructionIndex <= 5)
		return;

	size_t ChangeStartIndex = ReturnInstructionIndex;
	size_t NumberOfInstructionsChanged = 0;
	size_t TotalReplacementSize = 0;
	uint64_t RemotePatchLocation = 0;

	std::string StubSource = "";

	while(TotalReplacementSize < 5)
	{
		auto pCurrentInstruction = OriginalPage.GetInstructionAtIndex(ChangeStartIndex);

		std::string CurrentLine = pCurrentInstruction->mnemonic + std::string(" ") + pCurrentInstruction->op_str + "\n";

		if (CurrentLine.find("lea") != std::string::npos)
		{
			CurrentLine = cUtilities::ReplaceAll(CurrentLine, "dword", "");
			CurrentLine = cUtilities::ReplaceAll(CurrentLine, "word", "");
			CurrentLine = cUtilities::ReplaceAll(CurrentLine, "byte", "");
		}

		CurrentLine = cUtilities::ReplaceAll(CurrentLine, "ptr", "");

		StubSource = CurrentLine + StubSource;

		ChangeStartIndex--;
		NumberOfInstructionsChanged++;
		TotalReplacementSize += pCurrentInstruction->size;
		RemotePatchLocation = pCurrentInstruction->address;
	}

	ChangeStartIndex++;

	size_t RemoteStubMemory = cRemoteMemoryManager::GetPointer(TotalReplacementSize + 12, pProcess);

	std::vector<uint8_t> PatchBytes;
	for (size_t i = 0; i < TotalReplacementSize; i++)
		PatchBytes.push_back(0xcc);

	PatchBytes[0] = 0xe9;
	*(uint32_t*)&PatchBytes[1] = (uint32_t)RemoteStubMemory - RemotePatchLocation - 5;   // Only for x86 PATCH ME!
	
	StubSource = "bits 32\nORG " + std::to_string(RemoteStubMemory) + "\n" + StubSource;
	
	//std::cout << "Assembling: " << ReplacementSource << std::endl;

	auto StubBytes = cNasmWrapper::AssembleASMSource(NasmPath, StubSource);

	if (StubBytes.size() == 0)
	{
		std::cout << "Error source: " << StubSource << std::endl;
		throw cUtilities::FormatExceptionString(__FILE__, "StubBytes.size() == 0");
	}

	if (pProcess->WriteMemoryInProcess((void*)RemoteStubMemory, StubBytes) == false)
		throw cUtilities::FormatExceptionString(__FILE__, "pProcess->WriteMemoryInProcess((void*)RemoteStubMemory, StubBytes) == false");

	if(pProcess->WriteMemoryInProcess((void*)RemotePatchLocation, PatchBytes) == false)
		throw cUtilities::FormatExceptionString(__FILE__, "pProcess->WriteMemoryInProcess((void*)RemotePatchLocation, PatchBytes) == false");

	auto NewPage = DisassemblePageAroundPointer(pProcess, RemoteStubMemory);
	size_t StartIndex = NewPage.GetInstructionIdAtAddress(RemoteStubMemory);

	cStaticRemoteFreeBranchInterdictor::MassAddToLookupTable(OriginalPage, NewPage, ChangeStartIndex, StartIndex, NumberOfInstructionsChanged);

	uint64_t DirtyRangeStart = RemotePatchLocation;
	uint64_t DirtyRangeEnd = RemotePatchLocation + PatchBytes.size();

	cDirtyRangeMarker::AddDirtyRange(DirtyRangeStart, DirtyRangeEnd);
}

cBranchEntry::cBranchEntry(uint64_t aMemoryLocation, uint64_t aInstructionSize, uint64_t aBranchesTo, bool aIsFreeBranch)
	: MemoryLocation(aMemoryLocation), InstructionSize(aInstructionSize), BranchesTo(aBranchesTo), IsFreeBranch(aIsFreeBranch)
{
}

cAnalysisResult::cAnalysisResult(std::shared_ptr<cProcessInformation> aptrProcess)
	: ptrProcess(aptrProcess)
{
}

void cAnalysisResult::AddBranches(const tBranchEntries & aBranchCollection)
{
	_Branches.insert(aBranchCollection.begin(), aBranchCollection.end());
}

void cAnalysisResult::UpdateBranchMemory(const tBranchMemoryLocationUpdates & aBranchUpdateCollection)
{
	for (auto x : aBranchUpdateCollection)
		_Branches[x.first].MemoryLocation = x.second;
}

const bool cAnalysisResult::IsMemoryReferenced(uint64_t MemoryAddress) const
{
	for (auto x : _Branches)
		if (x.second.BranchesTo == MemoryAddress)
			return true;

	return false;
}

const bool cAnalysisResult::IsBranchInstructionAtMemory(uint64_t MemoryAddress) const
{
	for (auto x : _Branches)
		if (x.second.MemoryLocation == MemoryAddress)
			return true;

	return false;
}

const bool cAnalysisResult::IsFreeBranchInstructionAtMemory(uint64_t MemoryAddress) const
{
	for (auto x : _Branches)
		if (x.second.MemoryLocation == MemoryAddress)
			return x.second.IsFreeBranch;

	return false;
}

const cBranchEntry cAnalysisResult::GetBranchInstructionAtMemory(uint64_t MemoryAddress) const
{
	for (auto x : _Branches)
		if (x.second.MemoryLocation == MemoryAddress)
			return x.second;

	throw "No such entry";
}

const std::vector<uint64_t> cAnalysisResult::GetAllReferencedMemory() const
{
	std::vector<uint64_t> Result;

	for (auto x : _Branches)
		if (x.second.IsFreeBranch == false)
			Result.push_back(x.second.BranchesTo);

	return Result;
}

const tBranchEntries cAnalysisResult::GetAllBranches() const
{
	return _Branches;
}

const tBranchEntries cAnalysisResult::GetAllFreeBranches() const
{
	tBranchEntries Result;

	for (auto x : _Branches)
		if (x.second.IsFreeBranch)
			Result.insert(x);

	return Result;
}

