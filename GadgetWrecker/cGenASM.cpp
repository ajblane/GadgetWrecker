

#include <iostream>

#include "cGenASM.hpp"
#include "cProcess.hpp"
#include "cStaticAnalysis.hpp"
#include "cNasmWrapper.hpp"

#include "../Shared/Utilities/cUtilities.hpp"

cArgument::cArgument(std::string Data, eArgumentType eType)
	: ByteData(Data.begin(), Data.end()), ArgumentType(eType)
{
	ByteData.push_back(0);

	if (eType == eRAW)
	{
		RawData = Data;
	}

}

cArgument::cArgument(std::vector<uint8_t> Data, eArgumentType eType)
	: ByteData(Data), ArgumentType(eType)
{
}

cArgument::cArgument(uint32_t Data, eArgumentType eType)
	: IntegerData(Data), ArgumentType(eType)
{
}

std::string cArgument::GenerateRepresentation()
{
	std::string Result = "";

	if (ArgumentType == eIntegerType)
	{
		char PushBuffer[100] = {};

		sprintf_s(PushBuffer, "push 0x%.8x\n", IntegerData);

		Result = PushBuffer;
	}
	else if (ArgumentType == ePointerType)
	{
		std::string LabelName = cUtilities::GenerateRandomData("abcdefghijklmnopqrstuvwxyz", 10);

		Result += "call " + LabelName + "\n";
		Result += cNasmWrapper::ConvertBinToNasmSource(ByteData) + "\n";
		Result += LabelName += ":\n";
	}
	else if (ArgumentType == eRAW)
	{
		return RawData;
	}

	return Result;
}

std::string cGenASMHelper::GenerateCallSource(uint32_t CallLocation, std::vector<cArgument> Arguments)
{
	std::string Result = "";

	for (auto x : Arguments)
		Result += x.GenerateRepresentation();

	char CallBuffer[100] = {};
	sprintf_s(CallBuffer, "call 0x%.8x\n", CallLocation);

	Result += CallBuffer;

	return Result;
}

std::string cGenASMHelper::GenerateInterdictionStub(uint64_t MemoryLocation, uint64_t FromLocation, uint64_t FunCheckLongList, std::string OperandExpression, bool IsCall)
{
	if (OperandExpression.find("esp") != std::string::npos)
		throw cUtilities::FormatExceptionString(__FILE__, "OperandExpression.find(\"esp\") != std::string::npos");

	std::string Result = "";

	/*
	The code below functions has two functions. The first function, 
	interdicting and possibly rerouting a free branch type instruction is already completed. 

	The other function is to cache branches that have been called
	in the local list, to improve performance. This	Is not yet completed.
	*/

	if(IsCall)
		Result		// This is the code for patching a free call type
		=
		R"(
			bits 32
			org )" + std::to_string(MemoryLocation) + R"(						; arg 0 -> location in memory
			push eax
			push ecx
			push ebx	
			call PastShortlist

				dd 1, 0							; 1 is rewritten to 0
				dd 0, 0							; 0 is rewritten to 0

PastShortlist: 
			mov eax, )" + OperandExpression + R"( ; arg 1 -> OperandExpression
			xor ecx, ecx			
			pop ebx
LoopLocation:
			cmp dword [ebx+ecx], eax
			je ShortlistOut
			cmp dword [ebx+ecx], 0
			je EndOfShortlist
			add ecx, 0x8					; Jump to next entry in shortlist
			jmp LoopLocation				; Repeat the check
ShortlistOut:
			add ecx, 4
			mov ecx, dword [ebx+ecx]
			mov dword [esp-4], ecx			; esp - 4, esp - 8, esp - c, esp - 10
			pop	ebx							; esp - 8
			pop ecx							; esp - c
			pop eax							; esp - 10
			push )" + std::to_string(FromLocation) + R"( ; Template arg 2 -> FromLocation + 4 (ret), act as if we called; esp - c
			jmp	dword [esp-0xc]			; To rewritten location
EndOfShortlist:
			call )" + std::to_string(FunCheckLongList) + R"(; arg 3 -> FunCheckLongList, this function taints eax, ecx and ebx (eax is the result)
			; eax -> Rewritten location, will jump here
			; TODO: append eax to the shortlist for greater performance

ToEaxLocation:
			mov dword [esp-4], eax			; esp - 4
			pop ebx							; esp - 8
			pop ecx							; esp - c
			pop eax							; esp - 10
			push )" + std::to_string(FromLocation) + R"( ;Template arg 4 -> FromLocation + 4 (ret), act as if we called; esp - c
			jmp dword [esp-0xc]			; To original location
		)";
	else
		Result		// This is the code for patching a free jump type
		=
		R"(
			bits 32
			org )" + std::to_string(MemoryLocation) + R"(						; arg 0 -> location in memory
			push eax
			push ecx
			push ebx	
			call PastShortlist

				dd 1, 0							; 1 is rewritten to 0
				dd 0, 0							; 0 is rewritten to 0

PastShortlist: 
			mov eax, )" + OperandExpression + R"( ; arg 1 -> OperandExpression
			xor ecx, ecx			
			pop ebx
LoopLocation:
			cmp dword [ebx+ecx], eax
			je ShortlistOut
			cmp dword [ebx+ecx], 0
			je EndOfShortlist
			add ecx, 0x8					; Jump to next entry in shortlist
			jmp LoopLocation				; Repeat the check
ShortlistOut:
			add ecx, 4
			mov ecx, dword [ebx+ecx]
			mov dword [esp-4], ecx			; esp - 4, esp - 8, esp - c, esp - 10
			pop	ebx							; esp - 8
			pop ecx							; esp - c
			pop eax							; esp - 10
			jmp	dword [esp-0x10]			; To rewritten location
EndOfShortlist:
			call )" + std::to_string(FunCheckLongList) + R"(; arg 3 -> FunCheckLongList, this function taints eax, ecx and ebx (eax is the result)
			; eax -> Rewritten location, will jump here
			; TODO: append eax to the shortlist for greater performance

ToEaxLocation:
			mov dword [esp-4], eax			; esp - 4
			pop ebx							; esp - 8
			pop ecx							; esp - c
			pop eax							; esp - 10
			jmp dword [esp-0x10]			; To original location
		)";

	return Result;
}

std::string cGenASMHelper::GenerateLongLookupTableChecker(uint64_t MemoryLocation, std::map<uint64_t, uint64_t> MemoryTranslation)
{
	std::string TranslationTableString = "";

	for (auto Pair : MemoryTranslation)
		TranslationTableString += "dd " + std::to_string(Pair.first) + ", " + std::to_string(Pair.second) + "\n"; // Note dd, implicit cast qword -> dword across languages!!1! if this is not an ugly hack I don't know anymore

	TranslationTableString += "dd 0, 0\n"; // End of the list

	std::string Template
		=
		R"(				;; Registers ecx and ebx are free to use, eax contains the argument (the orignal memory location)
			bits 32
			org 0x%x				;	arg 0 -> MemoryLocation

			call PastMemoryTranslationTable  ; arg 1 -> TranslationTableString
		)" + TranslationTableString + R"(
PastMemoryTranslationTable:
			xor ecx, ecx			; ecx -> Will be the index
			pop ebx					; ebx -> TranslationTable
CompareLoop:
			cmp dword [ebx+ecx], eax
			je LongListOut
			cmp dword [ebx+ecx], 0		
			je OutNochange							; 0 found, end of the list
			add ecx, 0x8							; Jump to next entry in longlist
			jmp CompareLoop

LongListOut:
			mov eax, dword [ebx+ecx+0x4]		; Move rewritten memory to eax, return			

OutNochange:
			ret						; No entry was found for this location, return eax

		)";

	std::string Buffer;
	Buffer.resize(TranslationTableString.size() + 0x1024);

	sprintf((char*)Buffer.data(), Template.c_str(), MemoryLocation, TranslationTableString.c_str());

	return Buffer;
}

bool cDirtyRangeMarker::IsPointerDirty(uint64_t Pointer)
{
	for (auto x : _DirtyRanges)
		if (x.first <= Pointer && x.second >= Pointer)
			return true;

	return false;
}

bool cDirtyRangeMarker::IsRangeDirty(uint64_t RangeStart, uint64_t RangeEnd)
{
	for (uint64_t i = RangeStart; i <= RangeEnd; i++)
		if (IsPointerDirty(i))
			return true;

	return false;
}

void cDirtyRangeMarker::AddDirtyRange(uint64_t RangeStart, uint64_t RangeEnd)
{
	_DirtyRanges.push_back(std::make_pair(RangeStart, RangeEnd));
}

std::vector<std::pair<uint64_t, uint64_t>>  cDirtyRangeMarker::_DirtyRanges;

std::map<uint64_t, uint64_t> cRemoteLongLookupInteraction::ReadRemoteLookupTable(std::shared_ptr<cProcessInformation> pProcess, uint64_t LookupLocation)
{
	const size_t LookupTableReservedSize = 0x01000000;

	std::map<uint64_t, uint64_t> Result;
	std::vector<uint8_t> LookupTableMemory;

	LookupTableMemory = pProcess->ReadMemoryInprocess((void*)LookupLocation, LookupTableReservedSize);

	size_t CurrentTableIndex = 5;

	while (*(uint64_t*)&LookupTableMemory[CurrentTableIndex] != 0)
	{
		Result[*(uint32_t*)&LookupTableMemory[CurrentTableIndex]] = *(uint32_t*)&LookupTableMemory[CurrentTableIndex + sizeof(uint32_t)];
		CurrentTableIndex += sizeof(uint32_t) * 2;
	}

	return Result;
}

void cRemoteLongLookupInteraction::WriteRemoteLookupTable(std::shared_ptr<cProcessInformation> pProcess, uint64_t LookupLocation, const std::string& NasmPath, const std::map<uint64_t, uint64_t>& Table)
{
	const size_t LookupTableReservedSize = 0x01000000;

	std::string TableSource = cGenASMHelper::GenerateLongLookupTableChecker((uint64_t)LookupLocation, Table);

	auto LongLookupBytes = cNasmWrapper::AssembleASMSource(NasmPath, TableSource);

	if (LongLookupBytes.size() == 0)
		throw cUtilities::FormatExceptionString(__FILE__, "LongLookupBytes.size() == 0");

	if (LongLookupBytes.size() > LookupTableReservedSize)
		throw cUtilities::FormatExceptionString(__FILE__, "LongLookupBytes.size() > LookupTableReservedSize");

	if (pProcess->WriteMemoryInProcess((void*)LookupLocation, LongLookupBytes) == false)
		throw cUtilities::FormatExceptionString(__FILE__, "pProcess->WriteMemoryInProcess((void*)LookupLocation, LongLookupBytes) == false");
}

bool cRemoteFreeBranchInterdictor::InterdictLargeFreeBranch(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess, uint64_t RemoteLongLookupTable, uint64_t BranchLocation)
{
	bool Result = true;

	uint64_t RemoteStubMemory = NULL;

	auto AbortCleanup = [&]() -> bool
	{
	//	if (RemoteStubMemory != NULL)
	//		pProcess->FreeMemoryInProcess(RemoteStubMemory);

	//	RemoteStubMemory = NULL;

		return false;
	};

	auto IsInstructionCall = [&](cs_insn* pInstr) -> bool
	{
		cs_detail *detail = pInstr->detail;

		for (size_t x = 0; x < detail->groups_count; x++)
			if (detail->groups[x] == X86_GRP_CALL)
				return true;

		return false;
	};

	const size_t StubFunctionReservedSize = 0x60;

	if (_Commited == true)
		throw cUtilities::FormatExceptionString(__FILE__, "_Commited == true");

	// Create remote free branch interdictor
	RemoteStubMemory = cRemoteMemoryManager::GetPointer(StubFunctionReservedSize, pProcess);
	//RemoteStubMemory = pProcess->AllocateMemoryInProcess(StubFunctionReservedSize);

	if(RemoteStubMemory == NULL)
		throw cUtilities::FormatExceptionString(__FILE__, "RemoteStubMemory == NULL");

	auto PageInformation = cStaticAnalysis::DisassemblePageAroundPointer(pProcess, BranchLocation);

	if(PageInformation.IsInstructionAtAddressAligned(BranchLocation) == false)
		throw cUtilities::FormatExceptionString(__FILE__, "PageInformation.IsInstructionAtAddressAligned(BranchLocation) == false");

	auto BranchInstruction = PageInformation.GetInstructionAtAddress(BranchLocation);

	bool IsCallType = IsInstructionCall(BranchInstruction);

	size_t ChangeIndex = PageInformation.GetInstructionIdAtAddress(BranchLocation);

	std::string OperandExpression = BranchInstruction->op_str;

	if (OperandExpression == "")
		return AbortCleanup();

	if (OperandExpression.find("esp") != std::string::npos)
		return AbortCleanup();											// TODO: write alternative interdictor that does not use the stack in case of esp based branch instruction
																		// Such as: jmp dword ptr[esp+0x10f] -> function pointers as arguments to functions without frame pointers or some such bullsh*t

	// Nasm does not deal with this
	OperandExpression = cUtilities::ReplaceAll(OperandExpression, "ptr", "");

	std::string InterdictionStubSource = cGenASMHelper::GenerateInterdictionStub((uint64_t)RemoteStubMemory, BranchLocation + BranchInstruction->size, RemoteLongLookupTable, OperandExpression, IsCallType);

	// Size is 0x5b for this release.
	auto InterdictionBytes = cNasmWrapper::AssembleASMSource(NasmPath, InterdictionStubSource);

	if (InterdictionBytes.size() == 0)
	{
		std::cout << "Error source: " << InterdictionStubSource << std::endl;

		throw cUtilities::FormatExceptionString(__FILE__, "InterdictionBytes.size() == 0");
	}

	if (InterdictionBytes.size() > StubFunctionReservedSize)
		throw cUtilities::FormatExceptionString(__FILE__, "InterdictionBytes.size() < StubFunctionReservedSize");

	if(pProcess->WriteMemoryInProcess((void*)RemoteStubMemory, InterdictionBytes) == false)
		throw cUtilities::FormatExceptionString(__FILE__, "pProcess->WriteMemoryInProcess(RemoteStubMemory, InterdictionBytes) == false");

	//std::cout << "Rewriting branch at: 0x" << std::hex << BranchLocation << std::endl;
	//std::cout << "Rewriting branch [" << OperandExpression << "] to: 0x" << std::hex << RemoteStubMemory << std::endl;
	//std::getchar();
	// Proceed to replace old free branch code with fixed jump to interdictor

	std::vector<uint8_t> ReplacementBuffer;
	ReplacementBuffer.resize(5 + (BranchInstruction->size - 5));				// TODO: patch me for x64, this is x86 only.

	ReplacementBuffer[0] = 0xe9;
	*(uint32_t*)&ReplacementBuffer[1] = ((uint32_t)RemoteStubMemory) - ((uint32_t)BranchLocation) - 5;

	for (size_t i = 5; i < ReplacementBuffer.size(); i++)
		ReplacementBuffer[i] = 0x90;

	if (pProcess->WriteMemoryInProcess((void*)BranchLocation, ReplacementBuffer) == false)
		throw cUtilities::FormatExceptionString(__FILE__, "pProcess->WriteMemoryInProcess(BranchLocation, ReplacementBuffer) == false");

	AddToLookupTable(BranchLocation, RemoteStubMemory);

	uint64_t DirtyRangeStart = BranchLocation;
	uint64_t DirtyRangeEnd = BranchLocation + ReplacementBuffer.size();

	cDirtyRangeMarker::AddDirtyRange(DirtyRangeStart, DirtyRangeEnd);

	// All done, lets hope it works.

	return Result;
}

bool cRemoteFreeBranchInterdictor::InterdictShortFreeBranch(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess, uint64_t RemoteLongLookupTable, uint64_t BranchLocation)
{
	bool Result = true;

	uint64_t RemoteStubMemory = NULL;
	uint64_t RemotePreStubMemory = NULL;

	auto AbortCleanup = [&]() -> bool
	{
		//	if (RemoteStubMemory != NULL)
		//		pProcess->FreeMemoryInProcess(RemoteStubMemory);

		//	RemoteStubMemory = NULL;

		return false;
	};

	const size_t StubFunctionReservedSize = 0x60;
	const size_t PreStubReservedSize = 0x16;

	if (_Commited == true)
		throw cUtilities::FormatExceptionString(__FILE__, "_Commited == true");

	// Create remote free branch interdictor
	RemoteStubMemory = cRemoteMemoryManager::GetPointer(StubFunctionReservedSize, pProcess);
	RemotePreStubMemory = cRemoteMemoryManager::GetPointer(PreStubReservedSize, pProcess);

	//RemoteStubMemory = pProcess->AllocateMemoryInProcess(StubFunctionReservedSize);

	if (RemoteStubMemory == NULL)
		throw cUtilities::FormatExceptionString(__FILE__, "RemoteStubMemory == NULL");

	if (RemotePreStubMemory == NULL)
		throw cUtilities::FormatExceptionString(__FILE__, "RemotePreStubMemory == NULL");

	auto OriginalPage = cStaticAnalysis::DisassemblePageAroundPointer(pProcess, BranchLocation);

	if (OriginalPage.IsInstructionAtAddressAligned(BranchLocation) == false)
		throw cUtilities::FormatExceptionString(__FILE__, "PageInformation.IsInstructionAtAddressAligned(BranchLocation) == false");

	auto BranchInstruction = OriginalPage.GetInstructionAtAddress(BranchLocation);

	std::string OperandExpression = BranchInstruction->op_str;

	if (OperandExpression == "")
		return AbortCleanup();

	if (OperandExpression.find("esp") != std::string::npos)
		return AbortCleanup();											// TODO: write alternative interdictor that does not use the stack in case of esp based branch instruction
																		// Such as: jmp dword ptr[esp+0x10f] -> function pointers as arguments to functions without frame pointers or some such bullsh*t
																		
	OperandExpression = cUtilities::ReplaceAll(OperandExpression, "ptr", ""); // Nasm does not deal with this

	size_t ReplaceSize = BranchInstruction->size;
	size_t StartChangeIndex = OriginalPage.GetInstructionIdAtAddress(BranchLocation);
	size_t NumInstructionReplaced = 0;

	size_t ReplacementAddress = 0;

	std::string ReplacementSource = "";
	std::string PreStubSource = "";

	do
	{
		StartChangeIndex--;
		NumInstructionReplaced++;

		auto PreviousInstruction = OriginalPage.GetInstructionAtIndex(StartChangeIndex);
		
		if(PreviousInstruction == NULL)
			throw cUtilities::FormatExceptionString(__FILE__, "PreviousInstruction == NULL");

		std::string CurrentLine = PreviousInstruction->mnemonic + std::string(" ") + PreviousInstruction->op_str + "\n";

		if (CurrentLine.find("lea") != std::string::npos)
		{
			CurrentLine = cUtilities::ReplaceAll(CurrentLine, "dword", "");
			CurrentLine = cUtilities::ReplaceAll(CurrentLine, "word", "");
			CurrentLine = cUtilities::ReplaceAll(CurrentLine, "byte", "");
		}

		CurrentLine = cUtilities::ReplaceAll(CurrentLine, "ptr", "");

		PreStubSource = CurrentLine + PreStubSource + "\n";

		ReplaceSize += PreviousInstruction->size;
		ReplacementAddress = PreviousInstruction->address;

	} while (ReplaceSize < 5);

	PreStubSource = "BITS 32\nORG " + std::to_string(RemotePreStubMemory) + "\n" + PreStubSource;
	PreStubSource += "jmp " + std::to_string(RemoteStubMemory) + "\n";

	ReplacementSource = "BITS 32\nORG " + std::to_string(ReplacementAddress) + "\n" + ReplacementSource;
	ReplacementSource += "jmp " + std::to_string(RemotePreStubMemory) + "\n";

	std::string InterdictionStubSource = cGenASMHelper::GenerateInterdictionStub((uint64_t)RemoteStubMemory, BranchLocation + BranchInstruction->size, RemoteLongLookupTable, OperandExpression);

	// Size is 0x5b for this release.
	auto StubBytes = cNasmWrapper::AssembleASMSource(NasmPath, InterdictionStubSource);
	auto PreStubBytes = cNasmWrapper::AssembleASMSource(NasmPath, PreStubSource);
	auto InterdictionBytes = cNasmWrapper::AssembleASMSource(NasmPath, ReplacementSource);

	if (StubBytes.size() == 0 || InterdictionBytes.size() == 0 || PreStubBytes.size() == 0)
	{
		std::cout 
			<< "Error source stub: " << InterdictionStubSource << std::endl
			<< "Error source pre-stub: " << PreStubSource << std::endl
			<< "Error source patch: " << ReplacementSource << std::endl;

		throw cUtilities::FormatExceptionString(__FILE__, "StubBytes.size() == 0 || InterdictionBytes.size() == 0 || PreStubBytes.size() == 0");
	}

	for (size_t i = InterdictionBytes.size(); i < ReplaceSize; i++)
		InterdictionBytes.push_back(0x90);

	if (StubBytes.size() > StubFunctionReservedSize)
		throw cUtilities::FormatExceptionString(__FILE__, "StubBytes.size() < StubFunctionReservedSize");

	if (pProcess->WriteMemoryInProcess((void*)RemoteStubMemory, StubBytes) == false)
		throw cUtilities::FormatExceptionString(__FILE__, "pProcess->WriteMemoryInProcess(RemoteStubMemory, StubBytes) == false");

	if (pProcess->WriteMemoryInProcess((void*)RemotePreStubMemory, PreStubBytes) == false)
		throw cUtilities::FormatExceptionString(__FILE__, "pProcess->WriteMemoryInProcess(RemoteStubMemory, PreStubBytes) == false");

	if (pProcess->WriteMemoryInProcess((void*)ReplacementAddress, InterdictionBytes) == false)
		throw cUtilities::FormatExceptionString(__FILE__, "pProcess->WriteMemoryInProcess((void*)ReplacementAddress, InterdictionBytes) == false)");

	auto NewPage = cStaticAnalysis::DisassemblePageAroundPointer(pProcess, RemotePreStubMemory);
	size_t NewPageIndex = NewPage.GetInstructionIdAtAddress(RemotePreStubMemory);

	MassAddToLookupTable(OriginalPage, NewPage, StartChangeIndex, NewPageIndex, NumInstructionReplaced);

	uint64_t DirtyRangeStart = ReplacementAddress;
	uint64_t DirtyRangeEnd = ReplacementAddress + InterdictionBytes.size();

	cDirtyRangeMarker::AddDirtyRange(DirtyRangeStart, DirtyRangeEnd);

	//std::cout << "Rewriting branch at: 0x" << std::hex << BranchLocation << std::endl;
	//std::cout << "Rewriting branch [" << OperandExpression << "] to: 0x" << std::hex << RemoteStubMemory << std::endl;
	//std::getchar();

	// All done, lets hope it works.

	return Result;
}

bool cRemoteFreeBranchInterdictor::PrepareBranchInterdiction(uint64_t BranchLocation, uint64_t BranchSize)
{
	if (BranchSize <= 4)
		_TargetFreeBranchesSizeFour.push_back(cPreparedRemoteBranchPatches(BranchLocation, BranchSize));		// TODO
	else
		_TargetFreeBranchesSizeFive.push_back(cPreparedRemoteBranchPatches(BranchLocation, BranchSize));

	return true;
}

void cRemoteFreeBranchInterdictor::MassAddToLookupTable(cDisassembledPage & OriginalPage, cDisassembledPage & NewPage, uint64_t ModifyIndex, uint64_t NewPageStartIndex, uint8_t NumChanges)
{
	if(OriginalPage.GetNumInstructions() <= ModifyIndex + NumChanges)
		throw cUtilities::FormatExceptionString(__FILE__, "OriginalPage.GetNumInstructions() <= ModifyIndex + NumChanges");

	for (size_t i = ModifyIndex; i < ModifyIndex + NumChanges; i++)
	{
		uint64_t oLocation = OriginalPage.GetInstructionAtIndex(i)->address;
		uint64_t nLocation = NewPage.GetInstructionAtIndex(NewPageStartIndex + (i - ModifyIndex))->address;
		AddToLookupTable(oLocation, nLocation);
	}
}

void cRemoteFreeBranchInterdictor::AddToLookupTable(uint64_t OriginalRemoteLocation, uint64_t NewRemoteLocation)
{
	if(_Commited == true)
		throw cUtilities::FormatExceptionString(__FILE__, "_Commited == true");

	_LocalLookupTable[OriginalRemoteLocation] = NewRemoteLocation;
}

void cRemoteFreeBranchInterdictor::Commit(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess)
{
	const size_t LookupTableReservedSize = 0x01000000;

	if (_Commited == true)
		throw cUtilities::FormatExceptionString(__FILE__, "_Commited == true");

	auto RemoteLookupTableMemory = pProcess->AllocateMemoryInProcess(LookupTableReservedSize);

	auto OldTable = _LocalLookupTable;

	cRemoteLongLookupInteraction::WriteRemoteLookupTable(pProcess, (uint64_t)RemoteLookupTableMemory, NasmPath, _LocalLookupTable);

	for (auto pBranch : _TargetFreeBranchesSizeFive)
	{
		if (cDirtyRangeMarker::IsPointerDirty(pBranch.BranchLocation) == false)
			InterdictLargeFreeBranch(NasmPath, pProcess, (uint64_t)RemoteLookupTableMemory, pBranch.BranchLocation);
	}

	for (auto pBranch : _TargetFreeBranchesSizeFour)
	{
		if(cDirtyRangeMarker::IsPointerDirty(pBranch.BranchLocation) == false)
			InterdictShortFreeBranch(NasmPath, pProcess, (uint64_t)RemoteLookupTableMemory, pBranch.BranchLocation);
	}

	auto RemoteTable = cRemoteLongLookupInteraction::ReadRemoteLookupTable(pProcess, (uint64_t)RemoteLookupTableMemory);

	for (auto x : _LocalLookupTable)
	{
		if (RemoteTable.find(x.first) == RemoteTable.end())
			RemoteTable[x.first] = x.second;
	}

	cRemoteLongLookupInteraction::WriteRemoteLookupTable(pProcess, (uint64_t)RemoteLookupTableMemory, NasmPath, RemoteTable);

	_Commited = true;
}

std::vector<cPreparedRemoteBranchPatches>	cRemoteFreeBranchInterdictor::_TargetFreeBranchesSizeFive;
std::vector<cPreparedRemoteBranchPatches>	cRemoteFreeBranchInterdictor::_TargetFreeBranchesSizeFour;

std::map<uint64_t, uint64_t>				cRemoteFreeBranchInterdictor::_LocalLookupTable;

uint64_t cRemoteFreeBranchInterdictor::_RemoteInterdictedLookupTable;
bool cRemoteFreeBranchInterdictor::_Commited;

cPreparedRemoteBranchPatches::cPreparedRemoteBranchPatches(uint64_t aOriginalBranchLocation, uint64_t aOriginalBranchSize)
	: BranchLocation(aOriginalBranchLocation), BranchSize(aOriginalBranchSize)
{
}

