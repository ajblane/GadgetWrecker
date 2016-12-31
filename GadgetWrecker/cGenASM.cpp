

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

std::string cGenASMHelper::GenerateInterdictionStub(uint64_t MemoryLocation, uint64_t FromLocation, uint64_t FunCheckLongList, std::string OperandExpression)
{
	if (OperandExpression.find("esp") != std::string::npos)
		throw cUtilities::FormatExceptionString(__FILE__, "OperandExpression.find(\"esp\") != std::string::npos");

	std::string Result
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

bool cRemoteFreeBranchInterdictor::InterdictFreeBranchSizeFive(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess, uint64_t RemoteLongLookupTable, uint64_t BranchLocation)
{
	bool Result = true;

	void* RemoteStubMemory = NULL;

	auto AbortCleanup = [&]() -> bool
	{
		if (RemoteStubMemory != NULL)
			pProcess->FreeMemoryInProcess(RemoteStubMemory);

		RemoteStubMemory = NULL;

		return false;
	};

	const size_t StubFunctionReservedSize = 0x1000;

	if (_Commited == true)
		throw cUtilities::FormatExceptionString(__FILE__, "_Commited == true");

	// Create remote free branch interdictor

	RemoteStubMemory = pProcess->AllocateMemoryInProcess(StubFunctionReservedSize);

	if(RemoteStubMemory == NULL)
		throw cUtilities::FormatExceptionString(__FILE__, "RemoteStubMemory == NULL");

	auto PageInformation = cStaticAnalysis::DisassemblePageAroundPointer(pProcess, BranchLocation);

	if(PageInformation.IsInstructionAtAddressAligned(BranchLocation) == false)
		throw cUtilities::FormatExceptionString(__FILE__, "PageInformation.IsInstructionAtAddressAligned(BranchLocation) == false");

	auto BranchInstruction = PageInformation.GetInstructionAtAddress(BranchLocation);

	std::string OperandExpression = BranchInstruction->op_str;

	if (OperandExpression == "")
		return AbortCleanup();

	if (OperandExpression.find("esp") != std::string::npos)
		return AbortCleanup();											// TODO: write alternative interdictor that does not use the stack in case of esp based branch instruction
																		// Such as: jmp dword ptr[esp+0x10f] -> function pointers as arguments to functions without frame pointers or some such bullsh*t

	// Nasm does not deal with this
	OperandExpression = cUtilities::ReplaceAll(OperandExpression, "ptr", "");

	std::string InterdictionStubSource = cGenASMHelper::GenerateInterdictionStub((uint64_t)RemoteStubMemory, BranchLocation + BranchInstruction->size, RemoteLongLookupTable, OperandExpression);

	auto InterdictionBytes = cNasmWrapper::AssembleASMSource(NasmPath, InterdictionStubSource);

	if(InterdictionBytes.size() == 0)
		throw cUtilities::FormatExceptionString(__FILE__, "InterdictionBytes.size() == 0");

	if (InterdictionBytes.size() > StubFunctionReservedSize)
		throw cUtilities::FormatExceptionString(__FILE__, "InterdictionBytes.size() < StubFunctionReservedSize");

	if(pProcess->WriteMemoryInProcess(RemoteStubMemory, InterdictionBytes) == false)
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

	// All done, lets hope it works.

	return Result;
}

bool cRemoteFreeBranchInterdictor::PrepareBranchInterdiction(uint64_t BranchLocation, uint64_t BranchSize)
{
	if (BranchSize <= 4)
		return false;				// TODO
	else
		_PreparedPatches.push_back(cPreparedRemoteBranchPatches(BranchLocation, BranchSize));

	return true;
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

	std::string TableSource = cGenASMHelper::GenerateLongLookupTableChecker((uint64_t)RemoteLookupTableMemory, _LocalLookupTable);

	auto LongLookupBytes = cNasmWrapper::AssembleASMSource(NasmPath, TableSource);

	if(LongLookupBytes.size() == 0)
		throw cUtilities::FormatExceptionString(__FILE__, "LongLookupBytes.size() == 0");
	
	if(LongLookupBytes.size() > LookupTableReservedSize)
		throw cUtilities::FormatExceptionString(__FILE__, "LongLookupBytes.size() > LookupTableReservedSize");

	if (pProcess->WriteMemoryInProcess(RemoteLookupTableMemory, LongLookupBytes) == false)
		throw cUtilities::FormatExceptionString(__FILE__, "pProcess->WriteMemoryInProcess((void*)RemoteLookupTableMemory, LongLookupBytes) == false");

	for (auto pBranch : _PreparedPatches)
	{
		InterdictFreeBranchSizeFive(NasmPath, pProcess, (uint64_t)RemoteLookupTableMemory, pBranch.BranchLocation);
	}

	_Commited = true;
}

std::vector<cPreparedRemoteBranchPatches>	cRemoteFreeBranchInterdictor::_PreparedPatches;
std::map<uint64_t, uint64_t>				cRemoteFreeBranchInterdictor::_LocalLookupTable;

uint64_t cRemoteFreeBranchInterdictor::_RemoteInterdictedLookupTable;
bool cRemoteFreeBranchInterdictor::_Commited;

cPreparedRemoteBranchPatches::cPreparedRemoteBranchPatches(uint64_t aOriginalBranchLocation, uint64_t aOriginalBranchSize)
	: BranchLocation(aOriginalBranchLocation), BranchSize(aOriginalBranchSize)
{
}
