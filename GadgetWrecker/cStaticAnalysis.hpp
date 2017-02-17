

#ifndef C_STATIC_ANALYSIS_HPP
#define C_STATIC_ANALYSIS_HPP

#include <map>
#include <vector>
#include <string>
#include <memory>

#include "CapstoneWrapper.hpp"

#include "../shared/cProcess/cProcess/cProcess.hpp"

class cSystemMemoryInformation
{
public:
	static bool IsPageExecutable(HANDLE hProcess, uint64_t pPage, uint64_t PageSize);

	static size_t GetPageSize();
};

class cRemoteMemoryManager
{
private:
	static uint64_t _CurrentPointer;
	static uint64_t _CurrentIndex;
	static uint64_t _SizeOfRemoteMemory;

public:
	static uint64_t GetPointer(uint32_t RequestedSize, std::shared_ptr<cProcessInformation> pProcess);
};

class cDisassembledPage
{
private:
	size_t					_NumberOfInstructions;
	csh						_CapstoneHandle;
	cs_insn*				_DisasembledInstructions;
	std::vector<uint8_t>	_RemotePageMemory;
	uint64_t				_BasePointer;

public:
	cDisassembledPage(uint64_t pBasePointer, const std::vector<uint8_t>& Memory);
	~cDisassembledPage();

	bool		IsInstructionAtAddressAligned(uint64_t Address);
	cs_insn*	GetInstructionAtAddress(uint64_t Address);
	
	size_t		GetInstructionIdAtAddress(uint64_t Address);
	cs_insn*	GetInstructionAtIndex(size_t Index);

	size_t		GetNumInstructions();
	cs_insn*	GetAllInstructions();
};

class cBranchEntry
{
public:
	cBranchEntry(uint64_t aMemoryLocation, uint64_t aInstructionSize, uint64_t aBranchesTo, bool aIsFreeBranch);

	uint64_t				MemoryLocation;
	uint64_t				InstructionSize;
	uint64_t				BranchesTo;
	bool					IsFreeBranch;
};

typedef std::map<std::string, cBranchEntry> tBranchEntries;
typedef std::map<std::string, uint64_t>		tBranchMemoryLocationUpdates;

class cAnalysisResult
{
private:
	tBranchEntries					_Branches;

public:
	cAnalysisResult(std::shared_ptr<cProcessInformation> aptrProcess);

	void			AddBranches(const tBranchEntries& aBranchCollection);
	void			UpdateBranchMemory(const tBranchMemoryLocationUpdates& aBranchUpdateCollection);

	const bool			IsMemoryReferenced(uint64_t MemoryAddress)const;
	const bool			IsBranchInstructionAtMemory(uint64_t MemoryAddress)const;
	const bool			IsFreeBranchInstructionAtMemory(uint64_t MemoryAddress)const;
	const cBranchEntry	GetBranchInstructionAtMemory(uint64_t MemoryAddress)const;

	const std::vector<uint64_t>		GetAllReferencedMemory()const;

	const tBranchEntries	GetAllBranches()const;
	const tBranchEntries	GetAllFreeBranches()const;

	std::shared_ptr<cProcessInformation>	ptrProcess;
};

class cStaticAnalysis
{
private:

public:
	static cDisassembledPage DisassemblePageAroundPointer(std::shared_ptr<cProcessInformation> pProcess, uint64_t UnalignedPointer);
	static tBranchEntries AnalyseModule(std::shared_ptr<cProcessInformation> pProcess, cModuleWrapper aModule);
	static cAnalysisResult AnalyseProcess(std::shared_ptr<cProcessInformation> pProcess, std::vector<std::string> TargetModules);

	static void PatchAlignedRetInstruction(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess, uint64_t pPointer);
};

#endif