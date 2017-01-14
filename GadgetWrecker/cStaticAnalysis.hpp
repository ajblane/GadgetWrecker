

#ifndef C_STATIC_ANALYSIS_HPP
#define C_STATIC_ANALYSIS_HPP

#include <map>
#include <vector>
#include <string>
#include <memory>

#include "cProcess.hpp"
#include "CapstoneWrapper.hpp"

class cStaticReferenceCounter
{
private:
	static std::map<uint64_t, std::vector<uint64_t>> _ReferenceMap;

public:

	static void AddReference(uint64_t ReferenceLocation, uint64_t ReferenceTarget);
	static bool IsReferenced(uint64_t ReferenceTarget);
	static std::vector<uint64_t> GetReferenceLocations(uint64_t ReferenceTarget);
};

class cFreeBranchReferenceCounter
{
private:
	static std::map<uint64_t, uint8_t> _FreeBranches;

public:
	static void AddFreeBranch(uint64_t BranchLocation, uint8_t InstructionLength);
	static bool IsLocationFreeBranch(uint64_t PotentialBranchLocation);
	static std::map<uint64_t, uint8_t> GetAllFreeBranches();

};

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

	bool	IsInstructionAtAddressAligned(uint64_t Address);
	cs_insn*	GetInstructionAtAddress(uint64_t Address);
	
	size_t		GetInstructionIdAtAddress(uint64_t Address);
	cs_insn*	GetInstructionAtIndex(size_t Index);

	size_t		GetNumInstructions();
	cs_insn*	GetAllInstructions();
};

class cStaticAnalysis
{
private:

public:
	
	static cDisassembledPage DisassemblePageAroundPointer(std::shared_ptr<cProcessInformation> pProcess, uint64_t UnalignedPointer);
	static std::vector<uint64_t> AnalyseModule(std::shared_ptr<cProcessInformation> pProcess, cModuleWrapper aModule);
	static void PatchAlignedRetInstruction(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess, uint64_t pPointer);
};

#endif