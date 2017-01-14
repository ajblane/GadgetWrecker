
#ifndef C_TRAMPOLINES_HPP
#define C_TRAMPOLINES_HPP

#include <map>
#include <string>
#include <vector>
#include <mutex>

#include "cNasmWrapper.hpp"
#include "cProcess.hpp"
#include "cStaticAnalysis.hpp"

enum eArgumentType
{
	eIntegerType,
	ePointerType,
	eRAW
};

class cArgument
{
public:
	cArgument(std::string Data, eArgumentType eType = ePointerType);
	cArgument(std::vector<uint8_t> Data, eArgumentType eType = ePointerType);
	cArgument(uint32_t Data, eArgumentType eType = eIntegerType);

	std::string GenerateRepresentation();

	eArgumentType			ArgumentType;
	std::vector<uint8_t>	ByteData;
	uint32_t				IntegerData;
	std::string				RawData;
};

class cGenASMHelper
{
public:
	static std::string GenerateCallSource(uint32_t CallLocation, std::vector<cArgument> Arguments);
	static std::string GenerateInterdictionStub(uint64_t MemoryLocation, uint64_t FromLocation, uint64_t FunCheckLongList, std::string OperandExpression);
	static std::string GenerateLongLookupTableChecker(uint64_t MemoryLocation, std::map<uint64_t, uint64_t> MemoryTranslation);
};

class cPreparedRemoteBranchPatches
{
public:
	cPreparedRemoteBranchPatches(uint64_t aOriginalBranchLocation, uint64_t aOriginalBranchSize);

	uint64_t BranchLocation;
	uint64_t BranchSize;
};

class cRemoteQuickResponseWriter
{
public:

};

class cRemoteQuickResponseReader
{
public:

};

class cDirtyRangeMarker
{
private:
	static std::vector<std::pair<uint64_t, uint64_t>> _DirtyRanges;

public:

	static bool IsPointerDirty(uint64_t Pointer);
	static bool IsRangeDirty(uint64_t RangeStart, uint64_t RangeEnd);
	static void AddDirtyRange(uint64_t RangeStart, uint64_t RangeEnd);
};

class cRemoteLongLookupInteraction
{
public:
	static std::map<uint64_t, uint64_t> ReadRemoteLookupTable(std::shared_ptr<cProcessInformation> pProcess, uint64_t LookupLocation);
	static void WriteRemoteLookupTable(std::shared_ptr<cProcessInformation> pProcess, uint64_t LookupLocation, const std::string& NasmPath, const std::map<uint64_t, uint64_t>& Table);
};

class cRemoteFreeBranchInterdictor
{
private:
	static std::vector<cPreparedRemoteBranchPatches>	_TargetFreeBranchesSizeFive;
	static std::vector<cPreparedRemoteBranchPatches>	_TargetFreeBranchesSizeFour;
	static std::map<uint64_t, uint64_t>					_LocalLookupTable;

	static uint64_t _RemoteInterdictedLookupTable;
	static bool _Commited;

	static bool InterdictLargeFreeBranch(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess, uint64_t RemoteLongLookupTable, uint64_t BranchLocation);
	static bool InterdictShortFreeBranch(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess, uint64_t RemoteLongLookupTable, uint64_t BranchLocation);

public:
	static bool PrepareBranchInterdiction(uint64_t BranchLocation, uint64_t BranchSize);

	static void MassAddToLookupTable(cDisassembledPage& OriginalPage, cDisassembledPage& NewPage, uint64_t ModifyIndex, uint64_t NewPageStartIndex, uint8_t NumChanges);
	static void AddToLookupTable(uint64_t OriginalRemoteLocation, uint64_t NewRemoteLocation);
	static void Commit(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess);
};

#endif