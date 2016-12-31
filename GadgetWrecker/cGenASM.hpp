
#ifndef C_TRAMPOLINES_HPP
#define C_TRAMPOLINES_HPP

#include <map>
#include <string>
#include <vector>
#include <mutex>

#include "cNasmWrapper.hpp"
#include "cProcess.hpp"

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

class cRemoteLongLookupWriter
{
public:
	static void WriteRemoteLookupTable(std::shared_ptr<cProcessInformation> pProcess, uint64_t LookupLocation, const std::map<uint64_t, uint64_t>& Table);
};

class cRemoteLongLookupReader
{
public:
	static std::map<uint64_t, uint64_t> ReadRemoteLookupTable(std::shared_ptr<cProcessInformation> pProcess, uint64_t LookupLocation);
};

class cRemoteFreeBranchInterdictor
{
private:
	static std::vector<cPreparedRemoteBranchPatches>	_PreparedPatches;
	static std::map<uint64_t, uint64_t>					_LocalLookupTable;

	static uint64_t _RemoteInterdictedLookupTable;
	static bool _Commited;

	static bool InterdictFreeBranchSizeFive(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess, uint64_t RemoteLongLookupTable, uint64_t BranchLocation);

public:
	static bool PrepareBranchInterdiction(uint64_t BranchLocation, uint64_t BranchSize);

	static void AddToLookupTable(uint64_t OriginalRemoteLocation, uint64_t NewRemoteLocation);
	static void Commit(const std::string& NasmPath, std::shared_ptr<cProcessInformation> pProcess);
};

#endif