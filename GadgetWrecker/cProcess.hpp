#ifndef C_PROCESSES_HPP
#define  C_PROCESSES_HPP

#include <string>
#include <vector>
#include <memory>

#include <Windows.h>
#include <psapi.h>
#include <TlHelp32.h>

class cHandleWrapper
{
public:
	HANDLE			hHandle;

	cHandleWrapper(HANDLE ahHandle = INVALID_HANDLE_VALUE);

	~cHandleWrapper();
};

enum eModuleType
{
	eModuleBits32,
	eModuleBits64
};

class cModuleWrapper
{
public:
	std::wstring		ModuleName;
	void*				hModule;
	void*				hModuleEnd;
	DWORD				OwnerId;
	eModuleType			Type;

	cModuleWrapper(DWORD aOwnerId, void* ahModule, void* ahModuleEnd, std::wstring aModulename, eModuleType aType);
};

class cThreadInformation
{
public:
	std::shared_ptr<cHandleWrapper>		ThreadHandle;
	DWORD								OwnerId;
	DWORD								ThreadId;

	cThreadInformation(DWORD aOwnerId, DWORD aThreadId);

	cThreadInformation(DWORD aOwnerId, DWORD aThreadId, HANDLE hThread);

	bool IsThreadOpened();

	bool OpenThread();

	bool SuspendThread();

	bool ResumeThread();

	CONTEXT GetThreadContext();
	void	SetThreadContext(const CONTEXT& Context);

	DWORD GetExitCode();

	DWORD WaitForExitCode();
};

class cProcessInformation
{
public:
	std::shared_ptr<cHandleWrapper>		ProcessHandle;
	DWORD								ProcessId;
	std::wstring						ProcessName;

	cProcessInformation(const std::wstring Name);

	cProcessInformation(DWORD Id);

	bool IsProcessOpened();

	bool OpenProcess();

	bool SuspendProcess();

	bool ResumeProcess();

	void* AllocateMemoryInProcess(size_t Size);

	void FreeMemoryInProcess(void* pMemory);

	bool WriteMemoryInProcess(void* pLocation, const std::vector<uint8_t>& Data);

	std::vector<uint8_t> ReadMemoryInprocess(void* pLocation, size_t Size);

	std::shared_ptr<cThreadInformation> StartThreadInProcess(void* pLocation, void* pArgument);

	void TerminateProcess();

	DWORD GetExitCode();

	DWORD WaitForExitCode();

	bool IsProcessRunning();

	static std::wstring GetProcessNameFromid(const DWORD Id);
	static DWORD GetProcessIdFromName(const std::wstring& Name);
	static std::vector<cThreadInformation> GetProcessThreads(DWORD Id);
	static std::vector<cModuleWrapper> GetProcessModules(DWORD Id);
};

class cProcess
{
public:
	static std::shared_ptr<cProcessInformation> StartProcess(const std::wstring& Path, const std::wstring& Arguments, bool SuspendProcess = true);

	static std::shared_ptr<cProcessInformation> OpenProcess(const std::wstring& Name);

	static std::shared_ptr<cProcessInformation> OpenProcess(DWORD Id);

	static std::vector<std::shared_ptr<cProcessInformation>> OpenAllProcesses();
};

#endif