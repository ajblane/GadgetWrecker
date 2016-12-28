
#include "cProcess.hpp"
#include "../Shared/Utilities/cUtilities.hpp"

cHandleWrapper::cHandleWrapper(HANDLE ahHandle)
	: hHandle(ahHandle)
{}

cHandleWrapper::~cHandleWrapper()
{
	if (hHandle != INVALID_HANDLE_VALUE)
		CloseHandle(hHandle);

	hHandle = INVALID_HANDLE_VALUE;
}

cModuleWrapper::cModuleWrapper(DWORD aOwnerId, void* ahModule, void* ahModuleEnd, std::wstring aModulename, eModuleType aType)
	: OwnerId(aOwnerId), hModule(ahModule), hModuleEnd(ahModuleEnd), ModuleName(aModulename), Type(aType)
{
}

cThreadInformation::cThreadInformation(DWORD aOwnerId, DWORD aThreadId)
	: OwnerId(aOwnerId), ThreadId(aThreadId), ThreadHandle(nullptr)
{
}

cThreadInformation::cThreadInformation(DWORD aOwnerId, DWORD aThreadId, HANDLE hThread)
	: OwnerId(aOwnerId), ThreadId(aThreadId), ThreadHandle(std::make_shared<cHandleWrapper>(hThread))
{
}

bool cThreadInformation::IsThreadOpened()
{
	if (ThreadHandle == nullptr)
		return false;

	return ThreadHandle->hHandle != INVALID_HANDLE_VALUE;
}

bool cThreadInformation::OpenThread()
{
	if (IsThreadOpened())
		return true;

	if (ThreadId == 0)
		return false;

	HANDLE hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);

	if (hThread != 0 && hThread != INVALID_HANDLE_VALUE)
		ThreadHandle = std::make_shared<cHandleWrapper>(hThread);

	return IsThreadOpened();
}

bool cThreadInformation::SuspendThread()
{
	if (!IsThreadOpened())
		return false;

	if (::SuspendThread(ThreadHandle->hHandle) == -1)
		return false;

	return true;
}

bool cThreadInformation::ResumeThread()
{
	if (!IsThreadOpened())
		return false;

	if (::ResumeThread(ThreadHandle->hHandle) == -1)
		return false;

	return true;
}

DWORD cThreadInformation::GetExitCode()
{
	if (!IsThreadOpened())
		return 0;

	DWORD Result = 0;

	if (!GetExitCodeThread(ThreadHandle->hHandle, &Result))
		return 0;

	return Result;
}

DWORD cThreadInformation::WaitForExitCode()
{
	if (!IsThreadOpened())
		return 0;

	WaitForSingleObject(ThreadHandle->hHandle, INFINITE);

	return GetExitCode();
}

cProcessInformation::cProcessInformation(const std::wstring Name)
	: ProcessName(Name), ProcessId(0), ProcessHandle(nullptr)
{
	ProcessId = GetProcessIdFromName(Name);
}

cProcessInformation::cProcessInformation(DWORD Id)
	: ProcessId(Id), ProcessName(L"Error")
{
	ProcessName = GetProcessNameFromid(Id);
}

bool cProcessInformation::IsProcessOpened()
{
	if (ProcessHandle == nullptr)
		return false;

	return ProcessHandle->hHandle != INVALID_HANDLE_VALUE;
}

bool cProcessInformation::OpenProcess()
{
	if (IsProcessOpened())
		return true;

	if (ProcessId == 0)
		return false;

	HANDLE hProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	if (hProc != 0 && hProc != INVALID_HANDLE_VALUE)
		ProcessHandle = std::make_shared<cHandleWrapper>(hProc);

	return IsProcessOpened();
}

bool cProcessInformation::SuspendProcess()
{
	auto Threads = cProcessInformation::GetProcessThreads(ProcessId);

	bool Result = true;

	for (auto x : Threads)
	{
		x.OpenThread();
		if (x.SuspendThread() == false)
			Result = false;
	}

	return Result;
}

bool cProcessInformation::ResumeProcess()
{
	auto Threads = cProcessInformation::GetProcessThreads(ProcessId);

	bool Result = true;

	for (auto x : Threads)
	{
		x.OpenThread();
		if (x.ResumeThread() == false)
			Result = false;
	}

	return Result;
}

void* cProcessInformation::AllocateMemoryInProcess(size_t Size)
{
	if (!IsProcessOpened())
		return NULL;

	void* pMemory = VirtualAllocEx(ProcessHandle->hHandle, NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	return pMemory;
}

void cProcessInformation::FreeMemoryInProcess(void* pMemory)
{
	if (!IsProcessOpened())
		return;

	VirtualFreeEx(ProcessHandle->hHandle, pMemory, NULL, MEM_RELEASE);
}

bool cProcessInformation::WriteMemoryInProcess(void* pLocation, const std::vector<uint8_t>& Data)
{
	DWORD BytesWritten = 0;

	if (!IsProcessOpened())
		return false;

	if (!WriteProcessMemory(ProcessHandle->hHandle, pLocation, (void*)Data.data(), Data.size(), &BytesWritten))
		return false;

	if (BytesWritten != Data.size())
		return false;

	return true;
}

std::vector<uint8_t> cProcessInformation::ReadMemoryInprocess(void* pLocation, size_t Size)
{
	DWORD BytesRead = 0;

	if (!IsProcessOpened())
		return std::vector<uint8_t>();

	std::vector<uint8_t> Memory;

	Memory.resize(Size);

	if (!ReadProcessMemory(ProcessHandle->hHandle, pLocation, (void*)Memory.data(), Memory.size(), &BytesRead))
		return std::vector<uint8_t>();

	if (BytesRead != Size)
		return std::vector<uint8_t>();

	return Memory;
}

std::shared_ptr<cThreadInformation> cProcessInformation::StartThreadInProcess(void* pLocation, void* pArgument)
{
	if (!IsProcessOpened())
		return  std::make_shared<cThreadInformation>(0, 0);

	DWORD Tid;

	HANDLE hThread = CreateRemoteThread(ProcessHandle->hHandle, NULL, 0, (LPTHREAD_START_ROUTINE)pLocation, pArgument, 0, &Tid);

	return std::make_shared<cThreadInformation>(ProcessId, Tid, hThread);
}

void cProcessInformation::TerminateProcess()
{
	::TerminateProcess(ProcessHandle->hHandle, 0);
}

DWORD cProcessInformation::GetExitCode()
{
	if (!IsProcessOpened())
		return 0;

	DWORD Result = 0;

	if (!GetExitCodeProcess(ProcessHandle->hHandle, &Result))
		return 0;

	return Result;
}

DWORD cProcessInformation::WaitForExitCode()
{
	if (!IsProcessOpened())
		return 0;

	WaitForSingleObject(ProcessHandle->hHandle, INFINITE);

	return GetExitCode();
}

bool cProcessInformation::IsProcessRunning()
{
	DWORD ExitCode = GetExitCode();

	return ExitCode == STILL_ACTIVE;
}

std::wstring cProcessInformation::GetProcessNameFromid(const DWORD Id)
{
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 Entry = {};

	Entry.dwSize = sizeof(Entry);

	auto Cleanup = [&](std::wstring Name) -> std::wstring
	{
		if (hSnap != INVALID_HANDLE_VALUE)
			CloseHandle(hSnap);

		hSnap = INVALID_HANDLE_VALUE;

		return Name;
	};

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (hSnap == INVALID_HANDLE_VALUE)
		return Cleanup(L"Error");

	if (!Process32First(hSnap, &Entry))
		return Cleanup(L"Error");

	if (Entry.th32ProcessID == Id)
		return Cleanup(Entry.szExeFile);

	while (Process32Next(hSnap, &Entry))
		if (Entry.th32ProcessID == Id)
			return Cleanup(Entry.szExeFile);

	return Cleanup(L"Error");
}

DWORD cProcessInformation::GetProcessIdFromName(const std::wstring& Name)
{
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 Entry = {};

	Entry.dwSize = sizeof(Entry);

	auto Cleanup = [&](DWORD Id = 0) -> DWORD
	{
		if (hSnap != INVALID_HANDLE_VALUE)
			CloseHandle(hSnap);

		hSnap = INVALID_HANDLE_VALUE;

		return Id;
	};

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (hSnap == INVALID_HANDLE_VALUE)
		return Cleanup();

	if (!Process32First(hSnap, &Entry))
		return Cleanup();

	if (Entry.szExeFile == Name)
		return Cleanup(Entry.th32ProcessID);

	while (Process32Next(hSnap, &Entry))
		if (Entry.szExeFile == Name)
			return Cleanup(Entry.th32ProcessID);

	return Cleanup();
}

std::vector<cThreadInformation> cProcessInformation::GetProcessThreads(DWORD Id)
{
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	std::vector<cThreadInformation> Result;
	THREADENTRY32 Entry = {};

	Entry.dwSize = sizeof(Entry);

	auto Cleanup = [&](std::vector<cThreadInformation> Threads = {}) -> std::vector<cThreadInformation>
	{
		if (hSnap != INVALID_HANDLE_VALUE)
			CloseHandle(hSnap);

		hSnap = INVALID_HANDLE_VALUE;

		return Threads;
	};

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, Id);

	if (hSnap == INVALID_HANDLE_VALUE)
		return Cleanup();

	if (!Thread32First(hSnap, &Entry))
		return Cleanup();

	if (Entry.th32OwnerProcessID == Id)
		Result.push_back(cThreadInformation(Entry.th32OwnerProcessID, Entry.th32ThreadID));

	while (Thread32Next(hSnap, &Entry))
		if (Entry.th32OwnerProcessID == Id)
			Result.push_back(cThreadInformation(Entry.th32OwnerProcessID, Entry.th32ThreadID));

	return Cleanup(Result);
}

std::vector<cModuleWrapper> cProcessInformation::GetProcessModules(DWORD Id)
{
	HMODULE Modules[4096] = {};
	DWORD cbNeeded;
	size_t i;
	std::vector<cModuleWrapper> Result;

	cProcessInformation aProc(Id);

	if (!aProc.OpenProcess())
		return Result;

	if (!EnumProcessModules(aProc.ProcessHandle->hHandle, Modules, sizeof(Modules), &cbNeeded))
		return Result;

	for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
	{
		TCHAR szModName[MAX_PATH];
		MODULEINFO aInfo = {};

		if (GetModuleFileNameEx(aProc.ProcessHandle->hHandle, Modules[i], szModName, sizeof(szModName) / sizeof(TCHAR)) == false)
			continue;

		if (GetModuleInformation(aProc.ProcessHandle->hHandle, Modules[i], &aInfo, sizeof(aInfo)) == false)
			continue;

		Result.push_back(cModuleWrapper(Id, (void*)Modules[i], (void*)(Modules[i] + aInfo.SizeOfImage), szModName, eModuleBits32));
	}

	return Result;
}

std::shared_ptr<cProcessInformation> cProcess::StartProcess(const std::wstring& Path, const std::wstring& Arguments, bool SuspendProcess)
{
	PROCESS_INFORMATION PI = {};
	STARTUPINFOW SI = {};

	SI.cb = sizeof(STARTUPINFOA);

	SI.wShowWindow = 0;

	if (!CreateProcessW(Path.c_str(), (LPWSTR)Arguments.c_str(), NULL, NULL, TRUE, SuspendProcess ? CREATE_SUSPENDED : NULL, NULL, NULL, &SI, &PI))
		throw std::exception(cUtilities::FormatExceptionString("cChannels", "!CreateProcessW(Path.c_str(), (LPWSTR)Arguments.c_str(), NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)").c_str());

	CloseHandle(PI.hThread);
	CloseHandle(PI.hProcess);

	auto aProc = std::make_shared<cProcessInformation>(PI.dwProcessId);
	aProc->OpenProcess();

	return aProc;
}

std::shared_ptr<cProcessInformation> cProcess::OpenProcess(const std::wstring& Name)
{
	auto aProc = std::make_shared<cProcessInformation>(Name);

	aProc->OpenProcess();

	return aProc;
}

std::shared_ptr<cProcessInformation> cProcess::OpenProcess(DWORD Id)
{
	auto aProc = std::make_shared<cProcessInformation>(Id);

	aProc->OpenProcess();

	return aProc;
}

std::vector<std::shared_ptr<cProcessInformation>> cProcess::OpenAllProcesses()
{
	std::vector<std::shared_ptr<cProcessInformation>> Result;
	std::vector<std::shared_ptr<cProcessInformation>> RealResult;

	DWORD Processes[4096], cbNeeded, cProcesses;

	if (!EnumProcesses(Processes, sizeof(Processes), &cbNeeded))
		return Result;

	cProcesses = cbNeeded / sizeof(DWORD);

	for (size_t i = 0; i < cProcesses; i++)
		if (Processes[i] != 0)
			Result.push_back(std::make_shared<cProcessInformation>(Processes[i]));

	for (auto x : Result)
		if (x->OpenProcess())
			RealResult.push_back(x);

	return RealResult;
}