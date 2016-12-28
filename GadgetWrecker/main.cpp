

#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <random>

#include "cProcess.hpp"
#include "cStaticAnalysis.hpp"

#include "../Shared/Utilities/cUtilities.hpp"

void Usage(char* Arg0)
{
	std::cout << "Usage: " << Arg0 << std::endl
		<< "Required arguments: " << std::endl
		<< "\t--target <process name> ; the process to open and patch gadgets in" << std::endl
		<< "\t--number <number> ; The number of gadgets to patch" << std::endl
		<< "Example: " << std::endl
		<< Arg0 << " --target <process name> --number <number of returns to patch>" << std::endl
		<< "Optional arguments: " << std::endl
		<< "\t --nasm </path/to/nasm> ; defaults to: ./Dependencies/nasm.exe" << std::endl;

	exit(0);
}

int main(int argc, char** argv)
{
	std::string NasmPath = "./Dependencies/nasm.exe";

	auto Parameters = cUtilities::ParseArguments(argv, argc);

	if (Parameters.size() == 0)
		Usage(argv[0]);

	if (Parameters.find("help") != Parameters.end()
		|| Parameters.find("--h") != Parameters.end() || Parameters.find("-h") != Parameters.end() || Parameters.find("h") != Parameters.end()
		|| Parameters.find("/h") != Parameters.end() || Parameters.find("?") != Parameters.end() || Parameters.find("/?") != Parameters.end()
		|| Parameters.find("--target") == Parameters.end() || Parameters.find("--number") == Parameters.end()
		)
		Usage(argv[0]);

	
	std::string Target = Parameters["--target"];

	if (Parameters.find("--nasm") != Parameters.end())
		NasmPath = Parameters["--nasm"];
	
	auto pProcessInfo = cProcess::OpenProcess(cUtilities::StringToWideString(Target));

	std::cout << "Wrecking ROP gadgets in: " << Target << " [" << pProcessInfo->ProcessId << "]" << std::endl;

	auto LoadedModules = cProcessInformation::GetProcessModules(pProcessInfo->ProcessId);

	std::cout << "Scanning memory space of: " << LoadedModules.size() << " modules" << std::endl;

	std::vector<uint64_t> ReturnPointers;

	size_t Counter = 0;

	for (auto aModule : LoadedModules)
	{
		auto TempResult = cStaticAnalysis::AnalyseModule(pProcessInfo, aModule);

		ReturnPointers.insert(ReturnPointers.end(), TempResult.begin(), TempResult.end());

		if (Counter++ % 10 == 0)
			std::cout << "Progress: " << Counter << "/" << LoadedModules.size() << std::endl;
	}

	std::cout << "Found: " << ReturnPointers.size() << " possible gadgets" << std::endl;

	std::cout << "Shuffeling pointers" << std::endl;

	std::shuffle(ReturnPointers.begin(), ReturnPointers.end(), std::random_device());

	std::cout << "Suspending process" << std::endl;

	if (pProcessInfo->SuspendProcess())
		std::cout << "Warning: One or more threads are not suspended, process is not completely suspended" << std::endl;

	std::cout << "Patching: " << Parameters["--number"] << " random pointers" << std::endl;

	size_t PatchCounter = strtol(Parameters["--number"].c_str(), NULL, 10);

	for (auto pPointer: ReturnPointers)
	{
		if (PatchCounter-- == 0)
			break;
		try
		{
			cStaticAnalysis::PatchAlignedRetInstruction(NasmPath, pProcessInfo, pPointer);
		}
		catch (std::exception e)
		{
			std::cout << "Exception: " << e.what() << std::endl;
		}
		catch (std::string e)
		{
			std::cout << "Exception: " << e << std::endl;
		}
		catch (...)
		{
			std::cout << "Unhandled exception" << std::endl;
		}
	}

	std::cout << "Resuming process" << std::endl;

	if (pProcessInfo->ResumeProcess() == false)
		std::cout << "Warning: One or more threads are not resumed, process is not completely resumed" << std::endl;

	return 0;
}