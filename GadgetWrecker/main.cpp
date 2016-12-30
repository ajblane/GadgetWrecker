

#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <random>

#include "cProcess.hpp"
#include "cGenASM.hpp"
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

	auto OtherFreeBranches = cFreeBranchReferenceCounter::GetAllFreeBranches();

	if (OtherFreeBranches.size() > 0)
	{
		std::cout << "Warning: Patch target will become unstable: Found free branch instructions of which:" << std::endl;
		
		size_t RegJumps = 0;
		size_t StatJumps = 0;

		size_t PreparedInterdictions = 0;

		size_t Counter = 100;

		//std::shuffle(OtherFreeBranches.begin(), OtherFreeBranches.end(), std::random_device());

		for (auto x : OtherFreeBranches)
		{
			if (Counter-- == 0)
				break;

			if (cStaticReferenceCounter::IsReferenced(x.first) == false)
			{
				if (cRemoteFreeBranchInterdictor::PrepareBranchInterdiction(x.first, x.second))
				{
					std::cout << "Patching: 0x" << std::hex << x.first << std::endl;
					// TODO: make sure these pointers travel back in time and are fixed before the LongLookup table is written to the remote process.
					//cRemoteFreeBranchInterdictor::AddToLookupTable(x.first, 0); // Rewriting
					PreparedInterdictions++;
				}
			}

			if (x.second <= 3)
				RegJumps++;
			else if (x.second >= 4)
				StatJumps++;
		}

		std::cout << "\t" << RegJumps << " are of size 3 or less, and are bad" << std::endl;
		std::cout << "\t" << StatJumps << " are of size 4 or more, and are good" << std::endl;
		std::cout << "\t" << PreparedInterdictions << " have been registered for an interdiction" << std::endl;
		std::cout << "Warning: Freebranch interdiction is is based on a best-effort basis, since it's not possible to rewrite all calls for now" << std::endl;
	}

	std::cout << "Shuffling pointers" << std::endl;

	std::shuffle(ReturnPointers.begin(), ReturnPointers.end(), std::random_device());

	std::cout << "Suspending process" << std::endl;

	if (pProcessInfo->SuspendProcess() == false)
		std::cout << "Warning: One or more threads are not suspended, process is not completely suspended" << std::endl;

	std::cout << "Patching: " << Parameters["--number"] << " random pointers" << std::endl;

	size_t PatchCounter = strtol(Parameters["--number"].c_str(), NULL, 10);

	for (auto pPointer: ReturnPointers)
	{
		if (PatchCounter-- == 0)
			break;
		try
		{
			uint64_t PatchedTo = cStaticAnalysis::PatchAlignedRetInstruction(NasmPath, pProcessInfo, pPointer);

			if(PatchedTo > 0)
				cRemoteFreeBranchInterdictor::AddToLookupTable(pPointer, PatchedTo);
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

	std::cout << "Patching free branches" << std::endl;

	try
	{
		cRemoteFreeBranchInterdictor::Commit(NasmPath, pProcessInfo);
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

	std::cout << "Resuming process" << std::endl;

	if (pProcessInfo->ResumeProcess() == false)
		std::cout << "Warning: One or more threads are not resumed, process is not completely resumed" << std::endl;

	return 0;
}