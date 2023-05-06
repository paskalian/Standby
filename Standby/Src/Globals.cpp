#include "Globals.h"

namespace Standby
{
	HWND* pMainWnd = nullptr;
	BOOLEAN bMainLoop = TRUE;

	BOOLEAN bSelectProcess = FALSE;
	BOOLEAN bSelectProcess_Confirm = FALSE;
	CHAR FilterProcess[MAX_PATH];
	std::vector<PROCESSINFORMATION> ProcessList;
	PROCESSINFORMATION* pSelectedProcess = nullptr;

	DWORD Pid = -1;

	std::vector<DLLINFORMATION> DllList;
	DLLINFORMATION* pSelectedDll = nullptr;

	std::vector<std::string> DebugMessages;
	std::string SelectedDebugMessage;

	BOOLEAN bConfigure;

	BOOLEAN Init()
	{
		GetAllProcesses();

		static const HMODULE NtdllModule = GetModuleHandleA("NTDLL.DLL");
		fNtOpenProcess = (tNtOpenProcess)GetProcAddress(NtdllModule, "NtOpenProcess");
		fNtOpenThread = (tNtOpenThread)GetProcAddress(NtdllModule, "ZwOpenThread");
		fNtQuerySystemInformation = (tNtQuerySystemInformation)GetProcAddress(NtdllModule, "NtQuerySystemInformation");
		fNtQueryObject = (tNtQueryObject)GetProcAddress(NtdllModule, "NtQueryObject");
		fNtDuplicateObject = (tNtDuplicateObject)GetProcAddress(NtdllModule, "ZwDuplicateObject");

		fNtAllocateVirtualMemory = (tNtAllocateVirtualMemory)GetProcAddress(NtdllModule, "NtAllocateVirtualMemory");
		fNtFreeVirtualMemory = (tNtFreeVirtualMemory)GetProcAddress(NtdllModule, "ZwFreeVirtualMemory");
		fNtReadVirtualMemory = (tNtReadVirtualMemory)GetProcAddress(NtdllModule, "ZwReadVirtualMemory");
		fNtWriteVirtualMemory = (tNtWriteVirtualMemory)GetProcAddress(NtdllModule, "NtWriteVirtualMemory");
		fNtProtectVirtualMemory = (tNtProtectVirtualMemory)GetProcAddress(NtdllModule, "ZwProtectVirtualMemory");
		fNtCreateThreadEx = (tNtCreateThreadEx)GetProcAddress(NtdllModule, "NtCreateThreadEx");

		return TRUE;
	}

	BOOLEAN GetAllProcesses()
	{
		Standby::Debug("[*] Reloading processes.");

		ProcessList.clear();

		pSelectedProcess = nullptr;
		Pid = -1;

		if (ProcessHandle)
		{
			CloseHandle(ProcessHandle);
			ProcessHandle = NULL;

			Debug("[*] Old process handle closed.");
		}

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		PROCESSENTRY32 ProcEntry;
		ProcEntry.dwSize = sizeof(PROCESSENTRY32);

		Process32First(hSnapshot, &ProcEntry);
		do
		{
			char ProcName[MAX_PATH] = {};

			size_t NumConverted = 0;
			wcstombs_s(&NumConverted, ProcName, ProcEntry.szExeFile, MAX_PATH);

			PROCESSINFORMATION NewProcess;
			NewProcess.Name = ProcName;
			NewProcess.Pid = ProcEntry.th32ProcessID;
			//NewProcess.BaseThreadId = GetBaseThread(NewProcess.Pid);

			ProcessList.push_back(NewProcess);
		} while (Process32Next(hSnapshot, &ProcEntry));

		std::sort(ProcessList.begin() + 1, ProcessList.end(), [](PROCESSINFORMATION& Proc1, PROCESSINFORMATION& Proc2)
		{
			return Proc1.Pid < Proc2.Pid;
		});
		
		Standby::Debug("[*] Processes reloaded successfully.");

		CloseHandle(hSnapshot);

		return TRUE;
	}

	DWORD GetBaseThread(DWORD Pid)
	{
		Standby::Debug("[*] Getting base thread.");

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, Pid);

		THREADENTRY32 ThreadEntry;
		ThreadEntry.dwSize = sizeof(THREADENTRY32);

		// Putting an iteration limit to prevent deadlock.
		SIZE_T IterateTimes = 0;
		Thread32First(hSnapshot, &ThreadEntry);
		do
		{
			Thread32Next(hSnapshot, &ThreadEntry);

			IterateTimes++;
			if (IterateTimes >= 10000)
			{
				Debug("[-] Base thread couldn't be found.\n");
				CloseHandle(hSnapshot);
				return 0;
			}
		} while (ThreadEntry.th32OwnerProcessID != Pid);

		CloseHandle(hSnapshot);

		return ThreadEntry.th32ThreadID;
	}


	HANDLE GetBaseThreadHandle(DWORD Pid)
	{
		DWORD Tid = GetBaseThread(Pid);

		HANDLE hThread = ThreadHandleRetrieve(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, Tid);
		if (!hThread)
			Debug("[-] Thread handle couldn't be retrieved.");
		Debug("[*] Thread handle retrieved successfully.");

		return hThread;
	}

	PROCESSINFORMATION_DETAILED GetDetailedProcessInformation(PROCESSINFORMATION& ProcessInfo)
	{
		PROCESSINFORMATION_DETAILED DetailedInfo;

		DetailedInfo.BasicInfo = ProcessInfo;

		CHAR PathBuffer[MAX_PATH]{};
		DWORD PathSize = MAX_PATH;
		QueryFullProcessImageNameA(ProcessHandle, 0, PathBuffer, &PathSize);

		DetailedInfo.Path = PathBuffer;

		PROCESSENTRY32 ProcEntry;
		ProcEntry.dwSize = sizeof(PROCESSENTRY32);

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, DetailedInfo.BasicInfo.Pid);

		Process32First(hSnapshot, &ProcEntry);

		DetailedInfo.ParentPid = ProcEntry.th32ParentProcessID;
		DetailedInfo.ThreadCount = ProcEntry.cntThreads;

		CloseHandle(hSnapshot);

		MODULEENTRY32 ModEntry;
		ModEntry.dwSize = sizeof(MODULEENTRY32);

		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, DetailedInfo.BasicInfo.Pid);

		Module32First(hSnapshot, &ModEntry);
		do
		{
			MODULEINFORMATION ModInfo;
			
			CHAR Buffer[MAX_PATH]{};
			size_t NumberOfCharConverted = 0;
			wcstombs_s(&NumberOfCharConverted, Buffer, ModEntry.szModule, MAX_PATH);

			ModInfo.ModuleName = Buffer;

			memset(Buffer, 0, MAX_PATH);
			wcstombs_s(&NumberOfCharConverted, Buffer, ModEntry.szExePath, MAX_PATH);

			ModInfo.ModulePath = Buffer;

			ModInfo.ModBaseAddr = (UINT_PTR)ModEntry.modBaseAddr;
			ModInfo.ModSize = ModEntry.modBaseSize;


			DetailedInfo.ModulesLoaded.push_back(ModInfo);
		} while (Module32Next(hSnapshot, &ModEntry));

		CloseHandle(hSnapshot);

		return DetailedInfo;
	}

	BOOLEAN InsertDll()
	{
		OPENFILENAMEW ofn;
		ZeroMemory(&ofn, sizeof(ofn));

		wchar_t szFile[MAX_PATH];

		ofn.lStructSize = sizeof(ofn);
		ofn.hwndOwner = *pMainWnd;
		ofn.lpstrFile = szFile;
		ofn.lpstrFile[0] = '\0';
		ofn.nMaxFile = sizeof(szFile);
		ofn.lpstrFilter = L"DLL File\0*.DLL*\0\0";
		ofn.nFilterIndex = 1;
		ofn.lpstrFileTitle = NULL;
		ofn.nMaxFileTitle = 0;
		ofn.lpstrInitialDir = NULL;
		ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

		if (GetOpenFileNameW(&ofn))
		{
			HANDLE FileHandle = CreateFileW(ofn.lpstrFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (FileHandle == INVALID_HANDLE_VALUE)
				return false;

			CHAR FilePath[MAX_PATH] = {};
			GetFinalPathNameByHandleA(FileHandle, FilePath, MAX_PATH, FILE_NAME_NORMALIZED);

			for (auto& DllIdx : DllList)
			{
				if (_stricmp(DllIdx.FullPath.c_str(), FilePath) == 0)
				{
					Standby::Debug("[*] Dll was already inserted.");
					CloseHandle(FileHandle);
					
					return true;
				}
			}

			DLLINFORMATION NewDll;
			NewDll.FullPath = FilePath;
			NewDll.Name = NewDll.FullPath.substr(NewDll.FullPath.find_last_of("/\\") + 1).c_str();

			Standby::Debug("[*] New dll inserted.");

			DllList.push_back(NewDll);

			CloseHandle(FileHandle);
		}
		else
		{
			Standby::Debug("[*] GetOpenFileNameW failed.");
			return false;
		}

		return true;
	}

	VOID Debug(const char* Msg, ...)
	{
		DebugMessages.push_back(Msg);
	}
}