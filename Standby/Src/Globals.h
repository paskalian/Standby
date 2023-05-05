#pragma once

#include "Includes.h"

#include "Nt.h"
#include "Render.h"
#include "Process.h"
#include "Injection.h"

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define STANDBY_VERSION "1.0"

#define STANDBY_NOPROCESS "No Process Selected"

struct PROCESSINFORMATION
{
	std::string Name;
	DWORD Pid;
	DWORD BaseThreadId;
};

struct MODULEINFORMATION
{
	std::string ModuleName;
	std::string ModulePath;
	UINT_PTR ModBaseAddr;
	UINT_PTR ModSize;
};

struct PROCESSINFORMATION_DETAILED
{
	PROCESSINFORMATION BasicInfo;
	std::string Path;
	DWORD ParentPid;
	DWORD ThreadCount;
	std::vector<MODULEINFORMATION> ModulesLoaded;
};

struct DLLINFORMATION
{
	std::string Name;
	std::string FullPath;
};

namespace Standby
{
	extern HWND* pMainWnd;
	extern BOOLEAN bMainLoop;
	
	extern BOOLEAN bSelectProcess;
	extern BOOLEAN bSelectProcess_Confirm;
	extern CHAR FilterProcess[MAX_PATH];
	extern std::vector<PROCESSINFORMATION> ProcessList;
	extern PROCESSINFORMATION* pSelectedProcess;

	extern DWORD Pid;

	extern std::vector<DLLINFORMATION> DllList;
	extern DLLINFORMATION* pSelectedDll;

	extern std::vector<std::string> DebugMessages;
	extern std::string SelectedDebugMessage;

	extern BOOLEAN bConfigure;

	BOOLEAN Init();
	BOOLEAN GetAllProcesses();
	DWORD GetBaseThread(DWORD Pid);
	HANDLE GetBaseThreadHandle(DWORD Pid);

	PROCESSINFORMATION_DETAILED GetDetailedProcessInformation(PROCESSINFORMATION& ProcessInfo);

	BOOLEAN InsertDll();

	VOID Debug(const char* Msg, ...);
}