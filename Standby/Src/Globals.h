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

struct DLLINFORMATION
{
	std::string Name;
	std::string FullPath;
};

namespace Standby
{
	extern HWND* pMainWnd;
	extern BOOLEAN bMainLoop;
	extern BOOLEAN bAbout;
	
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

	BOOLEAN InsertDll();

	VOID Debug(const char* Msg, ...);
}