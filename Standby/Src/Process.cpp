#include "Process.h"

#define HANDLE_OPENPROCESS 0
#define HANDLE_NTOPENPROCESS 1
#define HANDLE_NTOPENPROCESSIMP 2
#define HANDLE_HANDLEHIJACK 3

#define THREADHANDLE_OPENTHREAD 0
#define THREADHANDLE_NTOPENTHREAD 1
#define THREADHANDLE_NTOPENTHREADIMP 2

#define HANDLE_TYPE_PROCESS 7

tNtOpenProcess fNtOpenProcess = nullptr;
tNtOpenThread fNtOpenThread = nullptr;
tNtQuerySystemInformation fNtQuerySystemInformation = nullptr;
tNtQueryObject fNtQueryObject = nullptr;
tNtDuplicateObject fNtDuplicateObject = nullptr;

namespace Standby
{
	HANDLE ProcessHandle;

	int HandleRetrieveMode = HANDLE_OPENPROCESS;

	BOOLEAN HandleRetrieve()
	{
		Debug("[*] Getting process handle.");

		if (ProcessHandle)
		{
			CloseHandle(ProcessHandle);
			ProcessHandle = NULL;

			Debug("[*] Old process handle closed.");
		}

		switch (HandleRetrieveMode)
		{
		case HANDLE_OPENPROCESS:
			return HandleRetrieve_OpenProcess();
		case HANDLE_NTOPENPROCESS:
			return HandleRetrieve_NtOpenProcess();
		case HANDLE_NTOPENPROCESSIMP:
			return HandleRetrieve_NtOpenProcessImp();
		case HANDLE_HANDLEHIJACK:
			return HandleRetrieve_HandleHijack();
		}

		return true;
	}

	BOOLEAN HandleRetrieve_OpenProcess()
	{
		Debug("[*] Retrieving handle through OpenProcess.");

		ProcessHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, pSelectedProcess->Pid);
		if (ProcessHandle == INVALID_HANDLE_VALUE)
		{
			Debug("[-] Handle couldn't be retrieved, OpenProcess");
			return false;
		}

		return true;
	}

	BOOLEAN HandleRetrieve_NtOpenProcess()
	{
		Debug("[*] Retrieving handle through NtOpenProcess.");

		OBJECT_ATTRIBUTES ObjAttr = {};

		CLIENT_ID ClientId = {};
		ClientId.UniqueProcess = (PVOID)pSelectedProcess->Pid;
		ClientId.UniqueThread = (PVOID)pSelectedProcess->BaseThreadId;

		NTSTATUS Status = fNtOpenProcess(&ProcessHandle, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, &ObjAttr, &ClientId);
		if (!NT_SUCCESS(Status))
		{
			Debug("Handle couldn't be retrieved, NtOpenProcess.");
			return false;
		}

		return true;
	}

	BOOLEAN HandleRetrieve_NtOpenProcessImp()
	{
		Debug("[*] Retrieving handle through NtOpenProcessImp.");

		OBJECT_ATTRIBUTES ObjAttr = {};

		CLIENT_ID ClientId = {};
		ClientId.UniqueProcess = (PVOID)pSelectedProcess->Pid;
		ClientId.UniqueThread = (PVOID)pSelectedProcess->BaseThreadId;

		NTSTATUS Status = NtOpenProcess(&ProcessHandle, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, &ObjAttr, &ClientId);
		if (!NT_SUCCESS(Status))
		{
			Debug("Handle couldn't be retrieved, NtOpenProcessImp");
			return false;
		}

		return true;
	}

	BOOLEAN HandleRetrieve_HandleHijack()
	{
		Debug("[*] Retrieving handle through HandleHijack.");

		// PcaSvc is the service which's process (svchost.exe) has a HANDLE with PROCESS_ALL_ACCESS permission to almost every process in the system.
		const DWORD SvcPid = HandleRetrieve_HandleHijack_GetSvcPidByName("PcaSvc");

		// Starting off with a little size, will be increased over failed attempts.
		// Using std::vector for memory safety.
		ULONG ReturnLength = 16;
		std::vector<BYTE> HandleMemory(ReturnLength, 0);

		NTSTATUS Status = STATUS_SUCCESS;
		SIZE_T IterateTimes = 0;
		while (Status = fNtQuerySystemInformation(SystemHandleInformation, &HandleMemory[0], ReturnLength, &ReturnLength), !NT_SUCCESS(Status))
		{
			HandleMemory.resize(ReturnLength);

			if (Status = fNtQuerySystemInformation(SystemHandleInformation, &HandleMemory[0], ReturnLength, &ReturnLength), NT_SUCCESS(Status))
				break;

			// If it still couldn't get the handle in the 100th time then we just quit to prevent deadlock.
			if (++IterateTimes >= 100)
			{
				Debug("[-] NtQuerySystemInformation couldn't retrieve handle information.");
				return false;
			}
		}

		// Storing the pointer at a different variable so we don't have to keep doing ' (PSYSTEM_HANDLE_INFORMATION)&HandleMemory[0] '.
		PSYSTEM_HANDLE_INFORMATION SysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)&HandleMemory[0];

		// Opening an handle to the service.
		HANDLE SvcHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, SvcPid);
		if (!SvcHandle)
		{
			Debug("[-] OpenProcess for SvcHandle failed.");
			return false;
		}

		// Iterating through all the handles.
		for (int i = 0; i < SysHandleInfo->HandleCount; i++)
		{
			const SYSTEM_HANDLE& IdxHandleEntry = SysHandleInfo->Handles[i];

			// ProcessId is the process who opened this handle, in our case since we are iterating through EVERY handle we must guarantee it was opened by our service process.
			// GrantedAccess is the accesses the handle have, if it doesn't have PROCESS_ALL_ACCESS it's unusable.
			// ObjectTypeNumber is a number indicating the handle type (yes) so we are checking if it's a process handle since we are hijack the handle of a process.
			if (IdxHandleEntry.ProcessId != SvcPid ||
				IdxHandleEntry.GrantedAccess != PROCESS_ALL_ACCESS ||
				IdxHandleEntry.ObjectTypeNumber != HANDLE_TYPE_PROCESS)
				continue;

			// Duplicating the handle so we can query it and use it later on.
			HANDLE DupHandle = 0;
			if (Status = fNtDuplicateObject(SvcHandle, (HANDLE)IdxHandleEntry.Handle, GetCurrentProcess(), &DupHandle, NULL, NULL, DUPLICATE_SAME_ACCESS), !NT_SUCCESS(Status))
			{
				Debug("[-] NtDuplicateObject failed");
				return false;
			}

			// Validating that the process this handle was opened for is our target process, if it is we return the handle.
			if (GetProcessId(DupHandle) == Pid)
			{
				ProcessHandle = DupHandle;
				return true;
			}

			// Otherwise we close this handle and continue iterating through the other handles.
			if (!CloseHandle(DupHandle))
				Debug("[-] CloseHandle for DupHandle failed");
		}

		Debug("[-] An open handle against the target process couldn't be found.\n");
		return false;
	}

	DWORD HandleRetrieve_HandleHijack_GetSvcPidByName(const char* SvcName)
	{
		DWORD SvcPid = 0;

		SC_HANDLE SvcManagerHandle = 0;
		SC_HANDLE SvcHandle = 0;
		do
		{
			// Getting an handle to the service manager.
			SvcManagerHandle = OpenSCManagerA(NULL, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT);
			if (!SvcManagerHandle)
			{
				Debug("[-] OpenSCManagerA failed.");
				break;
			}

			// Opening the service with the name SvcName from the service manager.
			SvcHandle = OpenServiceA(SvcManagerHandle, SvcName, GENERIC_READ);
			if (!SvcHandle)
			{
				Debug("[-] OpenServiceA failed.");
				break;
			}

			// Querying the returned service so we can get it's PID.
			SERVICE_STATUS_PROCESS SvcStatus = {};
			DWORD BytesNeeded = 0;
			if (!QueryServiceStatusEx(SvcHandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&SvcStatus, sizeof(SERVICE_STATUS_PROCESS), &BytesNeeded))
			{
				Debug("[-] QueryServiceStatusEx failed.");
				break;
			}

			SvcPid = SvcStatus.dwProcessId;
		} while (FALSE);

		if (SvcHandle && !CloseServiceHandle(SvcHandle))
			Debug("[-] CloseServiceHandle for SvcHandle failed.");

		if (SvcManagerHandle && !CloseServiceHandle(SvcManagerHandle))
			Debug("[-] CloseServiceHandle for SvcManagerHandle failed.");

		return SvcPid;
	}

	int ThreadHandleRetrieveMode = THREADHANDLE_OPENTHREAD;

	HANDLE ThreadHandleRetrieve(DWORD dwDesiredAccess, DWORD dwThreadId)
	{
		Debug("[*] Getting thread handle.");

		switch (ThreadHandleRetrieveMode)
		{
		case THREADHANDLE_OPENTHREAD:
			return ThreadHandleRetrieve_OpenThread(dwDesiredAccess, dwThreadId);
		case THREADHANDLE_NTOPENTHREAD:
			return ThreadHandleRetrieve_NtOpenThread(dwDesiredAccess, dwThreadId);
		case THREADHANDLE_NTOPENTHREADIMP:
			return ThreadHandleRetrieve_NtOpenThreadImp(dwDesiredAccess, dwThreadId);
		}

		return NULL;
	}

	HANDLE ThreadHandleRetrieve_OpenThread(DWORD dwDesiredAccess, DWORD dwThreadId)
	{
		Debug("[*] Retrieving thread handle through OpenThread.");

		HANDLE ThreadHandle = OpenThread(dwDesiredAccess, FALSE, dwThreadId);
		if (!ThreadHandle)
			Debug("[-] Thread handle couldn't be retrieved, OpenThread.");

		return ThreadHandle;
	}

	HANDLE ThreadHandleRetrieve_NtOpenThread(DWORD dwDesiredAccess, DWORD dwThreadId)
	{
		Debug("[*] Retrieving thread handle through NtOpenThread.");

		HANDLE ThreadHandle = NULL;

		OBJECT_ATTRIBUTES ObjAttrib = {};
#ifndef _WIN64
		ObjAttrib.Length = 24;
#endif

		CLIENT_ID ClientId = {};
		ClientId.UniqueProcess = (PVOID)GetProcessId(ProcessHandle);
		ClientId.UniqueThread = (PVOID)dwThreadId;

		NTSTATUS Status = fNtOpenThread(&ThreadHandle, dwDesiredAccess, &ObjAttrib, &ClientId);
		if (!NT_SUCCESS(Status))
			Debug("[-] Thread handle couldn't be retrieved, NtOpenThread");

		return ThreadHandle;
	}

	HANDLE ThreadHandleRetrieve_NtOpenThreadImp(DWORD dwDesiredAccess, DWORD dwThreadId)
	{
		Debug("[*] Retrieving thread handle through NtOpenThreadImp.");

		HANDLE ThreadHandle = NULL;

		OBJECT_ATTRIBUTES ObjAttrib = {};
#ifndef _WIN64
		ObjAttrib.Length = 24;
#endif

		CLIENT_ID ClientId = {};
		ClientId.UniqueProcess = (PVOID)GetProcessId(ProcessHandle);
		ClientId.UniqueThread = (PVOID)dwThreadId;

		NTSTATUS Status = NtOpenThread(&ThreadHandle, dwDesiredAccess, &ObjAttrib, &ClientId);
		if (!NT_SUCCESS(Status))
			Debug("[-] Thread handle couldn't be retrieved, NtOpenThread");

		return ThreadHandle;
	}
}