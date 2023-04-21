#include "Process.h"

#define HANDLE_OPENPROCESS 0
#define HANDLE_NTOPENPROCESS 1
#define HANDLE_NTOPENPROCESSIMP 2
#define HANDLE_HANDLEHIJACK 3

tNtOpenProcess fNtOpenProcess = nullptr;

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
			Debug("NtOpenProcess failed.");
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
			Debug("NtOpenProcessImp failed.");
			return false;
		}

		return true;
	}

	BOOLEAN HandleRetrieve_HandleHijack()
	{
		Debug("[*] Retrieving handle through HandleHijack.");

		return true;
	}
}