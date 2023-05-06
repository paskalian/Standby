#pragma once

#include "Includes.h"

using tNtOpenProcess = NTSTATUS(__stdcall*)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
extern tNtOpenProcess fNtOpenProcess;

extern "C" NTSTATUS __stdcall NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

using tNtQuerySystemInformation = NTSTATUS(__stdcall*)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
extern tNtQuerySystemInformation fNtQuerySystemInformation;

using tNtQueryObject = NTSTATUS(__stdcall*)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
extern tNtQueryObject fNtQueryObject;

using tNtDuplicateObject = NTSTATUS(__stdcall*)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
extern tNtDuplicateObject fNtDuplicateObject;

using tNtOpenThread = NTSTATUS(__stdcall*)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
extern tNtOpenThread fNtOpenThread;

extern "C" NTSTATUS __stdcall NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

namespace Standby
{
	extern HANDLE ProcessHandle;

	extern int HandleRetrieveMode;

	BOOLEAN HandleRetrieve();

	BOOLEAN HandleRetrieve_OpenProcess();
	BOOLEAN HandleRetrieve_NtOpenProcess();
	BOOLEAN HandleRetrieve_NtOpenProcessImp();
	BOOLEAN HandleRetrieve_HandleHijack();
	DWORD HandleRetrieve_HandleHijack_GetSvcPidByName(const char* SvcName);

	extern int ThreadHandleRetrieveMode;

	HANDLE ThreadHandleRetrieve(DWORD dwDesiredAccess, DWORD dwThreadId);

	HANDLE ThreadHandleRetrieve_OpenThread(DWORD dwDesiredAccess, DWORD dwThreadId);
	HANDLE ThreadHandleRetrieve_NtOpenThread(DWORD dwDesiredAccess, DWORD dwThreadId);
	HANDLE ThreadHandleRetrieve_NtOpenThreadImp(DWORD dwDesiredAccess, DWORD dwThreadId);
}