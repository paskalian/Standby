#pragma once

#include "Includes.h"

using tNtOpenProcess = NTSTATUS(__fastcall*)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
extern tNtOpenProcess fNtOpenProcess;

extern "C" NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

namespace Standby
{
	extern HANDLE ProcessHandle;

	extern int HandleRetrieveMode;

	BOOLEAN HandleRetrieve();

	BOOLEAN HandleRetrieve_OpenProcess();
	BOOLEAN HandleRetrieve_NtOpenProcess();
	BOOLEAN HandleRetrieve_NtOpenProcessImp();
	BOOLEAN HandleRetrieve_HandleHijack();
}