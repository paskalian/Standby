#ifndef _WIN64

#include "Includes.h"

__declspec(naked) NTSTATUS __stdcall NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	__asm
	{
		mov eax, 26h
		call dword ptr fs:[0C0h]
		retn 16
	}
}

__declspec(naked) NTSTATUS __stdcall NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	__asm
	{
		mov eax, 137h
		call dword ptr fs:[0C0h]
		retn 16
	}
}

__declspec(naked) NTSTATUS __stdcall NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
	__asm
	{
		mov eax, 18h
		call dword ptr fs:[0C0h]
		retn 24
	}
}

__declspec(naked) NTSTATUS __stdcall NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
{
	__asm
	{
		mov eax, 1Eh
		call dword ptr fs:[0C0h]
		retn 16
	}
}

__declspec(naked) NTSTATUS __stdcall NtReadVirtualMemory(HANDLE ProcessHandle, PVOID  BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded)
{
	__asm
	{
		mov eax, 3Fh
		call dword ptr fs:[0C0h]
		retn 20
	}
}

__declspec(naked) NTSTATUS __stdcall NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
	__asm
	{
		mov eax, 3Ah
		call dword ptr fs:[0C0h]
		retn 20
	}
}

__declspec(naked) NTSTATUS __stdcall NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
{
	__asm
	{
		mov eax, 50h
		call dword ptr fs:[0C0h]
		retn 20
	}
}

__declspec(naked) NTSTATUS __stdcall NtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer)
{
	__asm
	{
		mov eax, 0B3h
		call dword ptr fs : [0C0h]
		retn 44
	}
}

#endif