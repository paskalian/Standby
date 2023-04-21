#pragma once

#include "Includes.h"

using tNtAllocateVirtualMemory = NTSTATUS(__fastcall*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern tNtAllocateVirtualMemory fNtAllocateVirtualMemory;

extern "C" NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

using tNtFreeVirtualMemory = NTSTATUS(__fastcall*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
extern tNtFreeVirtualMemory fNtFreeVirtualMemory;

extern "C" NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

using tNtReadVirtualMemory = NTSTATUS(__fastcall*)(HANDLE ProcessHandle, PVOID  BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
extern tNtReadVirtualMemory fNtReadVirtualMemory;

extern "C" NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID  BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);

using tNtWriteVirtualMemory = NTSTATUS(__fastcall*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
extern tNtWriteVirtualMemory fNtWriteVirtualMemory;

extern "C" NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

using tNtProtectVirtualMemory = NTSTATUS(__fastcall*)(HANDLE ProcessHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
extern tNtProtectVirtualMemory fNtProtectVirtualMemory;

extern "C" NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

using tNtCreateThreadEx = NTSTATUS(__fastcall*)(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
extern tNtCreateThreadEx fNtCreateThreadEx;

extern "C" NTSTATUS NtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

using FLOADLIBRARYA = HMODULE(__fastcall*)(LPCSTR lpLibFileName);

#define LOADLIBRARYSHELLCODESIZE 0x50
struct LoadLibraryScParams
{
	FLOADLIBRARYA fLoadLibraryA;
	PCHAR DllPath;
	HMODULE ReturnModule;
};

using FLDRPLOADDLL = NTSTATUS(__fastcall*)(PWCHAR PathToFile, PULONG pFlags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);

#define LDRLOADDLLSHELLCODESIZE 0x50
struct LdrLoadDllScParams
{
	FLDRPLOADDLL fLdrpLoadDll;

	PWCHAR PathToFile;
	PULONG Flags;
	PUNICODE_STRING ModuleFileName;
	PHANDLE ModuleHandle;
	
	HMODULE ReturnModule;
};

using FGETPROCADDRESS = UINT_PTR(__fastcall*)(HMODULE hModule, LPCSTR lpProcName);

#define MANUALMAPPINGSHELLCODESIZE 0x500
struct ManualMappingScParams
{
	FLOADLIBRARYA fLoadLibraryA;
	FGETPROCADDRESS fGetProcAddress;
	PIMAGE_DOS_HEADER pDosHeader;
};

#define UNLINKFROMPEBSHELLCODESIZE 0x500

namespace Standby
{
	LPVOID InjectDll();

	// MAPPING
	extern int MappingMode;

	LPVOID MapDll();

	LPVOID MapDll_LoadLibrary();
#ifdef _WIN64
	VOID MapDll_LoadLibrary_Shellcode(LoadLibraryScParams* pScParams);
#endif
	LPVOID MapDll_LdrLoadDll();
	NTSTATUS MapDll_LdrLoadDll_Shellcode(LdrLoadDllScParams* pScParams);

	LPVOID MapDll_ManualMapping();
	HANDLE MapDll_ManualMapping_GetDllFileHandle();
	std::vector<BYTE> MapDll_ManualMapping_ReadDllFileIntoBuffer(HANDLE hDllFile);
	BOOLEAN MapDll_ManualMapping_ConfirmChecks(PIMAGE_DOS_HEADER pDosHeader);
	VOID MapDll_ManualMapping_Shellcode(ManualMappingScParams* pScParams);

	// ALLOCATION MODE
	extern int AllocMode;

	LPVOID Alloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flProtect);

	LPVOID Alloc_VirtualAllocEx(LPVOID lpAddress, SIZE_T dwSize, DWORD flProtect);
	LPVOID Alloc_NtAllocateVirtualMemory(LPVOID lpAddress, SIZE_T dwSize, DWORD flProtect);
	LPVOID Alloc_NtAllocateVirtualMemoryImp(LPVOID lpAddress, SIZE_T dwSize, DWORD flProtect);

	// FREE MODE
	extern int FreeMode;

	BOOL Free(LPVOID lpAddress);

	BOOL Free_VirtualFreeEx(LPVOID lpAddress);
	BOOL Free_NtFreeVirtualMemory(LPVOID lpAddress);
	BOOL Free_NtFreeVirtualMemoryImp(LPVOID lpAddress);

	// READ MEMORY
	extern int ReadMode;

	BOOL Read(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize);

	BOOL Read_ReadProcessMemory(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize);
	BOOL Read_NtReadVirtualMemory(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize);
	BOOL Read_NtReadVirtualMemoryImp(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize);

	// WRITE MEMORY
	extern int WriteMode;
		
	BOOL Write(LPVOID lpAddress, LPCVOID lpBuffer, SIZE_T nSize);

	BOOL Write_WriteProcessMemory(LPVOID lpAddress, LPCVOID lpBuffer, SIZE_T nSize);
	BOOL Write_NtWriteVirtualMemory(LPVOID lpAddress, LPCVOID lpBuffer, SIZE_T nSize);
	BOOL Write_NtWriteVirtualMemoryImp(LPVOID lpAddress, LPCVOID lpBuffer, SIZE_T nSize);

	// PROTECT MEMORY
	extern int ProtectMode;

	BOOL Protect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

	BOOL Protect_VirtualProtectEx(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	BOOL Protect_NtProtectVirtualMemory(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	BOOL Protect_NtProtectVirtualMemoryImp(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

	// REMOTE THREAD
	extern int RemoteThreadMode;

	HANDLE RemoteThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);

	HANDLE RemoteThread_CreateRemoteThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
	HANDLE RemoteThread_NtCreateThreadEx(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
	HANDLE RemoteThread_NtCreateThreadExImp(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);

	extern bool UnlinkFromPeb;
	extern bool DeletePEHeader;

	BOOLEAN Dll_UnlinkFromPeb(LPVOID DllBase);
	BOOLEAN Dll_UnlinkFromPeb_Shellcode(LPVOID DllBase);

	BOOLEAN Dll_DeletePEHeader(LPVOID DllBase);
}