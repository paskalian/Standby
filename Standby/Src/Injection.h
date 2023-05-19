#pragma once

#include "Includes.h"

#define HIDWORD(x) (x >> 32)
#define LODWORD(x) (x & 0xFFFFFFFF)

using tNtAllocateVirtualMemory = NTSTATUS(__stdcall*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern tNtAllocateVirtualMemory fNtAllocateVirtualMemory;

extern "C" NTSTATUS __stdcall NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

using tNtFreeVirtualMemory = NTSTATUS(__stdcall*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
extern tNtFreeVirtualMemory fNtFreeVirtualMemory;

extern "C" NTSTATUS __stdcall NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

using tNtReadVirtualMemory = NTSTATUS(__stdcall*)(HANDLE ProcessHandle, PVOID  BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
extern tNtReadVirtualMemory fNtReadVirtualMemory;

extern "C" NTSTATUS __stdcall NtReadVirtualMemory(HANDLE ProcessHandle, PVOID  BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);

using tNtWriteVirtualMemory = NTSTATUS(__stdcall*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
extern tNtWriteVirtualMemory fNtWriteVirtualMemory;

extern "C" NTSTATUS __stdcall NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

using tNtProtectVirtualMemory = NTSTATUS(__stdcall*)(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
extern tNtProtectVirtualMemory fNtProtectVirtualMemory;

extern "C" NTSTATUS __stdcall NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

using tNtCreateThreadEx = NTSTATUS(__stdcall*)(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
extern tNtCreateThreadEx fNtCreateThreadEx;

extern "C" NTSTATUS __stdcall NtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

using FLOADLIBRARYA = HMODULE(__stdcall*)(LPCSTR lpLibFileName);

struct LoadLibraryScParams
{
	FLOADLIBRARYA fLoadLibraryA;
	PCHAR DllPath;
	HMODULE ReturnModule;
};

using FLDRLOADDLL = NTSTATUS(__stdcall*)(PWCHAR PathToFile, PULONG pFlags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);

struct LdrLoadDllScParams
{
	FLDRLOADDLL fLdrLoadDll;

	PWCHAR PathToFile;
	PULONG Flags;
	PUNICODE_STRING ModuleFileName;
	PHANDLE ModuleHandle;
	
	HMODULE ReturnModule;
};

using FGETPROCADDRESS = UINT_PTR(__stdcall*)(HMODULE hModule, LPCSTR lpProcName);

struct ManualMappingScParams
{
	FLOADLIBRARYA fLoadLibraryA;
	FGETPROCADDRESS fGetProcAddress;
	PIMAGE_DOS_HEADER pDosHeader;
};

struct THREADHIJACKDATA
{
	UINT_PTR FunctionAddress = 0;
	UINT_PTR VariablesAddress = 0;
};

enum class THREADSIZETYPE
{
	DEFAULT,
	INCLUDEEXTRA,
	ACTUALSIZE
};


enum class THREADHIJACKTYPE
{
	DIRECT, // ExecuteAddress is treated as is in the target process address space, there will be no extra allocations other than for the Arguments. After the set-up,
	// it gets executed.

	SELF,   // ExecuteAddress is treated as an array of 2 UINT_PTRs which the first UINT_PTR being the function address (in the current process), and the second being the
	// function size, which then the function size is used to allocate memory for the function itself and copy it to there from the function address + the Arguments
	// inside the target process. Finally after the set-up, it gets executed.

	BYTE    // ExecuteAddress is treated as an std::vector<BYTE>* which is used to allocate an extra memory for the function itself and copy it to there + the Arguments
			// inside the target process. Finally after the set-up, it gets executed.
};

enum class CALLINGCONVENTION : DWORD
{
	CC_CDECL,
	CC_STDCALL,
	CC_FASTCALL
};

struct RTRET
{
	HANDLE ThreadHandle;
	UINT_PTR ReturnVal;
};

namespace Standby
{
	LPVOID InjectDll();

	// MAPPING
	extern int MappingMode;

	LPVOID MapDll();

	LPVOID MapDll_LoadLibrary();
	LPVOID MapDll_LdrLoadDll();

	LPVOID MapDll_ManualMapping();
	HANDLE MapDll_ManualMapping_GetDllFileHandle();
	std::vector<BYTE> MapDll_ManualMapping_ReadDllFileIntoBuffer(HANDLE hDllFile);
	BOOLEAN MapDll_ManualMapping_ConfirmChecks(PIMAGE_DOS_HEADER pDosHeader);

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

	BOOL Read(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize, BOOLEAN Dbg = true);

	BOOL Read_ReadProcessMemory(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize, BOOLEAN Dbg = true);
	BOOL Read_NtReadVirtualMemory(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize, BOOLEAN Dbg = true);
	BOOL Read_NtReadVirtualMemoryImp(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize, BOOLEAN Dbg = true);

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

	RTRET RemoteThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, CALLINGCONVENTION CallConvention = CALLINGCONVENTION::CC_STDCALL);

	RTRET RemoteThread_CreateRemoteThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
	RTRET RemoteThread_NtCreateThreadEx(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
	RTRET RemoteThread_NtCreateThreadExImp(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
	RTRET RemoteThread_ThreadHijacking(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, CALLINGCONVENTION CallConvention);
	UINT_PTR RemoteThread_ThreadHijacking_Handle(HANDLE TargetProcess, THREADHIJACKTYPE HijackType, UINT_PTR FunctionAddress, std::vector<std::any> Arguments = {}, CALLINGCONVENTION CallConvention = CALLINGCONVENTION::CC_CDECL);
	SIZE_T RemoteThread_ThreadHijacking_GetTypeSize(const std::any& Type, THREADSIZETYPE SizeType);
	SIZE_T RemoteThread_ThreadHijacking_GetArgumentsSize(const std::vector<std::any>& Arguments, THREADSIZETYPE SizeType);
	UINT_PTR RemoteThread_ThreadHijacking_HijackThread(HANDLE TargetProcess, THREADHIJACKDATA& Data);

	extern bool UnlinkFromPeb;
	extern bool DeletePEHeader;

	BOOLEAN Dll_UnlinkFromPeb(LPVOID DllBase);

	BOOLEAN Dll_DeletePEHeader(LPVOID DllBase);
}