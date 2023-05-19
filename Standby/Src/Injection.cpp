#include "Injection.h"

#define MAPPING_LOADLIBRARY 0
#define MAPPING_LDRLOADDLL 1
#define MAPPING_MANUALMAPPING 2

#define ALLOC_VIRTUALALLOCEX 0
#define ALLOC_NTALLOCATEVIRTUALMEMORY 1
#define ALLOC_NTALLOCATEVIRTUALMEMORYIMP 2

#define FREE_VIRTUALFREEEX 0
#define FREE_NTFREEVIRTUALMEMORY 1
#define FREE_NTFREEVIRTUALMEMORYIMP 2

#define READ_READPROCESSMEMORY 0
#define READ_NTREADVIRTUALMEMORY 1
#define READ_NTREADVIRTUALMEMORYIMP 2

#define WRITE_WRITEPROCESSMEMORY 0
#define WRITE_NTWRITEVIRTUALMEMORY 1
#define WRITE_NTWRITEVIRTUALMEMORYIMP 2

#define PROTECT_VIRTUALPROTECTEX 0
#define PROTECT_NTPROTECTVIRTUALMEMORY 1
#define PROTECT_NTPROTECTVIRTUALMEMORYIMP 2

#define REMOTETHREAD_CREATEREMOTETHREAD 0
#define REMOTETHREAD_NTCREATETHREADEX 1
#define REMOTETHREAD_NTCREATETHREADEXIMP 2
#define REMOTETHREAD_THREADHIJACKING 3

tNtAllocateVirtualMemory fNtAllocateVirtualMemory = nullptr;
tNtFreeVirtualMemory fNtFreeVirtualMemory = nullptr;
tNtReadVirtualMemory fNtReadVirtualMemory = nullptr;
tNtWriteVirtualMemory fNtWriteVirtualMemory = nullptr;
tNtProtectVirtualMemory fNtProtectVirtualMemory = nullptr;
tNtCreateThreadEx fNtCreateThreadEx = nullptr;

namespace Standby
{
	LPVOID InjectDll()
	{
		Debug("[*] Injection process started.");

		if (!ProcessHandle)
		{
			Debug("[-] There is no process handle.");
			return nullptr;
		}

		if (!pSelectedDll)
		{
			Debug("[-] There is no dll selected.");
			return nullptr;
		}

		return MapDll();
	}

	// MAPPING
	int MappingMode = MAPPING_LOADLIBRARY;

	LPVOID MapDll()
	{
		Debug("[*] Mapping DLL.");

		switch (MappingMode)
		{
		case MAPPING_LOADLIBRARY:
			return MapDll_LoadLibrary();
		case MAPPING_LDRLOADDLL:
			return MapDll_LdrLoadDll();
		case MAPPING_MANUALMAPPING:
			return MapDll_ManualMapping();
		}

		return nullptr;
	}

	LPVOID MapDll_LoadLibrary()
	{
		Debug("[*] Mapping through LoadLibrary.");

		HMODULE ReturnModule = 0;

		// Allocating memory from target process for our DLL path.
		LPVOID DllPath = Alloc(NULL, pSelectedDll->FullPath.length(), PAGE_READWRITE);
		if (!DllPath)
		{
			Debug("[-] Alloc failed.");
			return nullptr;
		}

		// Writing the DLL path to the allocated memory.
		if (!Write(DllPath, pSelectedDll->FullPath.c_str(), pSelectedDll->FullPath.length()))
		{
			Debug("[-] Write failed.");

			if (!Free(DllPath))
				Debug("[-] Free failed.");

			return nullptr;
		}

		static const HMODULE Kernel32Module = GetModuleHandleA("KERNEL32.DLL");
		static const LPVOID LoadLibraryAddress = GetProcAddress(Kernel32Module, "LoadLibraryA");

#ifdef _WIN64
		LoadLibraryScParams ScParams;
		ScParams.fLoadLibraryA = (FLOADLIBRARYA)LoadLibraryAddress;
		ScParams.DllPath = (PCHAR)DllPath;
		ScParams.ReturnModule = 0;

		BYTE LoadLibraryShellcodeBytes[] = "\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\x8B\x49\x08\xFF\x13\x48\x89\x43\x10\x48\x83\xC4\x20\x5B\xC3";

		// Allocating memory from target process for our shellcode + params.
		LPVOID ShellcodeAddress = Alloc(NULL, sizeof(LoadLibraryShellcodeBytes) + sizeof(LoadLibraryScParams), PAGE_EXECUTE_READWRITE);
		if (!ShellcodeAddress)
		{
			Debug("[-] Alloc failed.");

			if (!Free(DllPath))
				Debug("[-] Free failed.");

			return nullptr;
		}

		// Making a variable to hold a pointer to the params INSIDE the target process, so we don't have to keep writing [ ((BYTE*)ShellcodeAddress + LOADLIBRARYSHELLCODESIZE ].
		LoadLibraryScParams* pScParams = (LoadLibraryScParams*)((BYTE*)ShellcodeAddress + sizeof(LoadLibraryShellcodeBytes));

		// Writing the shellcode + params to our allocated memory.
		if (!Write(ShellcodeAddress, LoadLibraryShellcodeBytes, sizeof(LoadLibraryShellcodeBytes)) ||
			!Write(pScParams, &ScParams, sizeof(LoadLibraryScParams)))
		{
			Debug("[-] Write failed.");

			if (!Free(ShellcodeAddress))
				Debug("[-] Free failed.");

			if (!Free(DllPath))
				Debug("[-] Free failed.");

			return nullptr;
		}

		// Executing the shellcode with these params.
		RTRET hLoadLibraryShellcode = RemoteThread((LPTHREAD_START_ROUTINE)ShellcodeAddress, pScParams, CALLINGCONVENTION::CC_CDECL);
		if (!hLoadLibraryShellcode.ThreadHandle)
		{
			Debug("[-] RemoteThread failed.");

			if (!Free(ShellcodeAddress))
				Debug("[-] Free failed.");

			if (!Free(DllPath))
				Debug("[-] Free failed.");

			return nullptr;
		}

		if (hLoadLibraryShellcode.ThreadHandle != INVALID_HANDLE_VALUE)
		{
			// Waiting for shellcode thread to finish.
			WaitForSingleObject(hLoadLibraryShellcode.ThreadHandle, INFINITE);
		}

		// Since the shellcode thread doesn't have a return value we don't even bother checking for it. (Making it send back a return value is useless anyways)

		// Reading the module returned from LoadLibraryA inside the target process to our actual ReturnModule variable.
		if (!Read((BYTE*)pScParams + offsetof(LoadLibraryScParams, ReturnModule), &ReturnModule, sizeof(HMODULE)))
			Debug("[-] Read failed.");

		// Freeing the shellcode memory.
		if (!Free(ShellcodeAddress))
			Debug("[-] Free failed.");
#else
		RTRET hLoadLibrary = RemoteThread((LPTHREAD_START_ROUTINE)LoadLibraryAddress, DllPath);
		if (!hLoadLibrary.ThreadHandle)
		{
			Debug("[-] RemoteThread failed.");
			if (!Free(DllPath))
				Debug("[-] Free failed.");

			return nullptr;
		}

		if (hLoadLibrary.ThreadHandle != INVALID_HANDLE_VALUE)
		{
			WaitForSingleObject(hLoadLibrary.ThreadHandle, INFINITE);

			if (!GetExitCodeThread(hLoadLibrary.ThreadHandle, (PDWORD)&ReturnModule))
				Debug("[-] GetExitCodeThread failed.");
		}
		else
			ReturnModule = (HMODULE)hLoadLibrary.ReturnVal;

		if (!ReturnModule)
			Debug("[-] LoadLibraryA failed.");
#endif
		// Freeing the dll path memory.
		if (!Free(DllPath))
			Debug("[-] Free failed.");

#ifndef _WIN64
		CloseHandle(hLoadLibrary.ThreadHandle);
#endif

		return (LPVOID)ReturnModule;
	}

/*
#ifdef _WIN64
	VOID MapDll_LoadLibrary_Shellcode(LoadLibraryScParams* pScParams)
	{
		pScParams->ReturnModule = pScParams->fLoadLibraryA(pScParams->DllPath);
	}
#endif
*/

	LPVOID MapDll_LdrLoadDll()
	{
		Debug("[*] Mapping through LdrLoadDll.");

		HMODULE ReturnModule = 0;

		// Converting the SelectedDll->FullPath which is a char* to wchar*
		WCHAR DllPathWc[MAX_PATH] = {};
		size_t NumberOfCharConverted = 0;
		mbstowcs_s(&NumberOfCharConverted, DllPathWc, pSelectedDll->FullPath.c_str(), MAX_PATH);

		// Initializing that wchar* into a unicode string since LdrLoadDll only accepts UNICODE_STRING.
		UNICODE_STRING DllPathUnicode = {};
		DllPathUnicode.Length = wcslen(DllPathWc) * 2;
		DllPathUnicode.MaximumLength = DllPathUnicode.Length + sizeof(WCHAR);
	
		// Allocating memory from target process for our DLL path unicode + actual wchar dll path.
		LPVOID DllPath = Alloc(NULL, sizeof(UNICODE_STRING) + sizeof(DllPathWc), PAGE_READWRITE);
		if (!DllPath)
		{
			Debug("[-] Alloc failed.");
			return nullptr;
		}

		// Setting buffer into pointing directly after the unicode string in the target process.
		DllPathUnicode.Buffer = (PWSTR)((BYTE*)DllPath + sizeof(UNICODE_STRING));

		// Writing the DLL path unicode + actual wchar dll path to the allocated memory.
		if (!Write(DllPath, &DllPathUnicode, sizeof(UNICODE_STRING)) ||
			!Write((BYTE*)DllPath + sizeof(UNICODE_STRING), DllPathWc, sizeof(DllPathWc)))
		{
			Debug("[-] Write failed.");

			if (!Free(DllPath))
				Debug("[-] Free failed.");

			return nullptr;
		}

		// Since we have set the unicode string to point directly after itself, the Buffer member now actually points to the wchar dll path in
		// the target process.

		static const HMODULE NtdllModule = GetModuleHandleA("NTDLL.DLL");
		static const LPVOID LdrLoadDllAddress = GetProcAddress(NtdllModule, "LdrLoadDll");

		LdrLoadDllScParams ScParams;
		ScParams.fLdrLoadDll = (FLDRLOADDLL)LdrLoadDllAddress;

		ScParams.PathToFile = (PWCHAR)1;
		ScParams.Flags = 0;
		ScParams.ModuleFileName = (PUNICODE_STRING)DllPath;
		ScParams.ModuleHandle = nullptr;
		ScParams.ReturnModule = 0;

#ifdef _WIN64
		static const BYTE LdrLoadDllShellcodeBytes[] = "\x4C\x8B\x49\x20\x48\x8B\xC1\x4C\x8B\x41\x18\x48\x8B\x51\x10\x48\x8B\x49\x08\x48\xFF\x20";
#else
		static const BYTE LdrLoadDllShellcodeBytes[] = "\x55\x8B\xEC\x8B\x45\x08\xFF\x70\x10\x8B\x08\xFF\x70\x0C\xFF\x70\x08\xFF\x70\x04\xFF\xD1\x5D\xC3";
#endif

		// Allocating memory from target process for our shellcode + params.
		LPVOID ShellcodeAddress = Alloc(NULL, sizeof(LdrLoadDllShellcodeBytes) + sizeof(LdrLoadDllScParams), PAGE_EXECUTE_READWRITE);
		if (!ShellcodeAddress)
		{
			Debug("[-] Alloc failed.");
			return nullptr;
		}

		// Making a variable to hold a pointer to the params INSIDE the target process, so we don't have to keep writing [ ((BYTE*)ShellcodeAddress + LDRLOADDLLSHELLCODESIZE ].
		LdrLoadDllScParams* pScParams = (LdrLoadDllScParams*)((BYTE*)ShellcodeAddress + sizeof(LdrLoadDllShellcodeBytes));

		// Setting ModuleHandle to point into directly after itself, which is ReturnModule (AS IN STRUCT MEMBER, NOT THE ONE DEFINED INSIDE THIS FUNCTION)
		ScParams.ModuleHandle = (PHANDLE)((BYTE*)pScParams + offsetof(LdrLoadDllScParams, ReturnModule));

		// Writing the shellcode + params to our allocated memory.
		if (!Write(ShellcodeAddress, LdrLoadDllShellcodeBytes, sizeof(LdrLoadDllShellcodeBytes)) ||
			!Write(pScParams, &ScParams, sizeof(LdrLoadDllScParams)))
		{
			Debug("[-] Write failed.");

			if (!Free(ShellcodeAddress))
				Debug("[-] Free failed.");

			if (!Free(DllPath))
				Debug("[-] Free failed.");

			return nullptr;
		}

		// Executing the shellcode with these params.
		RTRET hLdrLoadDllShellcode = RemoteThread((LPTHREAD_START_ROUTINE)ShellcodeAddress, pScParams, CALLINGCONVENTION::CC_CDECL);
		if (!hLdrLoadDllShellcode.ThreadHandle)
		{
			Debug("[-] RemoteThread failed.");

			if (!Free(ShellcodeAddress))
				Debug("[-] Free failed.");

			if (!Free(DllPath))
				Debug("[-] Free failed.");

			return nullptr;
		}

		if (hLdrLoadDllShellcode.ThreadHandle != INVALID_HANDLE_VALUE)
		{
			// Waiting for shellcode thread to finish.
			WaitForSingleObject(hLdrLoadDllShellcode.ThreadHandle, INFINITE);

			NTSTATUS ReturnStatus = 0;
			if (!GetExitCodeThread(hLdrLoadDllShellcode.ThreadHandle, (PDWORD)&ReturnStatus))
				Debug("[-] GetExitCodeThread failed.");

			if (!NT_SUCCESS(ReturnStatus))
				Debug("[-] LdrLoadDll failed.");
		}

		// Reading the module that was set by LdrLoadDll to the handle inside ModuleHandle, that pointer was directly pointing to the next member (ReturnModule - AS IN STRUCT MEMBER -) so we can just read
		// from that member (ReturnModule - AS IN STRUCT MEMBER -) inside the target process to our actual ReturnModule (- AS IN THIS FUNCTION -) variable.
		if (!Read((BYTE*)pScParams + offsetof(LdrLoadDllScParams, ReturnModule), &ReturnModule, sizeof(HMODULE)))
			Debug("[-] Read failed.");

		// Freeing the shellcode memory.
		if (!Free(ShellcodeAddress))
			Debug("[-] Free failed.");

		// Freeing the DLL path unicode + actual wchar dll path memory.
		if (!Free(DllPath))
			Debug("[-] Free failed.");

		return (LPVOID)ReturnModule;
	}
	
	/*
	NTSTATUS MapDll_LdrLoadDll_Shellcode(LdrLoadDllScParams* pScParams)
	{
		return pScParams->fLdrLoadDll(pScParams->PathToFile, pScParams->Flags, pScParams->ModuleFileName, pScParams->ModuleHandle);
	}
	*/

	LPVOID MapDll_ManualMapping()
	{
		Debug("[*] Mapping through ManualMapping.");

		HANDLE hDllFile = MapDll_ManualMapping_GetDllFileHandle();
		if (hDllFile == INVALID_HANDLE_VALUE)
			return nullptr;

		std::vector<BYTE> DllBuffer;
		if (DllBuffer = MapDll_ManualMapping_ReadDllFileIntoBuffer(hDllFile), DllBuffer[0] == 0)
			return nullptr;

		// Close the handle to our DLL file since we don't need that anymore.
		if (CloseHandle(hDllFile) == FALSE)
		{
			Debug("[-] CloseHandle failed. Err code: 0x%X\n", GetLastError());
			return nullptr;
		}

		PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(&DllBuffer[0]);
		if (MapDll_ManualMapping_ConfirmChecks(pDosHeader) == FALSE)
			return nullptr;

		PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)pDosHeader + pDosHeader->e_lfanew);
		PIMAGE_FILE_HEADER pFileHeader = &pNtHeaders->FileHeader;
		PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeaders->OptionalHeader;

		// Allocating memory from the target process so we can map our dll into it.
		PVOID PreferredDllBase = reinterpret_cast<PVOID>(pOptHeader->ImageBase);
		SIZE_T AllocateSize = pOptHeader->SizeOfImage;
		PreferredDllBase = Alloc(PreferredDllBase, AllocateSize, PAGE_EXECUTE_READWRITE);
		if (!PreferredDllBase)
		{
			Debug("[*] Alloc failed to allocate memory on preferred Dll base, attempting to allocate randomly.\n");
			PreferredDllBase = Alloc(NULL, AllocateSize, PAGE_EXECUTE_READWRITE);

			if (!PreferredDllBase)
			{
				Debug("[-] Alloc failed.");
				return nullptr;
			}
		}

#ifdef _WIN64
		static const BYTE ManualMappingShellcodeBytes[] =
			"\x48\x89\x4C\x24\x08\x53\x56\x57\x41\x56\x48\x83\xEC\x38\x48\x8B\x59\x10\x48\x8B"
			"\xD1\x44\x8B\xDB\x48\x89\x6C\x24\x70\x48\x63\x73\x3C\x48\x03\xF3\x48\x89\x74\x24"
			"\x68\x44\x2B\x5E\x30\x0F\x84\xA0\x00\x00\x00\x8B\x86\xB4\x00\x00\x00\x85\xC0\x0F"
			"\x84\x92\x00\x00\x00\xC1\xE8\x03\x4C\x8B\xCB\x85\xC0\x0F\x84\x84\x00\x00\x00\x8B"
			"\xF8\xBD\xFF\x0F\x00\x00\x66\x66\x0F\x1F\x84\x00\x00\x00\x00\x00\x41\x8B\x41\x04"
			"\x4D\x8D\x41\x08\x48\x83\xE8\x08\x48\xD1\xE8\x85\xC0\x74\x4E\x44\x8B\xD0\x66\x66"
			"\x0F\x1F\x84\x00\x00\x00\x00\x00\x41\x0F\xB7\x00\x0F\xB7\xC8\x66\x23\xC5\x66\xC1"
			"\xE9\x0C\x80\xF9\x03\x75\x0F\x41\x8B\x11\x0F\xB7\xC0\x48\x03\xC3\x44\x01\x1C\x02"
			"\xEB\x15\x80\xF9\x0A\x75\x10\x41\x8B\x11\x0F\xB7\xC8\x48\x03\xCB\x41\x8B\xC3\x48"
			"\x01\x04\x11\x49\x83\xC0\x02\x49\x83\xEA\x01\x75\xBF\x41\x8B\x41\x04\x4C\x03\xC8"
			"\x48\x83\xEF\x01\x75\x92\x48\x8B\x54\x24\x60\x45\x33\xF6\x44\x39\xB6\x94\x00\x00"
			"\x00\x0F\x84\xC1\x00\x00\x00\x8B\xBE\x90\x00\x00\x00\x48\x03\xFB\x44\x39\x37\x0F"
			"\x84\xAF\x00\x00\x00\x4C\x89\x64\x24\x30\x4C\x89\x6C\x24\x28\x45\x8B\xEE\x4C\x89"
			"\x7C\x24\x20\x8B\x4F\x0C\x48\x03\xCB\xFF\x12\x8B\x0F\x41\x8B\xEE\x44\x8B\x67\x10"
			"\x4C\x8B\xF8\x4C\x03\xE3\x48\x8B\x14\x19\x48\x85\xD2\x74\x50\x49\x8B\xF6\x4C\x8B"
			"\x74\x24\x60\x90\x49\x8B\x46\x08\x49\x8B\xCF\x48\x85\xD2\x79\x05\x0F\xB7\xD2\xEB"
			"\x07\x48\x83\xC2\x02\x48\x03\xD3\xFF\xD0\x49\x89\x04\x24\xFF\xC5\x8B\x4F\x10\x48"
			"\x83\xC6\x08\x8B\x07\x48\x03\xCB\x48\x63\xD5\x48\x03\xC6\x4C\x8D\x24\xD1\x48\x8B"
			"\x14\x18\x48\x85\xD2\x75\xC1\x48\x8B\x74\x24\x68\x45\x33\xF6\x8B\xBE\x90\x00\x00"
			"\x00\x49\x83\xC5\x14\x48\x8B\x54\x24\x60\x49\x03\xFD\x48\x03\xFB\x83\x3F\x00\x0F"
			"\x85\x72\xFF\xFF\xFF\x4C\x8B\x7C\x24\x20\x4C\x8B\x6C\x24\x28\x4C\x8B\x64\x24\x30"
			"\x83\xBE\xD4\x00\x00\x00\x00\x48\x8B\x6C\x24\x70\x74\x3D\x8B\xBE\xD0\x00\x00\x00"
			"\x48\x8B\x44\x1F\x18\x4C\x8B\x08\x4D\x85\xC9\x74\x2A\x66\x66\x66\x0F\x1F\x84\x00"
			"\x00\x00\x00\x00\x45\x33\xC0\x48\x8B\xCB\x41\x8D\x50\x01\x41\xFF\xD1\x48\x8B\x44"
			"\x1F\x18\x4D\x8D\x76\x08\x4D\x8B\x0C\x06\x4D\x85\xC9\x75\xE1\x8B\x46\x28\x45\x33"
			"\xC0\x48\x03\xC3\x48\x8B\xCB\x41\x8D\x50\x01\x48\x83\xC4\x38\x41\x5E\x5F\x5E\x5B"
			"\x48\xFF\xE0";
#else
		static const BYTE ManualMappingShellcodeBytes[] =
			"\x55\x8B\xEC\x83\xEC\x14\x8B\x55\x08\x53\x56\x57\x8B\x72\x08\x8B\xC6\x89\x75\xF4"
			"\x8B\x7E\x3C\x03\xFE\x89\x7D\xFC\x2B\x47\x34\x89\x45\xF8\x0F\x84\x8F\x00\x00\x00"
			"\x8B\x8F\xA4\x00\x00\x00\x85\xC9\x0F\x84\x81\x00\x00\x00\xC1\xE9\x03\x8B\xFE\x89"
			"\x4D\xF0\x85\xC9\x74\x72\x8B\x5F\x04\x8D\x47\x04\x83\xEB\x08\x89\x45\xEC\xD1\xEB"
			"\xB8\x00\x00\x00\x00\x74\x4D\x66\x0F\x1F\x84\x00\x00\x00\x00\x00\x0F\xB7\x4C\x47"
			"\x08\x66\x8B\xD1\x81\xE1\xFF\x0F\x00\x00\x66\xC1\xEA\x0C\x80\xFA\x03\x75\x0D\x8D"
			"\x14\x0E\x8B\x0F\x8B\x75\xF8\x01\x34\x0A\xEB\x15\x80\xFA\x0A\x75\x13\x8D\x14\x0E"
			"\x8B\x0F\x8B\x75\xF8\x01\x34\x0A\x83\x54\x0A\x04\x00\x8B\x75\xF4\x40\x3B\xC3\x72"
			"\xBF\x8B\x4D\xF0\x8B\x45\xEC\x03\x38\x83\xE9\x01\x89\x4D\xF0\x75\x91\x8B\x55\x08"
			"\x8B\x7D\xFC\x83\xBF\x84\x00\x00\x00\x00\x0F\x84\x8F\x00\x00\x00\x8B\x9F\x80\x00"
			"\x00\x00\x03\xDE\x83\x3B\x00\x0F\x84\x7E\x00\x00\x00\x89\x75\xF8\x8B\x4B\x0C\x8B"
			"\x02\x03\xCE\x51\xFF\xD0\x8B\x0B\x8B\x7B\x10\x03\xFE\x89\x45\xF0\x8B\x0C\x0E\x85"
			"\xC9\x74\x44\xC7\x45\xF4\x00\x00\x00\x00\x66\x0F\x1F\x44\x00\x00\x8B\x45\x08\x8B"
			"\x50\x04\x85\xC9\x79\x05\x0F\xB7\xC1\xEB\x05\x8D\x41\x02\x03\xC6\x50\xFF\x75\xF0"
			"\xFF\xD2\x8B\x4D\xF4\x89\x07\x83\xC1\x04\x8B\x03\x8B\x7B\x10\x03\xC1\x03\xF9\x89"
			"\x4D\xF4\x03\xFE\x8B\x0C\x30\x85\xC9\x75\xC9\x8B\x7D\xFC\x8B\x45\xF8\x8B\x55\x08"
			"\x83\xC0\x14\x89\x45\xF8\x8B\x9F\x80\x00\x00\x00\x03\xD8\x83\x3B\x00\x75\x85\x83"
			"\xBF\xC4\x00\x00\x00\x00\x74\x2C\x8B\x9F\xC0\x00\x00\x00\x8B\x44\x33\x0C\x8B\x00"
			"\x85\xC0\x74\x1C\x33\xFF\x66\x90\x6A\x00\x6A\x01\x56\xFF\xD0\x8B\x44\x33\x0C\x8D"
			"\x7F\x04\x8B\x04\x07\x85\xC0\x75\xEB\x8B\x7D\xFC\x8B\x47\x28\x6A\x00\x6A\x01\x56"
			"\x03\xC6\xFF\xD0\x5F\x5E\x5B\x8B\xE5\x5D\xC3";
#endif

		// Allocating memory for our shellcode + params.
		AllocateSize = sizeof(ManualMappingShellcodeBytes) + sizeof(ManualMappingScParams);
		PVOID AllocatedShellcode = Alloc(NULL, AllocateSize, PAGE_EXECUTE_READWRITE);
		if (!AllocatedShellcode)
		{
			Debug("[-] Alloc failed.");

			if (!Free(PreferredDllBase))
				Debug("[-] Free failed.");

			return nullptr;
		}

		// Writing the shellcode into the allocated memory.
		SIZE_T BytesWritten = 0;
		if (!Write(AllocatedShellcode, ManualMappingShellcodeBytes, sizeof(ManualMappingShellcodeBytes)))
		{
			Debug("[-] Write failed.");

			if (!Free(PreferredDllBase))
				Debug("[-] Free failed.");

			if (!Free(AllocatedShellcode))
				Debug("[-] Free failed.");

			return nullptr;
		}

		// Writing the needed shellcode parameters just after the function.
		ManualMappingScParams ScPass = {};
		ScPass.fLoadLibraryA = reinterpret_cast<FLOADLIBRARYA>(GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "LoadLibraryA"));
		ScPass.fGetProcAddress = reinterpret_cast<FGETPROCADDRESS>(GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "GetProcAddress"));
		ScPass.pDosHeader = static_cast<PIMAGE_DOS_HEADER>(PreferredDllBase);

		if (!Write((BYTE*)AllocatedShellcode + sizeof(ManualMappingShellcodeBytes), &ScPass, sizeof(ManualMappingScParams)))
		{
			Debug("[-] Write failed.");

			if (!Free(PreferredDllBase))
				Debug("[-] Free failed.");

			if (!Free(AllocatedShellcode))
				Debug("[-] Free failed.");

			return nullptr;
		}

		// Writing the entire dll into the target process.
		if (!Write(PreferredDllBase, pDosHeader, pOptHeader->SizeOfHeaders))
		{
			Debug("[-] Write failed.");

			if (!Free(PreferredDllBase))
				Debug("[-] Free failed.");

			if (!Free(AllocatedShellcode))
				Debug("[-] Free failed.");

			return nullptr;
		}

		for (int i = 0; i < pFileHeader->NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER pIdxSection = &IMAGE_FIRST_SECTION(pNtHeaders)[i];

			if (!Write((BYTE*)PreferredDllBase + pIdxSection->VirtualAddress, (BYTE*)pDosHeader + pIdxSection->PointerToRawData, pIdxSection->SizeOfRawData))
			{
				Debug("[-] Write failed.");

				if (!Free(PreferredDllBase))
					Debug("[-] Free failed.");

				if (!Free(AllocatedShellcode))
					Debug("[-] Free failed.");

				return nullptr;
			}
		}

		RTRET hShellcodeThread = RemoteThread((LPTHREAD_START_ROUTINE)AllocatedShellcode, (BYTE*)AllocatedShellcode + sizeof(ManualMappingShellcodeBytes), CALLINGCONVENTION::CC_CDECL);
		if (!hShellcodeThread.ThreadHandle)
		{
			Debug("[-] RemoteThread failed.");

			if (!Free(PreferredDllBase))
				Debug("[-] Free failed.");

			if (!Free(AllocatedShellcode))
				Debug("[-] Free failed.");

			return nullptr;
		}

		if (hShellcodeThread.ThreadHandle != INVALID_HANDLE_VALUE)
		{
			WaitForSingleObject(hShellcodeThread.ThreadHandle, INFINITE);
		}

		if (!Free(AllocatedShellcode))
			Debug("[-] Free failed.");

		return PreferredDllBase;
	}

	HANDLE MapDll_ManualMapping_GetDllFileHandle()
	{
		Debug("[*] Trying to obtain a handle to the dll file.");

		// Gheck if the DLL path corresponds to a valid file.
		const char* DllPath = pSelectedDll->FullPath.c_str();
		if (GetFileAttributesA(DllPath) == INVALID_FILE_ATTRIBUTES)
		{
			Debug("[-] Invalid path.\n");
			return INVALID_HANDLE_VALUE;
		}

		// Get an Handle to the DLL file so we can read from it.
		HANDLE hDllFile = CreateFileA(DllPath, GENERIC_READ, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDllFile == INVALID_HANDLE_VALUE)
		{
			Debug("[-] Invalid file.");
			return INVALID_HANDLE_VALUE;
		}
		Debug("[*] Dll file handle obtained successfully.");

		return hDllFile;
	}

	std::vector<BYTE> MapDll_ManualMapping_ReadDllFileIntoBuffer(HANDLE hDllFile)
	{
		LARGE_INTEGER DllFileSize = {};
		if (GetFileSizeEx(hDllFile, &DllFileSize) == FALSE)
		{
			Debug("[-] GetFileSizeEx failed.");
			return { 0 };
		}

		// Read the entire DLL file into our buffer so we can start manipulating it.
		std::vector<BYTE> ReturnBuffer(DllFileSize.QuadPart);

		if (ReadFile(hDllFile, &ReturnBuffer[0], DllFileSize.QuadPart, NULL, NULL) == FALSE)
		{
			Debug("[-] ReadFile failed.");
			return { 0 };
		}

		return ReturnBuffer;
	}

	BOOLEAN MapDll_ManualMapping_ConfirmChecks(PIMAGE_DOS_HEADER pDosHeader)
	{
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			Debug("[-] Invalid MZ signature.\n");
			return false;
		}

		// Checking for NT signature.
		PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)pDosHeader + pDosHeader->e_lfanew);
		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			Debug("[-] Invalid NT signature.\n");
			return false;
		}

		PIMAGE_FILE_HEADER pFileHeader = &pNtHeaders->FileHeader;
		PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeaders->OptionalHeader;

		// Checking for Machine type.
		if (pFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64
			&& pFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
		{
			Debug("[-] Invalid machine.\n");
			return false;
		}

		// Checking for File type.
		if (!(pFileHeader->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) || !(pFileHeader->Characteristics & IMAGE_FILE_DLL))
		{
			Debug("[-] Invalid file type.\n");
			return false;
		}

		// Checking for Image type.
		if (pOptHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		{
			Debug("[-] Invalid image type.\n");
			return false;
		}

		return true;
	}

	/*
	using TDLLENTRY = BOOL(__stdcall*)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
	VOID MapDll_ManualMapping_Shellcode(ManualMappingScParams* pScParams)
	{
		PIMAGE_DOS_HEADER pVDosHeader = pScParams->pDosHeader;
		PIMAGE_NT_HEADERS pVNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)pVDosHeader + pVDosHeader->e_lfanew);
		PIMAGE_FILE_HEADER pVFileHeader = &pVNtHeaders->FileHeader;
		PIMAGE_OPTIONAL_HEADER pVOptHeader = &pVNtHeaders->OptionalHeader;

		// Fixing up relocations if it must be fixed and there are any to fix.
		DWORD Offset = (DWORD)((BYTE*)pVDosHeader - pVOptHeader->ImageBase);

		if (Offset && pVOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			DWORD AmountOfRelocs = pVOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size / sizeof(IMAGE_BASE_RELOCATION);

			PIMAGE_BASE_RELOCATION pBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(((BYTE*)pVDosHeader + pVOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, pVDosHeader));
			for (int idx = 0; idx < AmountOfRelocs; idx++)
			{
				DWORD AmountOfEntries = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

				PWORD FirstEntry = reinterpret_cast<PWORD>((BYTE*)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));
				for (int idx2 = 0; idx2 < AmountOfEntries; idx2++)
				{
					WORD IdxEntry = FirstEntry[idx2];

					BYTE IdxType = IdxEntry >> 12;
					WORD RelOffset = IdxEntry & 0xFFF;

					if (IdxType == IMAGE_REL_BASED_HIGHLOW)
					{
						*(DWORD32*)((BYTE*)pVDosHeader + pBaseReloc->VirtualAddress + RelOffset) += Offset;
					}
					else if (IdxType == IMAGE_REL_BASED_DIR64)
					{
						*(DWORD64*)((BYTE*)pVDosHeader + pBaseReloc->VirtualAddress + RelOffset) += Offset;
					}
					else if (IdxType == IMAGE_REL_BASED_ABSOLUTE)
					{
						// Skipped.
					}
					else
					{
						//Debug("[-] Relocation entry has an unknown type.\n");
						//return false;
					}
				}

				pBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>((BYTE*)pBaseReloc + pBaseReloc->SizeOfBlock);
			}
		}

		// Resolving imports.
		PIMAGE_DATA_DIRECTORY pImportDataDir = &pVOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (pImportDataDir->Size)
		{
			for (int i = 0; ; i++)
			{
				PIMAGE_IMPORT_DESCRIPTOR pImportIdx = &reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>((BYTE*)pVDosHeader + pImportDataDir->VirtualAddress)[i];
				if (!pImportIdx->Characteristics)
					break;

				PCHAR ModName = reinterpret_cast<PCHAR>((BYTE*)pVDosHeader + pImportIdx->Name);
				HMODULE hMod = pScParams->fLoadLibraryA(ModName);

				for (int i2 = 0; ; i2++)
				{
					PIMAGE_THUNK_DATA pFirstThunk = &reinterpret_cast<PIMAGE_THUNK_DATA>((BYTE*)pVDosHeader + pImportIdx->FirstThunk)[i2];
					PIMAGE_THUNK_DATA pThunkIdx = &reinterpret_cast<PIMAGE_THUNK_DATA>((BYTE*)pVDosHeader + pImportIdx->OriginalFirstThunk)[i2];
					if (!pThunkIdx->u1.AddressOfData)
						break;

					if (IMAGE_SNAP_BY_ORDINAL(pThunkIdx->u1.Ordinal))
					{
						pFirstThunk->u1.Function = pScParams->fGetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pThunkIdx->u1.Ordinal));
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME pName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((BYTE*)pVDosHeader + pThunkIdx->u1.AddressOfData);
						pFirstThunk->u1.Function = pScParams->fGetProcAddress(hMod, pName->Name);
					}
				}
			}
		}

		// Calling TLS callbacks.
		PIMAGE_DATA_DIRECTORY pTlsDataDir = &pVOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (pTlsDataDir->Size)
		{
			PIMAGE_TLS_DIRECTORY pTlsDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY>((BYTE*)pVDosHeader + pTlsDataDir->VirtualAddress);
			for (int i = 0; ; i++)
			{
				PIMAGE_TLS_CALLBACK pTlsCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTlsDir->AddressOfCallBacks)[i];
				if (!pTlsCallback)
					break;

				pTlsCallback(pVDosHeader, DLL_PROCESS_ATTACH, NULL);
			}
		}

		// Calling DllMain.
		reinterpret_cast<TDLLENTRY>((BYTE*)pVDosHeader + pVOptHeader->AddressOfEntryPoint)((HINSTANCE)pVDosHeader, DLL_PROCESS_ATTACH, NULL);
	}
	*/

	// ALLOCATION MODE
	int AllocMode = ALLOC_VIRTUALALLOCEX;

	LPVOID Alloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flProtect)
	{
		Debug("[*] Trying to allocate memory from target process.");

		switch (AllocMode)
		{
		case ALLOC_VIRTUALALLOCEX:
			return Alloc_VirtualAllocEx(lpAddress, dwSize, flProtect);
		case ALLOC_NTALLOCATEVIRTUALMEMORY:
			return Alloc_NtAllocateVirtualMemory(lpAddress, dwSize, flProtect);
		case ALLOC_NTALLOCATEVIRTUALMEMORYIMP:
			return Alloc_NtAllocateVirtualMemoryImp(lpAddress, dwSize, flProtect);
		}

		return nullptr;
	}

	LPVOID Alloc_VirtualAllocEx(LPVOID lpAddress, SIZE_T dwSize, DWORD flProtect)
	{
		Debug("[*] Allocating memory through VirtualAllocEx.");

		return VirtualAllocEx(ProcessHandle, lpAddress, dwSize, MEM_COMMIT | MEM_RESERVE, flProtect);
	}

	LPVOID Alloc_NtAllocateVirtualMemory(LPVOID lpAddress, SIZE_T dwSize, DWORD flProtect)
	{
		Debug("[*] Allocating memory through NtAllocateVirtualMemory.");

		SIZE_T Size = dwSize;
		PVOID ReturnAddress = lpAddress;

		NTSTATUS Status = fNtAllocateVirtualMemory(ProcessHandle, &ReturnAddress, 0, &Size, MEM_COMMIT | MEM_RESERVE, flProtect);
		if (!NT_SUCCESS(Status))
		{
			Debug("[-] NtAllocateVirtualMemory failed.");

			return nullptr;
		}

		return ReturnAddress;
	}

	LPVOID Alloc_NtAllocateVirtualMemoryImp(LPVOID lpAddress, SIZE_T dwSize, DWORD flProtect)
	{
		Debug("[*] Allocating memory through NtAllocateVirtualMemoryImp.");

		SIZE_T Size = dwSize;
		PVOID ReturnAddress = lpAddress;

		NTSTATUS Status = NtAllocateVirtualMemory(ProcessHandle, &ReturnAddress, 0, &Size, MEM_COMMIT | MEM_RESERVE, flProtect);
		if (!NT_SUCCESS(Status))
		{
			Debug("[-] NtAllocateVirtualMemory failed.");

			return nullptr;
		}

		return ReturnAddress;

		return nullptr;
	}

	// FREE MODE
	int FreeMode = FREE_VIRTUALFREEEX;

	BOOL Free(LPVOID lpAddress)
	{
		Debug("[*] Trying to free memory from target process.");

		switch (FreeMode)
		{
		case FREE_VIRTUALFREEEX:
			return Free_VirtualFreeEx(lpAddress);
		case FREE_NTFREEVIRTUALMEMORY:
			return Free_NtFreeVirtualMemory(lpAddress);
		case FREE_NTFREEVIRTUALMEMORYIMP:
			return Free_NtFreeVirtualMemoryImp(lpAddress);
		}

		return false;
	}

	BOOL Free_VirtualFreeEx(LPVOID lpAddress)
	{
		Debug("[*] Freeing memory through VirtualFreeEx.");

		return VirtualFreeEx(ProcessHandle, lpAddress, NULL, MEM_RELEASE);
	}

	BOOL Free_NtFreeVirtualMemory(LPVOID lpAddress)
	{
		Debug("[*] Freeing memory through NtFreeVirtualMemory.");

		SIZE_T RegionSize = 0;
		NTSTATUS Status = fNtFreeVirtualMemory(ProcessHandle, &lpAddress, &RegionSize, MEM_RELEASE);
		return NT_SUCCESS(Status);
	}

	BOOL Free_NtFreeVirtualMemoryImp(LPVOID lpAddress)
	{
		Debug("[*] Freeing memory through NtFreeVirtualMemoryImp.");

		SIZE_T RegionSize = 0;
		NTSTATUS Status = NtFreeVirtualMemory(ProcessHandle, &lpAddress, &RegionSize, MEM_RELEASE);
		return NT_SUCCESS(Status);
	}

	// READ MEMORY
	int ReadMode = READ_READPROCESSMEMORY;

	BOOL Read(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize, BOOLEAN Dbg)
	{
		if (Dbg)
			Debug("[*] Trying to read from the memory of target process.");

		switch (ReadMode)
		{
		case READ_READPROCESSMEMORY:
			return Read_ReadProcessMemory(lpAddress, lpBuffer, nSize, Dbg);
		case READ_NTREADVIRTUALMEMORY:
			return Read_NtReadVirtualMemory(lpAddress, lpBuffer, nSize, Dbg);
		case READ_NTREADVIRTUALMEMORYIMP:
			return Read_NtReadVirtualMemoryImp(lpAddress, lpBuffer, nSize, Dbg);
		}

		return true;
	}

	BOOL Read_ReadProcessMemory(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize, BOOLEAN Dbg)
	{
		if (Dbg)
			Debug("[*] Reading memory through ReadProcessMemory.");

		SIZE_T NumberOfBytesRead = 0;
		return ReadProcessMemory(ProcessHandle, lpAddress, lpBuffer, nSize, &NumberOfBytesRead);
	}

	BOOL Read_NtReadVirtualMemory(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize, BOOLEAN Dbg)
	{
		if (Dbg)
			Debug("[*] Reading memory through NtReadVirtualMemory.");

		ULONG NumberOfBytesRead = 0;
		return NT_SUCCESS(fNtReadVirtualMemory(ProcessHandle, (PVOID)lpAddress, lpBuffer, nSize, &NumberOfBytesRead));
	}

	BOOL Read_NtReadVirtualMemoryImp(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize, BOOLEAN Dbg)
	{
		if (Dbg)
			Debug("[*] Reading memory through NtReadVirtualMemoryImp.");

		ULONG NumberOfBytesRead = 0;
		return NT_SUCCESS(NtReadVirtualMemory(ProcessHandle, (PVOID)lpAddress, lpBuffer, nSize, &NumberOfBytesRead));
	}

	// WRITE MEMORY
	int WriteMode = WRITE_WRITEPROCESSMEMORY;

	BOOL Write(LPVOID lpAddress, LPCVOID lpBuffer, SIZE_T nSize)
	{
		Debug("[*] Trying to write to the memory of target process.");

		switch (AllocMode)
		{
		case WRITE_WRITEPROCESSMEMORY:
			return Write_WriteProcessMemory(lpAddress, lpBuffer, nSize);
		case WRITE_NTWRITEVIRTUALMEMORY:
			return Write_NtWriteVirtualMemory(lpAddress, lpBuffer, nSize);
		case WRITE_NTWRITEVIRTUALMEMORYIMP:
			return Write_NtWriteVirtualMemoryImp(lpAddress, lpBuffer, nSize);
		}

		return true;
	}

	BOOL Write_WriteProcessMemory(LPVOID lpAddress, LPCVOID lpBuffer, SIZE_T nSize)
	{
		Debug("[*] Writing to memory through WriteProcessMemory.");

		SIZE_T NumberOfBytesWritten = 0;
		return WriteProcessMemory(ProcessHandle, lpAddress, lpBuffer, nSize, &NumberOfBytesWritten);
	}

	BOOL Write_NtWriteVirtualMemory(LPVOID lpAddress, LPCVOID lpBuffer, SIZE_T nSize)
	{
		Debug("[*] Writing to memory through NtWriteVirtualMemory.");

		ULONG NumberOfBytesWritten = 0;
		return NT_SUCCESS(fNtWriteVirtualMemory(ProcessHandle, lpAddress, (PVOID)lpBuffer, nSize, &NumberOfBytesWritten));
	}

	BOOL Write_NtWriteVirtualMemoryImp(LPVOID lpAddress, LPCVOID lpBuffer, SIZE_T nSize)
	{
		Debug("[*] Writing to memory through NtWriteVirtualMemoryImp.");

		ULONG NumberOfBytesWritten = 0;
		return NT_SUCCESS(NtWriteVirtualMemory(ProcessHandle, lpAddress, (PVOID)lpBuffer, nSize, &NumberOfBytesWritten));
	}

	// PROTECT MEMORY
	int ProtectMode = PROTECT_VIRTUALPROTECTEX;

	BOOL Protect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
	{
		Debug("[*] Trying to change access protections of memory in target process.");

		switch (AllocMode)
		{
		case PROTECT_VIRTUALPROTECTEX:
			return Protect_VirtualProtectEx(lpAddress, dwSize, flNewProtect, lpflOldProtect);
		case PROTECT_NTPROTECTVIRTUALMEMORY:
			return Protect_NtProtectVirtualMemory(lpAddress, dwSize, flNewProtect, lpflOldProtect);
		case PROTECT_NTPROTECTVIRTUALMEMORYIMP:
			return Protect_NtProtectVirtualMemoryImp(lpAddress, dwSize, flNewProtect, lpflOldProtect);
		}

		return true;
	}

	BOOL Protect_VirtualProtectEx(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
	{
		return VirtualProtectEx(ProcessHandle, lpAddress, dwSize, flNewProtect, lpflOldProtect);
	}

	BOOL Protect_NtProtectVirtualMemory(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
	{
		NTSTATUS Status = fNtProtectVirtualMemory(ProcessHandle, &lpAddress, (PULONG)&dwSize, flNewProtect, lpflOldProtect);
		return NT_SUCCESS(Status);
	}

	BOOL Protect_NtProtectVirtualMemoryImp(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
	{
		NTSTATUS Status = NtProtectVirtualMemory(ProcessHandle, &lpAddress, (PULONG)&dwSize, flNewProtect, lpflOldProtect);
		return NT_SUCCESS(Status);
	}

	// REMOTE THREAD
	int RemoteThreadMode = REMOTETHREAD_CREATEREMOTETHREAD;

	RTRET RemoteThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, CALLINGCONVENTION CallConvention)
	{
		Debug("[*] Trying to create a remote thread in the target process.");

		switch (RemoteThreadMode)
		{
		case REMOTETHREAD_CREATEREMOTETHREAD:
			return RemoteThread_CreateRemoteThread(lpStartAddress, lpParameter);
		case REMOTETHREAD_NTCREATETHREADEX:
			return RemoteThread_NtCreateThreadEx(lpStartAddress, lpParameter);
		case REMOTETHREAD_NTCREATETHREADEXIMP:
			return RemoteThread_NtCreateThreadExImp(lpStartAddress, lpParameter);
		case REMOTETHREAD_THREADHIJACKING:
			return RemoteThread_ThreadHijacking(lpStartAddress, lpParameter, CallConvention);
		}

		Debug("[-] Unhandled remote thread mode.");
		return {};
	}

	RTRET RemoteThread_CreateRemoteThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
	{
		Debug("[*] Creating a remote thread through CreateRemoteThread.");

		RTRET ReturnVal = {};
		ReturnVal.ThreadHandle = CreateRemoteThread(ProcessHandle, NULL, NULL, lpStartAddress, lpParameter, NULL, NULL);

		return ReturnVal;
	}

	RTRET RemoteThread_NtCreateThreadEx(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
	{
		Debug("[*] Creating a remote thread through NtCreateThreadEx.");

		RTRET ReturnVal = {};

		NTSTATUS Status = fNtCreateThreadEx(&ReturnVal.ThreadHandle, THREAD_ALL_ACCESS, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, FALSE, NULL, NULL, NULL, NULL);

		return ReturnVal;
	}

	RTRET RemoteThread_NtCreateThreadExImp(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
	{
		Debug("[*] Creating a remote thread through NtCreateThreadExImp.");

		RTRET ReturnVal = {};

		NTSTATUS Status = NtCreateThreadEx(&ReturnVal.ThreadHandle, THREAD_ALL_ACCESS, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, FALSE, NULL, NULL, NULL, NULL);

		return ReturnVal;
	}

	RTRET RemoteThread_ThreadHijacking(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, CALLINGCONVENTION CallConvention)
	{
		Debug("[*] Creating a remote thread through ThreadHijacking.");

		RTRET ReturnVal = {};

		ReturnVal.ThreadHandle = INVALID_HANDLE_VALUE;
		ReturnVal.ReturnVal = RemoteThread_ThreadHijacking_Handle(ProcessHandle, THREADHIJACKTYPE::DIRECT, (UINT_PTR)lpStartAddress, { lpParameter }, CallConvention);

		return ReturnVal;
	}

	UINT_PTR RemoteThread_ThreadHijacking_Handle(HANDLE TargetProcess, THREADHIJACKTYPE HijackType, UINT_PTR FunctionAddress, std::vector<std::any> Arguments, CALLINGCONVENTION CallConvention)
	{
#ifdef _WIN64
		// If the number of arguments is less than 4, we complete it to 4.
		while (Arguments.size() < 4)
			Arguments.push_back(0);
#else
		if (CallConvention == CALLINGCONVENTION::CC_FASTCALL)
		{
			// If the number of arguments is less than 2, we complete it to 2.
			while (Arguments.size() < 2)
				Arguments.push_back(0);
		}
#endif

		THREADHIJACKDATA Data = {};

		PVOID VariablesMemory = nullptr;

		const SIZE_T ArgumentsSize = RemoteThread_ThreadHijacking_GetArgumentsSize(Arguments, THREADSIZETYPE::INCLUDEEXTRA) + sizeof(DWORD64) + sizeof(UINT_PTR);
		const SIZE_T OffsetToExtra = RemoteThread_ThreadHijacking_GetArgumentsSize(Arguments, THREADSIZETYPE::DEFAULT) + sizeof(DWORD64) + sizeof(UINT_PTR);

		// Allocating space for the argument count + arguments 
		VariablesMemory = Alloc(NULL, ArgumentsSize, PAGE_READWRITE);
		if (!VariablesMemory)
		{
			Debug("[-] Alloc failed.");
			return -1;
		}

		// Writing the argument count to the first UINT_PTR
		const SIZE_T ArgumentCount = Arguments.size();
		if (!Write((BYTE*)VariablesMemory, &ArgumentCount, sizeof(SIZE_T)))
		{
			Debug("[-] Write failed.");
			Free(VariablesMemory);
			return -1;
		}
	#ifndef _WIN64
		// Writing the calling convetion to the second UINT_PTR
		if (!Write((BYTE*)VariablesMemory + 4, &CallConvention, sizeof(DWORD)))
		{
			Debug("[-] Write failed.");
			VirtualFreeEx(TargetProcess, VariablesMemory, 0, MEM_RELEASE);
			return -1;
		}
	#endif

		// Writing the other arguments, if it's a string we write them to the extra zone.
		SIZE_T Offset = sizeof(DWORD64) + sizeof(UINT_PTR);
		SIZE_T OffsetFromExtra = 0;
		for (auto& ArgIdx : Arguments)
		{
			const SIZE_T ArgSize = RemoteThread_ThreadHijacking_GetTypeSize(ArgIdx, THREADSIZETYPE::INCLUDEEXTRA);

			const BOOLEAN IsString = ArgSize > sizeof(PVOID);
			const SIZE_T StringSize = IsString ? ArgSize - sizeof(PVOID) : 0;
			if (IsString)
			{
				BYTE* StringAddress = (BYTE*)VariablesMemory + OffsetToExtra + OffsetFromExtra;
				if (!Write((BYTE*)VariablesMemory + Offset, &StringAddress, sizeof(PVOID)) ||
				   (!Write(StringAddress, *(const char**)&ArgIdx, StringSize)))
				{
					Debug("[-] Write failed.");
					Free(VariablesMemory);
					return -1;
				}
			}
			else
			{
				const SIZE_T ActualSize = RemoteThread_ThreadHijacking_GetTypeSize(ArgIdx, THREADSIZETYPE::ACTUALSIZE);
				if (!Write((BYTE*)VariablesMemory + Offset, &ArgIdx, ActualSize))
				{
					Debug("[-] Write failed.");
					Free(VariablesMemory);
					return -1;
				}
			}

			Offset += sizeof(PVOID);
			OffsetFromExtra += StringSize;
		}

		Data.VariablesAddress = (UINT_PTR)VariablesMemory;

		PVOID AllocatedMemory = nullptr;

		UINT_PTR ReturnValue = 0;
		switch (HijackType)
		{
			case THREADHIJACKTYPE::DIRECT:
			{
				// If it's direct we don't need to allocate then write the function since it's already in the target process.
				Data.FunctionAddress = FunctionAddress;

				ReturnValue = RemoteThread_ThreadHijacking_HijackThread(TargetProcess, Data);

				break;
			}
			case THREADHIJACKTYPE::BYTE:
			{
				// Allocating memory for the function in the target process and writing the function bytes there.
				std::vector<BYTE>* FunctionBytes = (std::vector<BYTE>*)FunctionAddress;
				AllocatedMemory = Alloc(NULL, FunctionBytes->size(), PAGE_READWRITE);
				if (!AllocatedMemory)
				{
					Debug("[-] Alloc failed.");
					return -1;
				}

				if (!Write(AllocatedMemory, FunctionBytes, FunctionBytes->size()))
				{
					Debug("[-] Write failed.");
					Free(AllocatedMemory);
					return -1;
				}
			}
			case THREADHIJACKTYPE::SELF:
			{
				// Since THREADHIJACKTYPE::BYTE doesn't have a break it will end up here after it's own functionality, this check is to seperate the two because they end up doing the exact
				// same thing ultimately.
				if (!AllocatedMemory)
				{
					// Allocating memory for the function in the target process and writing the function bytes there.
					UINT_PTR* FunctionAndSize = (UINT_PTR*)FunctionAddress;

					AllocatedMemory = Alloc(NULL, FunctionAndSize[1], PAGE_READWRITE);
					if (!AllocatedMemory)
					{
						Debug("[-] Alloc failed.");
						return -1;
					}

					if (!Write(AllocatedMemory, (PVOID)FunctionAndSize[0], FunctionAndSize[1]))
					{
						Debug("[-] Write failed.");
						Free(AllocatedMemory);
						return -1;
					}
				}

				Data.FunctionAddress = (UINT_PTR)AllocatedMemory;
				ReturnValue = RemoteThread_ThreadHijacking_HijackThread(TargetProcess, Data);

				break;
			}
		}

		if (HijackType != THREADHIJACKTYPE::DIRECT)
		{
			if (Data.FunctionAddress)
				Free((LPVOID)Data.FunctionAddress);
		}

		if (Data.VariablesAddress)
			Free((LPVOID)Data.VariablesAddress);

		return ReturnValue;
	}

	SIZE_T RemoteThread_ThreadHijacking_GetTypeSize(const std::any& Type, THREADSIZETYPE SizeType)
	{
		const type_info& TypeInfo = Type.type();
		const std::string TypeName = TypeInfo.name();

		// I can't switch.
		if (TypeInfo == typeid(const char*) || TypeInfo == typeid(char*))
			return SizeType == THREADSIZETYPE::INCLUDEEXTRA ? (sizeof(char*) + strlen(*(const char**)&Type) + 1) : sizeof(char*);
		else if (TypeInfo == typeid(const wchar_t*))
			return SizeType == THREADSIZETYPE::INCLUDEEXTRA ? (sizeof(wchar_t*) + wcslen(*(const wchar_t**)&Type) * sizeof(WCHAR) + 2) : sizeof(wchar_t*);
		else
		{
			if (SizeType == THREADSIZETYPE::ACTUALSIZE)
			{
				if (TypeName.find('*') != TypeName.npos)
					return sizeof(PVOID);
				else if (TypeInfo == typeid(int))
					return sizeof(int);
				else if (TypeInfo == typeid(long))
					return sizeof(long);
				else if (TypeInfo == typeid(short))
					return sizeof(short);
				else if (TypeInfo == typeid(bool))
					return sizeof(bool);
				// Floating point values must be handled by the xmm registers and I don't know how.
				//else if (TypeInfo == typeid(float))
				//  return sizeof(float);
				else
				{
					assert(false);
				}
			}

			return sizeof(PVOID);
		}
	}

	SIZE_T RemoteThread_ThreadHijacking_GetArgumentsSize(const std::vector<std::any>& Arguments, THREADSIZETYPE SizeType)
	{
		SIZE_T ArgumentsSize = 0;
		for (auto& ArgIdx : Arguments)
			ArgumentsSize += RemoteThread_ThreadHijacking_GetTypeSize(ArgIdx, SizeType);

		return ArgumentsSize;
	}

	UINT_PTR RemoteThread_ThreadHijacking_HijackThread(HANDLE TargetProcess, THREADHIJACKDATA& Data)
	{
#ifdef _WIN64
		static const BYTE ShellcodeBytes[] =
			"\x48\x83\xEC\x08\xC7\x04\x24\xCC\xCC\xCC\xCC\xC7\x44\x24\x04\xCC\xCC\xCC\xCC\x9C\x50\x51\x52\x53\x55\x56\x57\x41\x50\x41\x51\x41\x52"
			"\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\xB8\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x8B\x30\x48\x8B\x48\x10\x48\x8B\x50\x18\x4C\x8B"
			"\x40\x20\x4C\x8B\x48\x28\x48\xC7\x00\x00\x00\x00\x00\x48\x83\xFE\x04\x76\x20\x48\x83\xEE\x04\x48\x89\x30\x48\xF7\xC6\x01\x00\x00\x00"
			"\x74\x04\x48\x83\xEC\x08\xFF\x74\xF0\x28\x48\xFF\xCE\x48\x85\xF6\x75\xF4\x48\xB8\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x20\xFF"
			"\xD0\x48\x8B\xD0\x48\x83\xC4\x20\x48\xB8\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x8B\x30\x48\x8B\xDE\x48\x6B\xF6\x08\x48\x03\xE6\x48\xF7"
			"\xC3\x01\x00\x00\x00\x74\x04\x48\x83\xC4\x08\x48\xC7\x00\xFF\xFF\xFF\xFF\x48\x89\x50\x08\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41"
			"\x5A\x41\x59\x41\x58\x5F\x5E\x5D\x5B\x5A\x59\x58\x9D\xC3";
#else
		static const BYTE ShellcodeBytes[] =
			"\x83\xEC\x04\xC7\x04\x24\xCC\xCC\xCC\xCC\x9C\x60\xB8\xCC\xCC\xCC\xCC\x8B\x30\x8B\x58\x04\x83\xFB\x02\x74\x0B\xFF\x74\xB0\x08\x4E\x85"
			"\xF6\x75\xF7\xEB\x1F\x8B\x48\x0C\x8B\x50\x10\xC7\x00\x00\x00\x00\x00\x83\xFE\x02\x76\x0E\x83\xEE\x02\x89\x30\xFF\x74\xB0\x10\x4E\x85"
			"\xF6\x75\xF7\xB8\xCC\xCC\xCC\xCC\xFF\xD0\x8B\xD0\xB8\xCC\xCC\xCC\xCC\x8B\x30\x8B\x58\x04\x85\xDB\x75\x05\x6B\xF6\x04\x03\xE6\xC7\x00"
			"\xFF\xFF\xFF\xFF\x89\x50\x08\x61\x9D\xC3";
#endif

		const PVOID ShellcodeMemory = Alloc(NULL, sizeof(ShellcodeBytes), PAGE_EXECUTE_READWRITE);
		if (!ShellcodeMemory)
		{
			Debug("[-] Alloc failed.");
			return -1;
		}

		if (!Write(ShellcodeMemory, ShellcodeBytes, sizeof(ShellcodeBytes)))
		{
			Debug("[-] Write failed.");

			Free(ShellcodeMemory);
			return -1;
		}

		// Getting a handle to the base thread.
		HANDLE hThread = GetBaseThreadHandle(GetProcessId(TargetProcess));
		if (!hThread)
		{
			Free(ShellcodeMemory);
			return -1;
		}
		Debug("[*] Retrieved handle for target thread.");

		// Setting up a CONTEXT structure to be used while getting the thread context, CONTEXT_CONTROL meaning
		// we will only work on RIP, etc.
		CONTEXT ThreadContext;
		ThreadContext.ContextFlags = CONTEXT_CONTROL;

		// Suspending the thread because if we change the thread context while it's running it can result in undefined behaviour.
		if (SuspendThread(hThread) == HandleToULong(INVALID_HANDLE_VALUE))
		{
			Debug("[-] SuspendThread failed.");

			Free(ShellcodeMemory);
			CloseHandle(hThread);
			return -1;
		}
		Debug("[*] Thread suspended.");

		// Getting the thread context.
		if (GetThreadContext(hThread, &ThreadContext))
		{
			// Saving the RIP since we are gonna return the thread after the shellcode is executed.
#ifdef _WIN64
			UINT_PTR JmpBackAddr = ThreadContext.Rip;
#else
			UINT_PTR JmpBackAddr = ThreadContext.Eip;
#endif

#ifdef _WIN64
			DWORD LoJmpBk = LODWORD(JmpBackAddr);
			DWORD HiJmpBk = HIDWORD(JmpBackAddr);

			// Writing the JmpBackAddr into the
			// mov dword ptr [rsp], 0CCCCCCCCh
			// mov dword ptr[rsp + 4], 0CCCCCCCCh
			// corresponding bytes ( CC ) and then when the shellcode is executed, it will get itself some stack space and write the
			// return address in there, when ret is called after all it pops the stack and returns to what was on top of
			// the stack which is that address.
			Write((LPVOID)((BYTE*)ShellcodeMemory + 7), &LoJmpBk, sizeof(DWORD));
			Write((LPVOID)((BYTE*)ShellcodeMemory + 15), &HiJmpBk, sizeof(DWORD));

			// Writing the ShellcodeParams into the
			// mov rax, 0CCCCCCCCCCCCCCCCh
			// corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the base for the parameters.
			DWORD64 Buffer64 = Data.VariablesAddress;
			Write((LPVOID)((BYTE*)ShellcodeMemory + 45), &Buffer64, sizeof(DWORD64));

			// Writing the ShellcodeParams into the
			// mov rax, 0CCCCCCCCCCCCCCCCh
			// corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the function address.
			Buffer64 = Data.FunctionAddress;
			Write((LPVOID)((BYTE*)ShellcodeMemory + 119), &Buffer64, sizeof(DWORD64));

			// Writing the ShellcodeParams into the
			// mov rax, 0CCCCCCCCCCCCCCCCh
			// corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the base for the parameters.
			Buffer64 = Data.VariablesAddress;
			Write((LPVOID)((BYTE*)ShellcodeMemory + 142), &Buffer64, sizeof(DWORD64));
#else
			// We can directly write JmpBackAddr since it will be a DWORD.

			// Writing the JmpBackAddr into the
			// mov dword ptr [esp], 0CCCCCCCCh
			// corresponding bytes ( CC ) and then when the shellcode is executed, it will get itself some stack space and write the
			// return address in there, when ret is called after all it pops the stack and returns to what was on top of
			// the stack which is that address.
			Write((LPVOID)((BYTE*)ShellcodeMemory + 6), &JmpBackAddr, sizeof(DWORD));

			// Writing the ShellcodeParams into the
			// mov eax, 0CCCCCCCCh
			// corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the base for the parameters.
			DWORD Buffer = Data.VariablesAddress;
			Write((LPVOID)((BYTE*)ShellcodeMemory + 13), &Buffer, sizeof(DWORD));

			// Writing the ShellcodeParams into the
			// mov eax, 0CCCCCCCCh
			// corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the base for the parameters.
			Buffer = Data.FunctionAddress;
			Write((LPVOID)((BYTE*)ShellcodeMemory + 70), &Buffer, sizeof(DWORD));

			// Writing the ShellcodeParams into the
			// mov eax, 0CCCCCCCCh
			// corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the base for the parameters.
			Buffer = Data.VariablesAddress;
			Write((LPVOID)((BYTE*)ShellcodeMemory + 79), &Buffer, sizeof(DWORD));
#endif

			// Updating the RIP to ShellcodeMemory
#ifdef _WIN64
			ThreadContext.Rip = (DWORD64)ShellcodeMemory;
#else
			ThreadContext.Eip = (DWORD32)ShellcodeMemory;
#endif

			// Setting the updated thread context.
			if (!SetThreadContext(hThread, &ThreadContext))
				Debug("[-] SetThreadContext failed.");
		}
		else
			Debug("[-] GetThreadContext failed.");

		// Resuming the thread with the updated RIP making the shellcode get executed IF the thread was already in a execute state when it was suspended,
		// if not, the thread will stay in it's suspend state.
		if (ResumeThread(hThread) == HandleToULong(INVALID_HANDLE_VALUE))
		{
			Debug("[-] ResumeThread failed.");

			Free(ShellcodeMemory);
			CloseHandle(hThread);
			return -1;
		}
		Debug("[*] Thread resumed.\n");

		CloseHandle(hThread);
		Debug("[*] Target thread handle closed.\n");

		// Checking if our thread has finished.
		UINT_PTR ThreadFinish = 0;
		while (Read((PVOID)Data.VariablesAddress, &ThreadFinish, sizeof(UINT_PTR), false), ThreadFinish != -1)
			;

		// Giving the shellcode a little more time to finish.
		Sleep(50);

		UINT_PTR ReturnValue = 0;
		ReadProcessMemory(TargetProcess, (PVOID)((UINT_PTR)Data.VariablesAddress + sizeof(DWORD64)), &ReturnValue, sizeof(UINT_PTR), NULL);

		Debug("[*] Hijacked thread finished.\n");

		Free(ShellcodeMemory);
		Debug("[*] Shellcode memory released.\n");

		return ReturnValue;
	}

	bool UnlinkFromPeb = false;
	bool DeletePEHeader = false;

	BOOLEAN Dll_UnlinkFromPeb(LPVOID DllBase)
	{
#ifdef _WIN64
		static const BYTE UnlinkFromPebShellcodeBytes[] =
			"\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x48\x8B\xD1\x4C\x8B\x40\x18\x49\x8B\x40\x10"
			"\x49\x8D\x48\x10\x48\x3B\xC1\x74\x21\x0F\x1F\x00\x48\x3B\x50\x30\x74\x0A\x48\x8B"
			"\x00\x48\x3B\xC1\x75\xF2\xEB\x0E\x48\x8B\x48\x08\x48\x8B\x00\x48\x89\x01\x48\x89"
			"\x48\x08\x49\x8B\x40\x20\x49\x8D\x48\x20\x48\x3B\xC1\x74\x23\x0F\x1F\x44\x00\x00"
			"\x48\x3B\x50\x20\x74\x0A\x48\x8B\x00\x48\x3B\xC1\x75\xF2\xEB\x0E\x48\x8B\x48\x08"
			"\x48\x8B\x00\x48\x89\x01\x48\x89\x48\x08\x49\x8B\x40\x30\x49\x8D\x48\x30\x48\x3B"
			"\xC1\x74\x24\x0F\x1F\x44\x00\x00\x48\x3B\x50\x10\x74\x0B\x48\x8B\x00\x48\x3B\xC1"
			"\x75\xF2\xB0\x01\xC3\x48\x8B\x48\x08\x48\x8B\x00\x48\x89\x01\x48\x89\x48\x08\xB0"
			"\x01\xC3";
#else
		static const BYTE UnlinkFromPebShellcodeBytes[] =
			"\x55\x8B\xEC\x64\xA1\x30\x00\x00\x00\x8B\x55\x08\x56\x8B\x70\x0C\x8B\x46\x0C\x8D"
			"\x4E\x0C\x3B\xC1\x74\x1D\x66\x0F\x1F\x44\x00\x00\x3B\x50\x18\x74\x08\x8B\x00\x3B"
			"\xC1\x75\xF5\xEB\x0A\x8B\x48\x04\x8B\x00\x89\x01\x89\x48\x04\x8B\x46\x14\x8D\x4E"
			"\x14\x3B\xC1\x74\x17\x3B\x50\x10\x74\x08\x8B\x00\x3B\xC1\x75\xF5\xEB\x0A\x8B\x48"
			"\x04\x8B\x00\x89\x01\x89\x48\x04\x8B\x46\x1C\x8D\x4E\x1C\x5E\x3B\xC1\x74\x19\x3B"
			"\x50\x08\x74\x0A\x8B\x00\x3B\xC1\x75\xF5\xB0\x01\x5D\xC3\x8B\x48\x04\x8B\x00\x89"
			"\x01\x89\x48\x04\xB0\x01\x5D\xC3\x56\x8B\xF1\x8B\x06\x85\xC0\x74\x3D\x8B\x4E\x08"
			"\x2B\xC8\x81\xF9\x00\x10\x00\x00\x72\x12\x8B\x50\xFC\x83\xC1\x23\x2B\xC2\x83\xC0"
			"\xFC\x83\xF8\x1F\x77\x22\x8B\xC2\x51\x50\xE8\x84\x5C\x00\x00\xC7\x06\x00\x00\x00"
			"\x00\x83\xC4\x08\xC7\x46\x04\x00\x00\x00\x00\xC7\x46\x08\x00\x00\x00\x00\x5E\xC3"
			"\xFF\x15\x9C\x92\x49\x00";
#endif

		// Allocating memory from target process for our shellcode.
		LPVOID ShellcodeAddress = Alloc(NULL, sizeof(UnlinkFromPebShellcodeBytes), PAGE_EXECUTE_READWRITE);
		if (!ShellcodeAddress)
		{
			Debug("[-] Alloc failed.");

			return false;
		}

		// Writing the shellcode + params to our allocated memory.
		if (!Write(ShellcodeAddress, UnlinkFromPebShellcodeBytes, sizeof(UnlinkFromPebShellcodeBytes)))
		{
			Debug("[-] Write failed.");

			if (!Free(ShellcodeAddress))
				Debug("[-] Free failed.");

			return false;
		}

		// Executing the shellcode with these params.
		RTRET hUnlinkFromPebShellcode = RemoteThread((LPTHREAD_START_ROUTINE)ShellcodeAddress, DllBase, CALLINGCONVENTION::CC_CDECL);
		if (!hUnlinkFromPebShellcode.ThreadHandle)
		{
			Debug("[-] RemoteThread failed.");

			if (!Free(ShellcodeAddress))
				Debug("[-] Free failed.");

			return false;
		}

		if (hUnlinkFromPebShellcode.ThreadHandle != INVALID_HANDLE_VALUE)
		{
			// Waiting for shellcode thread to finish.
			WaitForSingleObject(hUnlinkFromPebShellcode.ThreadHandle, INFINITE);
		}

		if (!Free(ShellcodeAddress))
			Debug("[-] Free failed.");

		return true;
	}

	/*
	BOOLEAN Dll_UnlinkFromPeb_Shellcode(LPVOID DllBase)
	{
#ifdef _WIN64
		auto pPEB = (PPEB)__readgsqword(0x60);
#else
		auto pPEB = (PPEB)__readfsdword(0x30);
#endif

		PPEB_LDR_DATA pLdrData = pPEB->Ldr;

		PLIST_ENTRY pLoadOrderHead = &pLdrData->InLoadOrderModuleList;
		PLIST_ENTRY pLoadOrderEntry = pLoadOrderHead->Flink;
		while (pLoadOrderEntry != pLoadOrderHead)
		{
			PLDR_DATA_TABLE_ENTRY pModule = CONTAINING_RECORD(pLoadOrderEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (DllBase == pModule->DllBase)
			{
				PLIST_ENTRY PrevEntry = pLoadOrderEntry->Blink;
				PLIST_ENTRY NextEntry = pLoadOrderEntry->Flink;

				PrevEntry->Flink = NextEntry;
				NextEntry->Blink = PrevEntry;

				break;
			}

			pLoadOrderEntry = pLoadOrderEntry->Flink;
		}

		PLIST_ENTRY pMemoryOrderHead = &pLdrData->InMemoryOrderModuleList;
		PLIST_ENTRY pMemoryOrderEntry = pMemoryOrderHead->Flink;
		while (pMemoryOrderEntry != pMemoryOrderHead)
		{
			PLDR_DATA_TABLE_ENTRY pModule = CONTAINING_RECORD(pMemoryOrderEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if (DllBase == pModule->DllBase)
			{
				PLIST_ENTRY PrevEntry = pMemoryOrderEntry->Blink;
				PLIST_ENTRY NextEntry = pMemoryOrderEntry->Flink;

				PrevEntry->Flink = NextEntry;
				NextEntry->Blink = PrevEntry;

				break;
			}

			pMemoryOrderEntry = pMemoryOrderEntry->Flink;
		}

		PLIST_ENTRY pInitOrderHead = &pLdrData->InInitializationOrderModuleList;
		PLIST_ENTRY pInitOrderEntry = pInitOrderHead->Flink;
		while (pInitOrderEntry != pInitOrderHead)
		{
			PLDR_DATA_TABLE_ENTRY pModule = CONTAINING_RECORD(pInitOrderEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);

			if (DllBase == pModule->DllBase)
			{
				PLIST_ENTRY PrevEntry = pInitOrderEntry->Blink;
				PLIST_ENTRY NextEntry = pInitOrderEntry->Flink;

				PrevEntry->Flink = NextEntry;
				NextEntry->Blink = PrevEntry;

				break;
			}

			pInitOrderEntry = pInitOrderEntry->Flink;
		}

		return true;
	}
	*/

	BOOLEAN Dll_DeletePEHeader(LPVOID DllBase)
	{
		const PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)DllBase;

		LONG LfanewOffset = 0;
		if (!Read((BYTE*)pDosHeader + offsetof(IMAGE_DOS_HEADER, e_lfanew), &LfanewOffset, sizeof(LfanewOffset)))
		{
			Debug("[-] Read failed.");
			return false;
		}

		const PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + LfanewOffset);

		DWORD SizeOfHeaders = 0;
		if (!Read((BYTE*)pNtHeaders + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + offsetof(IMAGE_OPTIONAL_HEADER, SizeOfHeaders), &SizeOfHeaders, sizeof(SizeOfHeaders)))
		{
			Debug("[-] Read failed.");
			return false;
		}

		BYTE* ZeroArr = new BYTE[SizeOfHeaders];
		memset(ZeroArr, 0, SizeOfHeaders);

		DWORD OldProtect = 0;
		Protect(pDosHeader, SizeOfHeaders, PAGE_READWRITE, &OldProtect);
		if (!Write(pDosHeader, ZeroArr, SizeOfHeaders))
		{
			Debug("[-] Write failed.");
			return false;
		}
		Protect(pDosHeader, SizeOfHeaders, OldProtect, &OldProtect);
		
		delete[] ZeroArr;

		return true;
	}
}