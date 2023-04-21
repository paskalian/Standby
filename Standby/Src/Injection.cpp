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
		// In 64-bit GetExitCodeThread can't be used fully functionally since it only returns 32-bit values, so our workaround is to use a shellcode function to
		// call LoadLibraryA directly inside the target process and write the return value to our structure inside the target process, then finally we can ReadProcessMemory
		// our structure + module offset and we got the loaded module.

		LoadLibraryScParams ScParams;
		ScParams.fLoadLibraryA = (FLOADLIBRARYA)LoadLibraryAddress;
		ScParams.DllPath = (PCHAR)DllPath;
		ScParams.ReturnModule = 0;

		// Allocating memory from target process for our shellcode + params.
		LPVOID ShellcodeAddress = Alloc(NULL, LOADLIBRARYSHELLCODESIZE + sizeof(LoadLibraryScParams), PAGE_EXECUTE_READWRITE);
		if (!ShellcodeAddress)
		{
			Debug("[-] Alloc failed.");

			if (!Free(DllPath))
				Debug("[-] Free failed.");

			return nullptr;
		}

		// Making a variable to hold a pointer to the params INSIDE the target process, so we don't have to keep writing [ ((BYTE*)ShellcodeAddress + LOADLIBRARYSHELLCODESIZE ].
		LoadLibraryScParams* pScParams = (LoadLibraryScParams*)((BYTE*)ShellcodeAddress + LOADLIBRARYSHELLCODESIZE);

		// Writing the shellcode + params to our allocated memory.
		if (!Write(ShellcodeAddress, MapDll_LoadLibrary_Shellcode, LOADLIBRARYSHELLCODESIZE) ||
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
		HANDLE hLoadLibraryShellcode = RemoteThread((LPTHREAD_START_ROUTINE)ShellcodeAddress, pScParams);
		if (!hLoadLibraryShellcode)
		{
			Debug("[-] RemoteThread failed.");

			if (!Free(ShellcodeAddress))
				Debug("[-] Free failed.");

			if (!Free(DllPath))
				Debug("[-] Free failed.");

			return nullptr;
		}

		// Waiting for shellcode thread to finish.
		WaitForSingleObject(hLoadLibraryShellcode, INFINITE);

		// Since the shellcode thread doesn't have a return value we don't even bother checking for it. (Making it send back a return value is useless anyways)

		// Reading the module returned from LoadLibraryA inside the target process to our actual ReturnModule variable.
		if (!Read((BYTE*)pScParams + offsetof(LoadLibraryScParams, ReturnModule), &ReturnModule, sizeof(HMODULE)))
			Debug("[-] Read failed.");

		// Freeing the shellcode memory.
		if (!Free(ShellcodeAddress))
			Debug("[-] Free failed.");
#else
		HANDLE hLoadLibrary = RemoteThread((LPTHREAD_START_ROUTINE)LoadLibraryAddress, DllPath);
		if (!hLoadLibrary)
		{
			Debug("[-] RemoteThread failed.");
			if (!Free(DllPath))
				Debug("[-] Free failed.");

			return nullptr;
		}

		WaitForSingleObject(hLoadLibrary, INFINITE);

		if (!GetExitCodeThread(hLoadLibrary, (PDWORD)&ReturnModule))
			Debug("[-] GetExitCodeThread failed.");

		if (!ReturnModule)
			Debug("[-] LoadLibraryA failed.");
#endif
		// Freeing the dll path memory.
		if (!Free(DllPath))
			Debug("[-] Free failed.");

#ifndef _WIN64
		CloseHandle(hLoadLibrary);
#endif

		return (LPVOID)ReturnModule;
	}

#ifdef _WIN64
	VOID MapDll_LoadLibrary_Shellcode(LoadLibraryScParams* pScParams)
	{
		pScParams->ReturnModule = pScParams->fLoadLibraryA(pScParams->DllPath);
	}
#endif

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
		ScParams.fLdrpLoadDll = (FLDRPLOADDLL)LdrLoadDllAddress;

		ScParams.PathToFile = (PWCHAR)1;
		ScParams.Flags = 0;
		ScParams.ModuleFileName = (PUNICODE_STRING)DllPath;
		ScParams.ModuleHandle = nullptr;
		ScParams.ReturnModule = 0;

		// Allocating memory from target process for our shellcode + params.
		LPVOID ShellcodeAddress = Alloc(NULL, LDRLOADDLLSHELLCODESIZE + sizeof(LdrLoadDllScParams), PAGE_EXECUTE_READWRITE);
		if (!ShellcodeAddress)
		{
			Debug("[-] Alloc failed.");
			return nullptr;
		}

		// Making a variable to hold a pointer to the params INSIDE the target process, so we don't have to keep writing [ ((BYTE*)ShellcodeAddress + LDRPLOADDLLSHELLCODESIZE ].
		LdrLoadDllScParams* pScParams = (LdrLoadDllScParams*)((BYTE*)ShellcodeAddress + LDRLOADDLLSHELLCODESIZE);

		// Setting ModuleHandle to point into directly after itself, which is ReturnModule (AS IN STRUCT MEMBER, NOT THE ONE DEFINED INSIDE THIS FUNCTION)
		ScParams.ModuleHandle = (PHANDLE)((BYTE*)pScParams + offsetof(LdrLoadDllScParams, ReturnModule));

		// Writing the shellcode + params to our allocated memory.
		if (!Write(ShellcodeAddress, MapDll_LdrLoadDll_Shellcode, LDRLOADDLLSHELLCODESIZE) ||
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
		HANDLE hLdrpLoadDllShellcode = RemoteThread((LPTHREAD_START_ROUTINE)ShellcodeAddress, pScParams);
		if (!hLdrpLoadDllShellcode)
		{
			Debug("[-] RemoteThread failed.");

			if (!Free(ShellcodeAddress))
				Debug("[-] Free failed.");

			if (!Free(DllPath))
				Debug("[-] Free failed.");

			return nullptr;
		}

		// Waiting for shellcode thread to finish.
		WaitForSingleObject(hLdrpLoadDllShellcode, INFINITE);

		NTSTATUS ReturnStatus = 0;
		if (!GetExitCodeThread(hLdrpLoadDllShellcode, (PDWORD)&ReturnStatus))
			Debug("[-] GetExitCodeThread failed.");

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

	NTSTATUS MapDll_LdrLoadDll_Shellcode(LdrLoadDllScParams* pScParams)
	{
		return pScParams->fLdrpLoadDll(pScParams->PathToFile, pScParams->Flags, pScParams->ModuleFileName, pScParams->ModuleHandle);
	}

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

		// Allocating memory for our shellcode.
		AllocateSize = MANUALMAPPINGSHELLCODESIZE + sizeof(ManualMappingScParams);
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
		if (!Write(AllocatedShellcode, MapDll_ManualMapping_Shellcode, MANUALMAPPINGSHELLCODESIZE))
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

		if (!Write((BYTE*)AllocatedShellcode + MANUALMAPPINGSHELLCODESIZE, &ScPass, sizeof(ManualMappingScParams)))
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

		HANDLE hShellcodeThread = RemoteThread((LPTHREAD_START_ROUTINE)AllocatedShellcode, (BYTE*)AllocatedShellcode + MANUALMAPPINGSHELLCODESIZE);
		if (!hShellcodeThread)
		{
			Debug("[-] RemoteThread failed.");

			if (!Free(PreferredDllBase))
				Debug("[-] Free failed.");

			if (!Free(AllocatedShellcode))
				Debug("[-] Free failed.");

			return nullptr;
		}

		WaitForSingleObject(hShellcodeThread, INFINITE);

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

	using TDLLENTRY = BOOL(__fastcall*)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
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

	BOOL Read(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize)
	{
		Debug("[*] Trying to read from the memory of target process.");

		switch (ReadMode)
		{
		case READ_READPROCESSMEMORY:
			return Read_ReadProcessMemory(lpAddress, lpBuffer, nSize);
		case READ_NTREADVIRTUALMEMORY:
			return Read_NtReadVirtualMemory(lpAddress, lpBuffer, nSize);
		case READ_NTREADVIRTUALMEMORYIMP:
			return Read_NtReadVirtualMemoryImp(lpAddress, lpBuffer, nSize);
		}

		return true;
	}

	BOOL Read_ReadProcessMemory(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize)
	{
		Debug("[*] Reading memory through ReadProcessMemory.");

		SIZE_T NumberOfBytesRead = 0;
		return ReadProcessMemory(ProcessHandle, lpAddress, lpBuffer, nSize, &NumberOfBytesRead);
	}

	BOOL Read_NtReadVirtualMemory(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize)
	{
		Debug("[*] Reading memory through NtReadVirtualMemory.");

		ULONG NumberOfBytesRead = 0;
		return NT_SUCCESS(fNtReadVirtualMemory(ProcessHandle, (PVOID)lpAddress, lpBuffer, nSize, &NumberOfBytesRead));
	}

	BOOL Read_NtReadVirtualMemoryImp(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize)
	{
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
		NTSTATUS Status = fNtProtectVirtualMemory(ProcessHandle, lpAddress, dwSize, flNewProtect, lpflOldProtect);
		return NT_SUCCESS(Status);
	}

	BOOL Protect_NtProtectVirtualMemoryImp(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
	{
		NTSTATUS Status = NtProtectVirtualMemory(ProcessHandle, lpAddress, dwSize, flNewProtect, lpflOldProtect);
		return NT_SUCCESS(Status);
	}

	// REMOTE THREAD
	int RemoteThreadMode = REMOTETHREAD_CREATEREMOTETHREAD;

	HANDLE RemoteThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
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
		}

		return INVALID_HANDLE_VALUE;
	}

	HANDLE RemoteThread_CreateRemoteThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
	{
		Debug("[*] Creating a remote thread through CreateRemoteThread.");

		return CreateRemoteThread(ProcessHandle, NULL, NULL, lpStartAddress, lpParameter, NULL, NULL);
	}

	HANDLE RemoteThread_NtCreateThreadEx(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
	{
		Debug("[*] Creating a remote thread through NtCreateThreadEx.");

		HANDLE ThreadHandle = 0;
		NTSTATUS Status = fNtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, FALSE, NULL, NULL, NULL, NULL);

		return ThreadHandle;
	}

	HANDLE RemoteThread_NtCreateThreadExImp(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
	{
		Debug("[*] Creating a remote thread through NtCreateThreadExImp.");

		HANDLE ThreadHandle = 0;
		NTSTATUS Status = NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, FALSE, NULL, NULL, NULL, NULL);

		return ThreadHandle;
	}

	bool UnlinkFromPeb = false;
	bool DeletePEHeader = false;

	BOOLEAN Dll_UnlinkFromPeb(LPVOID DllBase)
	{
		// Allocating memory from target process for our shellcode.
		LPVOID ShellcodeAddress = Alloc(NULL, UNLINKFROMPEBSHELLCODESIZE, PAGE_EXECUTE_READWRITE);
		if (!ShellcodeAddress)
		{
			Debug("[-] Alloc failed.");

			return false;
		}

		// Writing the shellcode + params to our allocated memory.
		if (!Write(ShellcodeAddress, Dll_UnlinkFromPeb_Shellcode, UNLINKFROMPEBSHELLCODESIZE))
		{
			Debug("[-] Write failed.");

			if (!Free(ShellcodeAddress))
				Debug("[-] Free failed.");

			return false;
		}

		// Executing the shellcode with these params.
		HANDLE hUnlinkFromPebShellcode = RemoteThread((LPTHREAD_START_ROUTINE)ShellcodeAddress, DllBase);
		if (!hUnlinkFromPebShellcode)
		{
			Debug("[-] RemoteThread failed.");

			if (!Free(ShellcodeAddress))
				Debug("[-] Free failed.");

			return false;
		}

		// Waiting for shellcode thread to finish.
		WaitForSingleObject(hUnlinkFromPebShellcode, INFINITE);

		if (!Free(ShellcodeAddress))
			Debug("[-] Free failed.");

		return true;
	}

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