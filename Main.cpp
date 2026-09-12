#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include <clocale>
#define STATIC_SYSCALLS
#include "Structs.h"
#include <conio.h>

/*--------------------------------------------------------------------
  DYNAMIC SYSCALL TABLE  (Task 1 - Hell's Gate)
  Populated at runtime from the clean on-disk NTDLL copy so that SSNs
  are always correct regardless of Windows version or patch level.
--------------------------------------------------------------------*/
static SYSCALL_ENTRY g_SyscallTable[MAX_SYSCALL_ENTRIES];
static DWORD         g_SyscallCount = 0;
static PBYTE         g_StubPool     = NULL; /* RWX allocation holding all stubs */

/* Write an 11-byte x64 syscall stub at dst for the given SSN.
   Layout: mov r10,rcx  |  mov eax,ssn  |  syscall  |  ret        */
static void WriteStub(PBYTE dst, WORD ssn) {
	dst[0]  = 0x4C; dst[1]  = 0x8B; dst[2]  = 0xD1; /* mov r10, rcx        */
	dst[3]  = 0xB8;                                   /* mov eax, imm32 ...  */
	dst[4]  = (BYTE)(ssn & 0xFF);
	dst[5]  = (BYTE)((ssn >> 8) & 0xFF);
	dst[6]  = 0x00;
	dst[7]  = 0x00;                                   /* ... imm32 high word */
	dst[8]  = 0x0F; dst[9]  = 0x05;                  /* syscall             */
	dst[10] = 0xC3;                                   /* ret                 */
}

/* Enumerate Nt* exports in the clean NTDLL section, extract each SSN
   from the "mov eax, SSN" at function offset +4, and emit a dynamic
   stub into the pre-allocated RWX pool.                             */
static BOOL BuildSyscallTable(PBYTE cleanBase) {
	PIMAGE_DOS_HEADER      dosHdr  = (PIMAGE_DOS_HEADER)cleanBase;
	PIMAGE_NT_HEADERS      ntHdrs  = (PIMAGE_NT_HEADERS)(cleanBase + dosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(cleanBase +
		ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD nameRva  = (PDWORD)(cleanBase + expDir->AddressOfNames);
	PWORD  ordinals = (PWORD) (cleanBase + expDir->AddressOfNameOrdinals);
	PDWORD funcRva  = (PDWORD)(cleanBase + expDir->AddressOfFunctions);

	g_StubPool = (PBYTE)VirtualAlloc(NULL,
		MAX_SYSCALL_ENTRIES * SYSCALL_STUB_SIZE,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!g_StubPool) {
		std::cout << "[ERROR] VirtualAlloc for stub pool failed (0x"
		          << std::hex << GetLastError() << ")" << std::endl;
		return FALSE;
	}

	g_SyscallCount = 0;
	for (DWORD i = 0; i < expDir->NumberOfNames && g_SyscallCount < MAX_SYSCALL_ENTRIES; i++) {
		const char* funcName = (const char*)(cleanBase + nameRva[i]);
		if (strncmp(funcName, "Nt", 2) != 0)
			continue;

		PBYTE fnBytes = cleanBase + funcRva[ordinals[i]];

		/* Verify this is a genuine syscall stub:
		   offset 0-2 = 4C 8B D1 (mov r10, rcx)
		   offset 3   = B8       (mov eax, imm32)           */
		if (fnBytes[0] != 0x4C || fnBytes[1] != 0x8B ||
		    fnBytes[2] != 0xD1 || fnBytes[3] != 0xB8)
			continue;

		/* SSN is the little-endian WORD at offset 4 (the imm16 of mov eax) */
		WORD ssn = *(WORD*)(fnBytes + 4);

		PSYSCALL_ENTRY entry = &g_SyscallTable[g_SyscallCount];
		strncpy_s(entry->name, sizeof(entry->name), funcName, _TRUNCATE);
		entry->ssn  = ssn;
		PBYTE stub  = g_StubPool + g_SyscallCount * SYSCALL_STUB_SIZE;
		WriteStub(stub, ssn);
		entry->stub = stub;
		g_SyscallCount++;
	}

	std::cout << "[DONE] Dynamic syscall table: resolved " << std::dec
	          << g_SyscallCount << " Nt* SSNs from clean NTDLL" << std::endl;
	return g_SyscallCount > 0;
}

/* Return the RWX stub pointer for a named Nt* function, or NULL.   */
PVOID GetSyscallStub(const char* name) {
	for (DWORD i = 0; i < g_SyscallCount; i++) {
		if (strcmp(g_SyscallTable[i].name, name) == 0)
			return g_SyscallTable[i].stub;
	}
	return NULL;
}

/*--------------------------------------------------------------------
  HELPERS retained from the original codebase
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

void printBanner() {
	const char* banner ="\n"
		"	  .oooooo.             oooo             .o8                                      \n"
		"	 d8P'  `Y8b            `888            \"888                                     \n"
		"	888           .ooooo.   888   .ooooo.   888oooo.   .ooooo.  oooo d8b ooo. .oo.  \n"
		"	888          d88' `88b  888  d88' `88b  d88' `88b d88' `88b `888\"\"8P `888P\"Y88b  \n"
		"	888          888ooo888  888  888ooo888  888   888 888   888  888      888   888  \n"
		"	 88b    ooo  888    .o  888  888    .o  888   888 888   888  888      888   888  \n"
		"	 `Y8bood8P'  `Y8bod8P' o888o `Y8bod8P'  `Y8bod8P' `Y8bod8P' d888b    o888o o888o \n"
		"                                       by @R0h1rr1m                                    \n";
	std::cout << banner << std::endl;
}

/* Returns 0 when the function should be skipped (not a real Nt stub) */
int nameException(const char* functionName) {
	const char* listOfNames[] = {
		"NtGetTickCount","NtQuerySystemTime",
		"NtdllDefWindowProc_A","NtdllDefWindowProc_W",
		"NtdllDialogWndProc_A","NtdllDialogWndProc_W"
	};
	for (int i = 0; i < 6; i++) {
		if (strcmp(functionName, listOfNames[i]) == 0)
			return 0;
	}
	return 1;
}

bool replaceTheContentOfFunction(const PCHAR funcNameForUnhook, PBYTE destinationAddress, PBYTE cleanNTDLLModule) {
	PBYTE imageBaseAddressOfNTDLL = (PBYTE)cleanNTDLLModule;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBaseAddressOfNTDLL;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)(imageBaseAddressOfNTDLL + dosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(imageBaseAddressOfNTDLL + imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD nameArray = (PDWORD)(imageBaseAddressOfNTDLL + imageExportDirectory->AddressOfNames);
	PWORD ordinalArray = (PWORD)(imageBaseAddressOfNTDLL + imageExportDirectory->AddressOfNameOrdinals);
	PDWORD addressArray = (PDWORD)(imageBaseAddressOfNTDLL + imageExportDirectory->AddressOfFunctions);
	PCHAR functionNameTemp;
	PBYTE functionAddrTemp;
	bool fixedOrNot = false;
	for (unsigned int i = 0; i < imageExportDirectory->NumberOfNames; i++) {
		functionNameTemp = (PCHAR)(imageBaseAddressOfNTDLL + nameArray[i]);
		functionAddrTemp = (PBYTE)(imageBaseAddressOfNTDLL + addressArray[ordinalArray[i]]);
		if (strncmp(functionNameTemp, funcNameForUnhook, strlen(funcNameForUnhook)) == 0) {
			memcpy(destinationAddress,functionAddrTemp,24);
			fixedOrNot = (destinationAddress[0] == 0x4C && destinationAddress[1] == 0x8B && destinationAddress[2] == 0xD1 && destinationAddress[3] == 0xB8);
			break;
		}
	}
	return fixedOrNot;
}

PVOID loadModuleAsSection(UNICODE_STRING * dllPath) {
	HANDLE ntdllHandle = NULL;
	HANDLE hSection = NULL;
	IO_STATUS_BLOCK IoStatusBlock;
	ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	OBJECT_ATTRIBUTES FileObjectAttributes;
	PVOID sectionBaseAddress = 0;
	SIZE_T viewSize = 0;
	UNICODE_STRING ucFilepath;
	WCHAR wcFilepath[100] = L"\\??\\\\";
	wcscat_s(wcFilepath, dllPath->Buffer);
	RtlInitUnicodeString(&ucFilepath, wcFilepath);
	InitializeObjectAttributes(&FileObjectAttributes,&ucFilepath, 0x00000040L, NULL, NULL);
	NTSTATUS status = NtCreateFileArbitrary(&ntdllHandle, FILE_GENERIC_READ, &FileObjectAttributes, &IoStatusBlock, 0,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, 0x1, 0x00000020, NULL, 0);

	if (ntdllHandle == INVALID_HANDLE_VALUE || status != 0) {
		std::cout << "[ERROR] Cannot open the clean version" << std::endl;
		exit(1);
	}

	status = NtCreateSectionArbitrary(&hSection, SECTION_ALL_ACCESS,NULL,0, PAGE_READONLY, SEC_IMAGE,ntdllHandle);

	if (status != 0) {
		std::cout << "[ERROR] Cannot create a section" << std::endl;
		exit(1);
	}
	status = ZwMapViewOfSectionArbitrary(hSection, GetCurrentProcess(), &sectionBaseAddress, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_READONLY);

	if (status != 0x40000003){
		std::cout << "[ERROR] Cannot map the section failed" << std::endl;
		exit(1);
	}

	std::cout << "[DONE] New section is created for clean " << std::endl;
	CloseHandle(hSection);
	CloseHandle(ntdllHandle);
	return sectionBaseAddress;
}


int main(int argc, char** argv) {
	printBanner();
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0;
	PVOID newSectionForNTDLL;
	PLDR_DATA_TABLE_ENTRY ntdllModule = NULL;
	PLIST_ENTRY beginningOfTheList = &pCurrentPeb->LoaderData->InMemoryOrderModuleList;
	PLIST_ENTRY cursorOfModules = beginningOfTheList->Flink;
	PLDR_DATA_TABLE_ENTRY currentModule;
	int count = 0;
	while (cursorOfModules != beginningOfTheList) {
		currentModule = (PLDR_DATA_TABLE_ENTRY) ((PBYTE)cursorOfModules - 0x10);
		if (wcscmp(currentModule->BaseDllName.Buffer, L"ntdll.dll") == 0) {
			std::cout << "[FOUND] Loaded Module Index of NTDLL.dll is " << count << std::endl;
			ntdllModule = currentModule;
		}
		count++;
		cursorOfModules = cursorOfModules->Flink;
	}
	if (ntdllModule) {
		newSectionForNTDLL = loadModuleAsSection(&ntdllModule->FullDllName);

		/* --- Task 1: Build dynamic SSN table from the clean NTDLL copy --- */
		BuildSyscallTable((PBYTE)newSectionForNTDLL);

		PBYTE imageBaseAddressOfNTDLL = (PBYTE) ntdllModule->DllBase;
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBaseAddressOfNTDLL;
		PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)(imageBaseAddressOfNTDLL + dosHeader->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(imageBaseAddressOfNTDLL + imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		PDWORD nameArray = (PDWORD) (imageBaseAddressOfNTDLL + imageExportDirectory->AddressOfNames);
		PWORD ordinalArray = (PWORD) (imageBaseAddressOfNTDLL + imageExportDirectory->AddressOfNameOrdinals);
		PDWORD addressArray = (PDWORD) (imageBaseAddressOfNTDLL + imageExportDirectory->AddressOfFunctions);
		PCHAR functionName;
		PBYTE functionAddr;
		PIMAGE_SECTION_HEADER textSection = (PIMAGE_SECTION_HEADER) (((PBYTE)imageNTHeaders) + sizeof(IMAGE_NT_HEADERS));
		for (unsigned int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
			if (strcmp((const char *)textSection[i].Name,".text") == 0) {
				std::cout << "[FOUND] Text Section Found" << std::endl;
				textSection = &textSection[i];
				break;
			}
		}

		ULONG oldProtection = 0;
		LPVOID lpBaseAddress = imageBaseAddressOfNTDLL + textSection->VirtualAddress;
		SIZE_T sizeOfSection= textSection->Misc.VirtualSize;
		bool returnFlag;
		NTSTATUS status = ZwProtectVirtualMemoryArbitrary(GetCurrentProcess(), &lpBaseAddress, &sizeOfSection, PAGE_EXECUTE_READWRITE, &oldProtection);
		if (status != 0) {
			std::cout << "[ERROR] Cannot change the permission of Text Section" << std::endl;
			exit(0);
		}

		for (unsigned int i = 0; i < imageExportDirectory->NumberOfNames; i++) {
			functionName = (PCHAR)( imageBaseAddressOfNTDLL + nameArray[i]);
			functionAddr = (PBYTE)(imageBaseAddressOfNTDLL + addressArray[ordinalArray[i]]);
			if (strncmp(functionName, "Nt", 2) == 0){
				if (!(functionAddr[0] == 0x4C && functionAddr[1] == 0x8B && functionAddr[2] == 0xD1 && functionAddr[3] == 0xB8) && nameException(functionName)) {
					std::cout << "[WARNING] Potential Hook : " << functionName << std::endl;
					returnFlag = replaceTheContentOfFunction(functionName, functionAddr,(PBYTE) newSectionForNTDLL);
					if (returnFlag) {
						std::cout << "[SUCCESS] Unhook success for " << functionName << std::endl;
					}
					else {
						std::cout << "[FAILED] Unhook failed for " << functionName << std::endl;
					}
				}
			}
		}

		status = ZwProtectVirtualMemoryArbitrary(GetCurrentProcess(), &lpBaseAddress, &sizeOfSection, oldProtection, &oldProtection);
		if (status != 0) {
			std::cout << "[ERROR] Cannot restore the permission of Text Section" << std::endl;
			exit(0);
		}
	}
	else {
		std::cout << "[ERROR] Cannot Find NTDLL.dll" << std::endl;
	}
	std::cout << "Press a key to continue ..." << std::endl;
	_getch();
	return 0;
}
