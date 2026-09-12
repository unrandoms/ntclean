#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include <clocale>
#define STATIC_SYSCALLS
#include "Structs.h"
#include <conio.h>

/*--------------------------------------------------------------------
  DYNAMIC SYSCALL TABLE  (Task 1 - Hell's Gate)
--------------------------------------------------------------------*/
static SYSCALL_ENTRY g_SyscallTable[MAX_SYSCALL_ENTRIES];
static DWORD         g_SyscallCount = 0;
static PBYTE         g_StubPool     = NULL;

static void WriteStub(PBYTE dst, WORD ssn) {
	dst[0]  = 0x4C; dst[1]  = 0x8B; dst[2]  = 0xD1;
	dst[3]  = 0xB8;
	dst[4]  = (BYTE)(ssn & 0xFF);
	dst[5]  = (BYTE)((ssn >> 8) & 0xFF);
	dst[6]  = 0x00;
	dst[7]  = 0x00;
	dst[8]  = 0x0F; dst[9]  = 0x05;
	dst[10] = 0xC3;
}

static BOOL BuildSyscallTable(PBYTE cleanBase) {
	PIMAGE_DOS_HEADER       dosHdr = (PIMAGE_DOS_HEADER)cleanBase;
	PIMAGE_NT_HEADERS       ntHdrs = (PIMAGE_NT_HEADERS)(cleanBase + dosHdr->e_lfanew);
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
		if (fnBytes[0] != 0x4C || fnBytes[1] != 0x8B ||
		    fnBytes[2] != 0xD1 || fnBytes[3] != 0xB8)
			continue;

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

PVOID GetSyscallStub(const char* name) {
	for (DWORD i = 0; i < g_SyscallCount; i++) {
		if (strcmp(g_SyscallTable[i].name, name) == 0)
			return g_SyscallTable[i].stub;
	}
	return NULL;
}

/*--------------------------------------------------------------------
  MULTI-DLL TARGET ARRAY  (Task 2)
  Add a new DLL by appending one entry to this array.
  name_prefix = NULL means compare all exported functions.
--------------------------------------------------------------------*/
static target_dll_t g_targets[] = {
	{ "ntdll.dll",      L"ntdll.dll",      "Nt", FALSE, NULL, NULL, {0} },
	{ "kernelbase.dll", L"KernelBase.dll", NULL, FALSE, NULL, NULL, {0} },
	{ "win32u.dll",     L"win32u.dll",     "Nt", FALSE, NULL, NULL, {0} },
};
#define TARGET_COUNT ((DWORD)(sizeof(g_targets) / sizeof(g_targets[0])))

/*--------------------------------------------------------------------
  HELPERS
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

/* Returns 0 when the function is in the skip list (not a real Nt syscall stub) */
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

/* Find a named export in a clean DLL image and return its address.
   Returns NULL if the name is not found.                           */
static PBYTE FindInClean(PBYTE cleanBase, const char* funcName) {
	PIMAGE_DOS_HEADER       dosHdr = (PIMAGE_DOS_HEADER)cleanBase;
	PIMAGE_NT_HEADERS       ntHdrs = (PIMAGE_NT_HEADERS)(cleanBase + dosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(cleanBase +
		ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD nameRva  = (PDWORD)(cleanBase + expDir->AddressOfNames);
	PWORD  ordinals = (PWORD) (cleanBase + expDir->AddressOfNameOrdinals);
	PDWORD funcRva  = (PDWORD)(cleanBase + expDir->AddressOfFunctions);
	for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
		if (strcmp((const char*)(cleanBase + nameRva[i]), funcName) == 0)
			return cleanBase + funcRva[ordinals[i]];
	}
	return NULL;
}

/* TRUE when the first 5 bytes of both addresses are identical.     */
static BOOL PrologueMatchesClean(PBYTE liveAddr, PBYTE cleanAddr) {
	return memcmp(liveAddr, cleanAddr, 5) == 0;
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
		return NULL;
	}

	status = NtCreateSectionArbitrary(&hSection, SECTION_ALL_ACCESS,NULL,0, PAGE_READONLY, SEC_IMAGE,ntdllHandle);

	if (status != 0) {
		std::cout << "[ERROR] Cannot create a section" << std::endl;
		CloseHandle(ntdllHandle);
		return NULL;
	}
	status = ZwMapViewOfSectionArbitrary(hSection, GetCurrentProcess(), &sectionBaseAddress, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_READONLY);

	if (status != 0x40000003){
		std::cout << "[ERROR] Cannot map the section" << std::endl;
		CloseHandle(hSection);
		CloseHandle(ntdllHandle);
		return NULL;
	}

	std::cout << "[DONE] Clean section mapped at 0x" << std::hex << (ULONG_PTR)sectionBaseAddress << std::endl;
	CloseHandle(hSection);
	CloseHandle(ntdllHandle);
	return sectionBaseAddress;
}

/*--------------------------------------------------------------------
  UnhookDll  (Task 2)
  Patches every export whose live prologue differs from the clean copy.
--------------------------------------------------------------------*/
UNHOOK_STATS UnhookDll(target_dll_t* target) {
	UNHOOK_STATS stats = {0};
	PBYTE liveBase  = target->live_base;
	PBYTE cleanBase = (PBYTE)target->clean_mapping;

	PIMAGE_DOS_HEADER       dosHdr = (PIMAGE_DOS_HEADER)liveBase;
	PIMAGE_NT_HEADERS       ntHdrs = (PIMAGE_NT_HEADERS)(liveBase + dosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(liveBase +
		ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD nameRva  = (PDWORD)(liveBase + expDir->AddressOfNames);
	PWORD  ordinals = (PWORD) (liveBase + expDir->AddressOfNameOrdinals);
	PDWORD funcRva  = (PDWORD)(liveBase + expDir->AddressOfFunctions);

	PIMAGE_SECTION_HEADER sects = (PIMAGE_SECTION_HEADER)(
		(PBYTE)ntHdrs + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER textSect = NULL;
	for (WORD s = 0; s < ntHdrs->FileHeader.NumberOfSections; s++) {
		if (strcmp((const char*)sects[s].Name, ".text") == 0) {
			textSect = &sects[s];
			break;
		}
	}
	if (!textSect) {
		std::cout << "[ERROR] No .text section in " << target->dll_name << std::endl;
		return stats;
	}

	ULONG  oldProtect   = 0;
	LPVOID lpBase       = liveBase + textSect->VirtualAddress;
	SIZE_T sectionBytes = (SIZE_T)textSect->Misc.VirtualSize;
	NTSTATUS status = ZwProtectVirtualMemoryArbitrary(GetCurrentProcess(),
		&lpBase, &sectionBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (status != 0) {
		std::cout << "[ERROR] Cannot change .text permissions for "
		          << target->dll_name << " (0x" << std::hex << status << ")" << std::endl;
		return stats;
	}

	for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
		const char* funcName = (const char*)(liveBase + nameRva[i]);
		PBYTE       liveAddr = liveBase + funcRva[ordinals[i]];

		if (target->name_prefix &&
		    strncmp(funcName, target->name_prefix, strlen(target->name_prefix)) != 0)
			continue;

		if (strcmp(target->dll_name, "ntdll.dll") == 0 && !nameException(funcName))
			continue;

		PBYTE cleanAddr = FindInClean(cleanBase, funcName);
		if (!cleanAddr)
			continue;

		if (!PrologueMatchesClean(liveAddr, cleanAddr)) {
			stats.total_checked++;
			std::cout << "[WARNING] Potential hook in " << target->dll_name
			          << " : " << funcName << std::endl;

			memcpy(liveAddr, cleanAddr, 24);

			if (PrologueMatchesClean(liveAddr, cleanAddr)) {
				std::cout << "[SUCCESS] Unhooked " << target->dll_name
				          << " : " << funcName << std::endl;
				stats.unhooked++;
			} else {
				std::cout << "[FAILED]  Unhook failed in " << target->dll_name
				          << " : " << funcName << std::endl;
				stats.failed++;
			}
		}
	}

	ZwProtectVirtualMemoryArbitrary(GetCurrentProcess(),
		&lpBase, &sectionBytes, oldProtect, &oldProtect);

	return stats;
}

/*--------------------------------------------------------------------
  VerifyDll  (Task 3)
  After all patching is complete, re-read each qualifying function's
  live prologue and compare it to the clean copy.  Counts:
    verified_clean  - prologue now matches the on-disk image
    still_hooked    - prologue still differs (patch failed or racing EDR)
  Names of still-hooked functions are recorded (up to MAX_STILL_HOOKED).
--------------------------------------------------------------------*/
VERIFY_STATS VerifyDll(target_dll_t* target) {
	VERIFY_STATS stats = {0};
	PBYTE liveBase  = target->live_base;
	PBYTE cleanBase = (PBYTE)target->clean_mapping;

	PIMAGE_DOS_HEADER       dosHdr = (PIMAGE_DOS_HEADER)liveBase;
	PIMAGE_NT_HEADERS       ntHdrs = (PIMAGE_NT_HEADERS)(liveBase + dosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(liveBase +
		ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD nameRva  = (PDWORD)(liveBase + expDir->AddressOfNames);
	PWORD  ordinals = (PWORD) (liveBase + expDir->AddressOfNameOrdinals);
	PDWORD funcRva  = (PDWORD)(liveBase + expDir->AddressOfFunctions);

	for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
		const char* funcName = (const char*)(liveBase + nameRva[i]);
		PBYTE       liveAddr = liveBase + funcRva[ordinals[i]];

		/* Apply the same filter as UnhookDll for a consistent view. */
		if (target->name_prefix &&
		    strncmp(funcName, target->name_prefix, strlen(target->name_prefix)) != 0)
			continue;

		if (strcmp(target->dll_name, "ntdll.dll") == 0 && !nameException(funcName))
			continue;

		PBYTE cleanAddr = FindInClean(cleanBase, funcName);
		if (!cleanAddr)
			continue;

		if (PrologueMatchesClean(liveAddr, cleanAddr)) {
			stats.verified_clean++;
		} else {
			if (stats.still_hooked < MAX_STILL_HOOKED) {
				strncpy_s(stats.still_hooked_names[stats.still_hooked],
				          128, funcName, _TRUNCATE);
			}
			stats.still_hooked++;
		}
	}

	return stats;
}


int main(int argc, char** argv) {
	printBanner();

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 1;

	/* ---- Traverse PEB to locate all target DLLs ---- */
	PLIST_ENTRY head   = &pCurrentPeb->LoaderData->InMemoryOrderModuleList;
	PLIST_ENTRY cursor = head->Flink;
	int moduleIdx = 0;
	while (cursor != head) {
		PLDR_DATA_TABLE_ENTRY entry =
			(PLDR_DATA_TABLE_ENTRY)((PBYTE)cursor - 0x10);
		for (DWORD t = 0; t < TARGET_COUNT; t++) {
			if (!g_targets[t].is_loaded &&
			    _wcsicmp(entry->BaseDllName.Buffer, g_targets[t].dll_wname) == 0) {
				g_targets[t].is_loaded  = TRUE;
				g_targets[t].live_base  = (PBYTE)entry->DllBase;
				g_targets[t].full_path  = entry->FullDllName;
				std::cout << "[FOUND] " << g_targets[t].dll_name
				          << " at module index " << moduleIdx << std::endl;
			}
		}
		moduleIdx++;
		cursor = cursor->Flink;
	}

	/* ---- Create clean on-disk section mappings ---- */
	for (DWORD t = 0; t < TARGET_COUNT; t++) {
		if (!g_targets[t].is_loaded) {
			std::cout << "[SKIP] " << g_targets[t].dll_name
			          << " not found in PEB, skipping" << std::endl;
			continue;
		}
		g_targets[t].clean_mapping = loadModuleAsSection(&g_targets[t].full_path);
		if (!g_targets[t].clean_mapping) {
			std::cout << "[WARN] Could not map clean copy of "
			          << g_targets[t].dll_name << std::endl;
		}
	}

	/* ---- Build dynamic SSN table from clean NTDLL (index 0) ---- */
	if (g_targets[0].is_loaded && g_targets[0].clean_mapping)
		BuildSyscallTable((PBYTE)g_targets[0].clean_mapping);

	/* ---- Unhook pass: patch all hooked functions in every DLL ---- */
	int totalUnhooked = 0, totalFailed = 0;
	for (DWORD t = 0; t < TARGET_COUNT; t++) {
		if (!g_targets[t].is_loaded || !g_targets[t].clean_mapping)
			continue;
		std::cout << "\n[---] Unhooking " << g_targets[t].dll_name << " ..." << std::endl;
		UNHOOK_STATS us = UnhookDll(&g_targets[t]);
		totalUnhooked += us.unhooked;
		totalFailed   += us.failed;
		std::cout << "[" << g_targets[t].dll_name << "] "
		          << std::dec << us.total_checked << " hooked, "
		          << us.unhooked << " patched, "
		          << us.failed   << " failed" << std::endl;
	}

	/* ---- Verification pass: re-read live prologues vs clean ---- */
	std::cout << "\n[===] Post-unhook verification" << std::endl;
	int totalVerified = 0, totalStillHooked = 0;
	for (DWORD t = 0; t < TARGET_COUNT; t++) {
		if (!g_targets[t].is_loaded || !g_targets[t].clean_mapping)
			continue;
		VERIFY_STATS vs = VerifyDll(&g_targets[t]);
		totalVerified    += vs.verified_clean;
		totalStillHooked += vs.still_hooked;
		std::cout << "[" << g_targets[t].dll_name << "] "
		          << std::dec << vs.verified_clean << " verified clean, "
		          << vs.still_hooked << " still hooked" << std::endl;
		/* Report each name that remains hooked (up to the cap). */
		int reportLimit = (vs.still_hooked < MAX_STILL_HOOKED)
		                  ? vs.still_hooked : MAX_STILL_HOOKED;
		for (int k = 0; k < reportLimit; k++) {
			std::cout << "  [HOOK REMAINS] " << vs.still_hooked_names[k] << std::endl;
		}
		if (vs.still_hooked > MAX_STILL_HOOKED) {
			std::cout << "  ... and " << (vs.still_hooked - MAX_STILL_HOOKED)
			          << " more (name buffer full)" << std::endl;
		}
	}

	/* ---- Final summary ---- */
	std::cout << "\n[SUMMARY] Unhooked: " << std::dec << totalUnhooked
	          << " | Verified clean: " << totalVerified
	          << " | Still hooked: "   << totalStillHooked << std::endl;

	if (totalStillHooked > 0) {
		std::cout << "[WARN] " << totalStillHooked
		          << " function(s) remain hooked after patching." << std::endl;
	} else {
		std::cout << "[OK] All targeted functions verified clean." << std::endl;
	}

	std::cout << "Press a key to continue ..." << std::endl;
	_getch();

	/* Non-zero exit when any function remains hooked (usable in CI). */
	return (totalStillHooked > 0) ? 1 : 0;
}
