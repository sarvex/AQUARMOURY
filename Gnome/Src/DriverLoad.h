#pragma once

#include <Windows.h>
#include <string>

// Structs
// ------------------------------------------------------------------------

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// Function prototypes
// ------------------------------------------------------------------------

typedef VOID(NTAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef NTSTATUS(NTAPI* _NtLoadDriver)(
	PUNICODE_STRING DriverServiceName
	);

typedef NTSTATUS(NTAPI* _NtUnloadDriver)(
	PUNICODE_STRING DriverServiceName
	);

// Convert ANSI string to wide string
// ------------------------------------------------------------------------

std::wstring convert_ansi_to_wide(const std::string& str) {
    int count = MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), NULL, 0);
    std::wstring wstr(count, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), &wstr[0], count);
    return wstr;
}

// To load a driver
// ------------------------------------------------------------------------

BOOL load_driver(LPSTR driverName) {
	// Dynamically resolve the API functions from Ntdll.dll
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	_NtLoadDriver NtLoadDriver = (_NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");
	if (NtLoadDriver == NULL) {
		return FALSE;
	}

	// Convert driver name to wstring
	std::wstring driverNameW = convert_ansi_to_wide(std::string(driverName));

	// Append it to create the registry path source variable
	std::wstring regPathSourceW = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + driverNameW;

	// Init some important variables
	LPCWSTR regPathSource = regPathSourceW.c_str();
	UNICODE_STRING regPathDest;

    // Convert path to unicode
    RtlInitUnicodeString(&regPathDest, regPathSource);

    // Load the driver
    NTSTATUS status = NtLoadDriver(&regPathDest);
    if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	return TRUE;
}

// To unload a driver
// ------------------------------------------------------------------------

BOOL unload_driver(LPSTR driverName) {
	// Dynamically resolve the API functions from Ntdll.dll
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	_NtUnloadDriver NtUnloadDriver = (_NtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
	if (NtUnloadDriver == NULL) {
		return FALSE;
	}

	// Convert driver name to wstring
	std::wstring driverNameW = convert_ansi_to_wide(std::string(driverName));

	// Append it to create the registry path source variable
	std::wstring regPathSourceW = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + driverNameW;

	// Init some important variables
    PCWSTR regPathSource = regPathSourceW.c_str();
    UNICODE_STRING regPathDest;

    // Convert path to unicode
    RtlInitUnicodeString(&regPathDest, regPathSource);

    // Load the driver
    NTSTATUS status = NtUnloadDriver(&regPathDest);
    if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	return TRUE;
}
