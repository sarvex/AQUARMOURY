#pragma once

#include <Windows.h>
#include <stdio.h>

// Function prototypes
// ------------------------------------------------------------------------

typedef LSTATUS(WINAPI* _RegCreateKeyExA)(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD Reserved,
    LPSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition
    );

typedef LSTATUS(WINAPI* _RegSetValueExA)(
    HKEY hKey,
    LPCSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData
    );

typedef LSTATUS(WINAPI* _RegSetValueExW)(
	HKEY hKey,
    LPCWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData
    );

typedef LSTATUS(WINAPI* _RegOpenKeyExA)(
	HKEY hKey,
    LPCSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
    );

typedef LSTATUS(WINAPI* _RegDeleteTreeA)(
	HKEY hKey,
	LPCSTR lpSubKey
	);

typedef LSTATUS(WINAPI* _RegCloseKey)(
    HKEY hKey
    );

// To create registry keys for the driver
// ------------------------------------------------------------------------

BOOL create_reg_keys(LPSTR driverName, LPWSTR driverPath) {
    // Dynamically resolve the API function from Advapi32.dll
    HMODULE advapi32 = LoadLibraryA("Advapi32.dll");

    _RegCreateKeyExA RegCreateKeyExA = (_RegCreateKeyExA)GetProcAddress(advapi32, "RegCreateKeyExA");
    if (RegCreateKeyExA == NULL)
        return FALSE;

    _RegSetValueExA RegSetValueExA = (_RegSetValueExA)GetProcAddress(advapi32, "RegSetValueExA");
    if (RegSetValueExA == NULL)
        return FALSE;

    _RegSetValueExW RegSetValueExW = (_RegSetValueExW)GetProcAddress(advapi32, "RegSetValueExW");
    if (RegSetValueExW == NULL)
        return FALSE;

    _RegCloseKey RegCloseKey = (_RegCloseKey)GetProcAddress(advapi32, "RegCloseKey");
    if (RegCloseKey == NULL)
        return FALSE;

    // Create registry entry
    DWORD dwDisposition;
    HKEY hKey;
    LPCSTR lpSubKey[MAX_PATH];
    sprintf((char* const)lpSubKey, "System\\CurrentControlSet\\Services\\%s", driverName);
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, (LPCSTR)lpSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
    	RegCloseKey(hKey);
    	return FALSE;
    }

    // Set up ErrorControl subkey
    DWORD errorControl = 0;
    if (RegSetValueExA(hKey, "ErrorControl", 0, REG_DWORD, reinterpret_cast<BYTE *>(&errorControl), sizeof(errorControl)) != ERROR_SUCCESS) {
    	RegCloseKey(hKey);
        return FALSE; 
    }

    // Set up Start subkey
    DWORD start = 3;
    if (RegSetValueExA(hKey, "Start", 0, REG_DWORD, reinterpret_cast<BYTE *>(&start), sizeof(start)) != ERROR_SUCCESS) {
    	RegCloseKey(hKey);
        return FALSE; 
    }

    // Set up Type subkey
    DWORD type = 1;
    if (RegSetValueExA(hKey, "Type", 0, REG_DWORD, reinterpret_cast<BYTE *>(&type), sizeof(type)) != ERROR_SUCCESS) {
    	RegCloseKey(hKey);
        return FALSE;
    }

    // Set up ImagePath subkey
    LPWSTR imagePath = driverPath;
    SIZE_T imagePathSize = ((((DWORD)lstrlenW(imagePath) + 1)) * 2);
    if (RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, (const BYTE*)(imagePath), imagePathSize) != ERROR_SUCCESS) {
    	RegCloseKey(hKey);
        return FALSE;
    }

    // Cleanup
    RegCloseKey(hKey);

    return TRUE;
}

// To delete registry keys for the driver
// ------------------------------------------------------------------------

BOOL delete_reg_keys(LPCSTR driverName) {
	// Dynamically resolve the API function from Advapi32.dll
    HMODULE advapi32 = LoadLibraryA("Advapi32.dll");

    _RegOpenKeyExA RegOpenKeyExA = (_RegOpenKeyExA)GetProcAddress(advapi32, "RegOpenKeyExA");
    if (RegOpenKeyExA == NULL)
        return FALSE;

    _RegDeleteTreeA RegDeleteTreeA = (_RegDeleteTreeA)GetProcAddress(advapi32, "RegDeleteTreeA");
    if (RegDeleteTreeA == NULL)
        return FALSE;

    _RegCloseKey RegCloseKey = (_RegCloseKey)GetProcAddress(advapi32, "RegCloseKey");
    if (RegCloseKey == NULL)
        return FALSE;

    // Open registry key
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services", 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) {
    	RegCloseKey(hKey);
    	return FALSE;
    } 

    // Delete subkeys
    if (RegDeleteTreeA(hKey, driverName) != ERROR_SUCCESS) {
    	RegCloseKey(hKey);
    	return FALSE;
    }

    // Cleanup
    RegCloseKey(hKey);

    return TRUE;
}

// Check whether the driver exists on disk
// ------------------------------------------------------------------------

BOOL exists(LPWSTR driverPath) {
	DWORD fileCheck = GetFileAttributesW(driverPath);
	return (fileCheck != INVALID_FILE_ATTRIBUTES);
}
