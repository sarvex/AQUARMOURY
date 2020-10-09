#pragma once

#include <Windows.h>
#include <wincrypt.h>
#include <string>

// Library function definitions
// ------------------------------------------------------------------------

typedef BOOL(WINAPI* _CryptAcquireContextW)(
	HCRYPTPROV *phProv,
    LPCWSTR    szContainer,
    LPCWSTR    szProvider,
    DWORD      dwProvType,
    DWORD      dwFlags
    );

typedef BOOL(WINAPI* _CryptReleaseContext)(
	HCRYPTPROV hProv,
    DWORD      dwFlags
    );

typedef BOOL(WINAPI* _CryptDeriveKey)(
	HCRYPTPROV hProv,
    ALG_ID     Algid,
    HCRYPTHASH hBaseData,
    DWORD      dwFlags,
    HCRYPTKEY  *phKey
    );

typedef BOOL(WINAPI * _CryptDestroyKey)(
	HCRYPTKEY hKey
	);

typedef BOOL(WINAPI* _CryptSetKeyParam)(
    HCRYPTKEY  hKey,
    DWORD      dwParam,
    const BYTE *pbData,
    DWORD      dwFlags
    );

typedef BOOL(WINAPI* _CryptDecrypt)(
	HCRYPTKEY  hKey,
    HCRYPTHASH hHash,
    BOOL       Final,
    DWORD      dwFlags,
    BYTE       *pbData,
    DWORD      *pdwDataLen
    );

typedef BOOL(WINAPI* _CryptCreateHash)(
	HCRYPTPROV hProv,
    ALG_ID     Algid,
    HCRYPTKEY  hKey,
    DWORD      dwFlags,
    HCRYPTHASH *phHash
    );

typedef BOOL(WINAPI* _CryptHashData)(
	HCRYPTHASH hHash,
    const BYTE *pbData,
    DWORD      dwDataLen,
    DWORD      dwFlags
    );

typedef BOOL(WINAPI* _CryptDestroyHash)(
	HCRYPTHASH hHash
	);

// To decrypt an AES-CBC 256 encrypted string with the appropriate PSK
// The result of the AESDecrypt operation will be reflected back in the argument itself
// ------------------------------------------------------------------------

BOOL aes_decrypt(std::string &ciphertext, std::string &iv, char* key) {
    // Dynamically resolve the API functions from Advapi32
    HMODULE Advapi32 = LoadLibraryA("Advapi32.dll");

    _CryptAcquireContextW CryptAcquireContextW = (_CryptAcquireContextW)
        GetProcAddress(Advapi32, "CryptAcquireContextW");
    if (CryptAcquireContextW == NULL) {
        return FALSE;
    }

    _CryptCreateHash CryptCreateHash = (_CryptCreateHash)
        GetProcAddress(Advapi32, "CryptCreateHash");
    if (CryptCreateHash == NULL) {
        return FALSE;
    }

    _CryptHashData CryptHashData = (_CryptHashData)
        GetProcAddress(Advapi32, "CryptHashData");
    if (CryptHashData == NULL) {
        return FALSE;
    }

    _CryptDeriveKey CryptDeriveKey = (_CryptDeriveKey)
        GetProcAddress(Advapi32, "CryptDeriveKey");
    if (CryptDeriveKey == NULL) {
        return FALSE;
    }

    _CryptSetKeyParam CryptSetKeyParam = (_CryptSetKeyParam)
        GetProcAddress(Advapi32, "CryptSetKeyParam");
    if (CryptSetKeyParam == NULL) {
        return FALSE;
    }

    _CryptDecrypt CryptDecrypt = (_CryptDecrypt)
        GetProcAddress(Advapi32, "CryptDecrypt");
    if (CryptDecrypt == NULL) {
        return FALSE;
    }

    _CryptReleaseContext CryptReleaseContext = (_CryptReleaseContext)
        GetProcAddress(Advapi32, "CryptReleaseContext");
    if (CryptReleaseContext == NULL) {
        return FALSE;
    }

    _CryptDestroyHash CryptDestroyHash = (_CryptDestroyHash)
        GetProcAddress(Advapi32, "CryptDestroyHash");
    if (CryptDestroyHash == NULL) {
        return FALSE;
    }

    _CryptDestroyKey CryptDestroyKey = (_CryptDestroyKey)
        GetProcAddress(Advapi32, "CryptDestroyKey");
    if (CryptDestroyKey == NULL) {
        return FALSE;
    }

    // Init some important stuff
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    // Decrypt
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return FALSE;
    }

    if (!CryptHashData(hHash, (BYTE*)key, strlen(key), 0)) {
        return FALSE;              
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)) {
        return FALSE;
    }

    if(!CryptSetKeyParam(hKey, KP_IV, (BYTE *)&iv[0], 0)) {
        return FALSE;
    }

    DWORD dwDataLen = ciphertext.length();
    if(!CryptDecrypt(hKey, NULL, TRUE, 0, (BYTE *)&ciphertext[0], &dwDataLen)) {
        return FALSE;
    }

    // Resize to actual ciphertext length
    ciphertext.resize(dwDataLen);

    // Cleanup
    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return TRUE;
}
