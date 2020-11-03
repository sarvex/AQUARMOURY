#include "Structs.h"
#include "Syscalls.h"
#include "SectionRemap.h"

// Call after DLL is loaded
// ------------------------------------------------------------------------

void go() {
	// [DEBUG]
	//OutputDebugStringA("[DBG] Preparing to baptize tainted Ntdll!");

    // Resolve the direct syscalls
	if (!resolve_syscalls()) {
		//OutputDebugStringA("[DBG] Failed to resolve syscalls!");
		return;
	}
	//OutputDebugStringA("[DBG] Syscalls resolved!");

	// Attempt to perform Section Remapping
	if (!section_remap()) {
		//OutputDebugStringA("[DBG] Failed to perform Section Remapping!");
		return;
	}
	//OutputDebugStringA("[DBG] Section Remapping done!");
}

// DllMain
// ------------------------------------------------------------------------

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	HANDLE threadHandle;
	DWORD dwThread;

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		// Init Code here
		go();
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