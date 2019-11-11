#include "stdafx.h"
#include "SystemHooks.h"
#include "KeyVault.h"
#include "hammer.h"

KEY_VAULT Security::keyVault;
BYTE Security::kvDigest[XECRYPT_SHA_DIGEST_SIZE];
BYTE Security::seshKey[16];
BYTE Security::hvRandomData[0x80];
BYTE Security::cpuKeyDigest[0x14];
BYTE Security::cpuKey[0x10];
BYTE Security::realCpuKey[0x10];

DWORD Security::dwUpdateSequence;
WCHAR Security::wErrMsg[ERRMSGLEN];

BOOL Security::fcrt = FALSE;
BOOL Security::crl = FALSE;
BOOL Security::type1KV = FALSE;
BOOL Security::fReboot = FALSE;
BOOL Security::canConnect = FALSE;

// XBLS Server
BOOL isPlatinum = FALSE;
BOOL isBypassed = FALSE;
BOOL isAuthed = FALSE;
BOOL hasChallenged = FALSE; 
BOOL dashLoaded = FALSE;

// Module handles
HANDLE hXBLS	= NULL;
HANDLE hXam     = NULL;
HANDLE hKernel  = NULL;

// Some helpful bools
BOOL XblsNetInitialized = FALSE;
BOOL IsDevkit = FALSE;
BOOL PresenceUpdateAlertShown = FALSE;
BOOL RunningFromUSB = FALSE;

HRESULT initNetwork();
HRESULT initXBLS();
BOOL IsUpdating = TRUE;

HRESULT Initialize() {

	//Running on devkit?
	IsDevkit =  *(DWORD*)0x8E038610 & 0x8000 ? FALSE : TRUE;
	Utilities::SetLiveBlock(TRUE);
	DbgPrint("Running on %s", IsDevkit ? "Devkit" : "Retail");

	if (XboxKrnlVersion->Build != supportedVersion)	{
		if(IsDevkit){
			DbgPrint("[WRN] Kernel version not supported!");
		}else{
			DbgPrint("Kernel version not supported!");
			return E_FAIL;
		}
	}

	Utilities::setErrMsg(L"\0\0");
	//lets not allow this xex to launch after system bootup
#if defined(_DEBUG) || defined(_DEVKIT)
	//DbgPrint("Skipping bootup check...");
#else
	if (*(WORD*)0x98000000 != 0x4D5A)
	{
		return E_FAIL;
	}
#endif

	if ((XboxHardwareInfo->Flags & 0x20) == 0x20) {
		if (Utilities::CreateSymbolicLink(XBLS_DRIVE_HDD, XBLS_DEVICE_NAME_HDD, TRUE) != ERROR_SUCCESS) {
			DbgPrint("Failed to map HDD");
			return E_FAIL;
		}
		DbgPrint("Running from HDD");
	}else{
		if (Utilities::CreateSymbolicLink(XBLS_DRIVE_USB, XBLS_DEVICE_NAME_USB, TRUE) != ERROR_SUCCESS) {
			DbgPrint("Failed to map USB");
			return E_FAIL;
		}
		DbgPrint("Running from USB");
		RunningFromUSB = TRUE;
	}

    hXBLS = GetModuleHandle(NAME_XBLS);
	hXam = GetModuleHandle(NAME_XAM);
	hKernel = GetModuleHandle(NAME_KERNEL);
	if (hXBLS == 0 || hXam == 0 || hKernel == 0){
		DbgPrint("Failed to get system module handles");
		return E_FAIL;
	}

	if(!InitializeSystemHooks()) {
		DbgPrint("InitializeSystemHooks failed");
		return E_FAIL;
	}

	if(!InitializeSystemXexHooks()) {
		DbgPrint("InitializeSystemXexHooks failed");
		return E_FAIL;
	}
	
	// Make sure we can peek and poke hv data
	if(HvPeekPoke::InitializeHvPeekPoke() != ERROR_SUCCESS) {
		DbgPrint("InitializeHvPeekPoke failed");
		return E_FAIL;
	}

	if (Security::ProcessRandomHVData() != ERROR_SUCCESS)	{
		DbgPrint("ProcessRandomHVData failed");
		return E_FAIL;
	}

	if(Security::ProcessCPUKeyBin(RunningFromUSB ? PATH_CPUKEY_USB : PATH_CPUKEY_HDD) != ERROR_SUCCESS) {
		DbgPrint("ProcessCPUKeyBin failed");
		return E_FAIL;
	}

	if (Utilities::ApplyPatches(RunningFromUSB ? PATH_KXAM_PATCHES_USB : PATH_KXAM_PATCHES_HDD, PATCH_DATA_KXAM_RETAIL) == 0) {
		DbgPrint("ApplyPatches returned 0");
		return E_FAIL;
	}

	if (Utilities::FileExists(RunningFromUSB ? PATH_KEYVAULT_USB : PATH_KEYVAULT_HDD)){
		DbgPrint("KV found on HDD/USB, using");
		if(Security::SetKeyVault(RunningFromUSB ? PATH_KEYVAULT_USB : PATH_KEYVAULT_HDD) != ERROR_SUCCESS) {
			DbgPrint("SetKeyVault(HDD/USB) failed");
			return E_FAIL;
		}	
	}else{
		DbgPrint("No KV found on HDD/USB, using existing");
		BYTE* kv = (BYTE*)malloc(0x4000);
		QWORD kvAddress = IsDevkit ? HvPeekPoke::HvPeekQWORD(0x00000002000160c0) : HvPeekPoke::HvPeekQWORD(0x0000000200016240);  //16547
		HvPeekPoke::HvPeekBytes(kvAddress, kv, 0x4000);
		if(Security::SetKeyVault(kv) != ERROR_SUCCESS) {
			DbgPrint("SetKeyVault(Flash) failed");
			free(kv);
			return E_FAIL;
		}
		free(kv);
	}
	Security::SetXConfigSettings();

	if (!XamCacheReset(XAM_CACHE_TICKETS)) DbgPrint("XamCacheReset failed");
	if (!XamCacheReset(XAM_CACHE_ALL)) DbgPrint("XamCacheReset failed");
	
	// All done
	return ERROR_SUCCESS;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	
	// Check how we want to enter
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH: {
				if (!Utilities::IsTrayOpen()){
				if (Initialize() == ERROR_SUCCESS) {
					DbgPrint("Titan is ready!");
				} else {
					DbgPrint("Titan failed to start!");
					HalReturnToFirmware(HalResetSMCRoutine);
				}}
				else{
					Utilities::SetLiveBlock(TRUE);
					DbgPrint("Titan Aborted, Tray Open...");
				}
				break;
		}
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
    return TRUE;
}
