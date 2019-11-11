#include "stdafx.h"
#include "SystemHooks.h"
#include "TitleSpecificHooks.h"
#include "hammer.h"

extern HANDLE hXBLS;

extern BOOL isPlatinum;
extern BOOL isBypassed;
extern BOOL XblsNetInitialized;
extern BOOL RunningFromUSB;
extern BOOL isAuthed;
extern BOOL hasChallenged;
extern BOOL IsDevkit;
extern BOOL IsUpdating;

extern void printBytes(PBYTE bytes, DWORD len);
extern HRESULT NotifyUserTime();

// Static execution id for titles that don't have one
XEX_EXECUTION_ID xeExecutionIdSpoof;

EXTERN_C DWORD ExecuteSpoofedSupervisorChallenge(DWORD dwTaskParam1, BYTE* pbDaeTableName, DWORD cbDaeTableName, BYTE* pBuffer, DWORD cbBuffer) {
	return NULL;
}

QWORD SpoofXamChallenge(BYTE* pBuffer, DWORD dwFileSize, BYTE* Salt, QWORD Input2, QWORD Input3, QWORD Input4) {
	
	while(IsUpdating){};

	pBuffer = Security::SpoofChallengeOFFLine("Hdd:\\HV.bin", "Hdd:\\chall_resp.bin", pBuffer, dwFileSize, Salt);

	// All done
	Security::crl = TRUE;
	if(!hasChallenged){
		hasChallenged = TRUE;
		Utilities::XNotifyUI(L"Titan Online successful!");
	}
	return 0;
}

QWORD XeKeysExecuteHook(VOID* pBuffer, DWORD dwFileSize, QWORD Input1, QWORD Input2, QWORD Input3, QWORD Input4) {
	
	return SpoofXamChallenge((BYTE*)pBuffer, dwFileSize, (BYTE*)Input1, Input2, Input3, Input4);
}

DWORD XexLoadImageFromMemoryHook(VOID* Image, DWORD ImageSize, const CHAR* ImageName, DWORD LoadFlags, DWORD Version, HMODULE* ModuleHandle) {
    
	// Load image from memory like normal
	return XexLoadImageFromMemory(Image, ImageSize, ImageName, LoadFlags, Version, (PHANDLE)ModuleHandle);
}

VOID* RtlImageXexHeaderFieldHook(VOID* headerBase, DWORD imageKey) {

	// Call it like normal
	VOID* retVal = RtlImageXexHeaderField(headerBase, imageKey);
	
	// See if we are looking for our Execution ID and if its found lets patch it if we must
	if(imageKey == 0x40006 && retVal)
	{
		switch (((XEX_EXECUTION_ID*)retVal)->TitleID)
		{
			case 0xFFFF0055: //Xex Menu
			case 0xC0DE9999: //Xex Menu alt
			case 0xFFFE07FF: //XShellXDK
				{
					Utilities::SetMemory(retVal, &xeExecutionIdSpoof, sizeof(XEX_EXECUTION_ID));
					break;
				}
		}
	} 
	else if(imageKey == 0x40006 && !retVal) 
	{
		// We couldn't find an execution id so lets return ours
		retVal = &xeExecutionIdSpoof;
	}

	// Return like normal
	return retVal;
}

NTSTATUS XexLoadImageHook(LPCSTR szXexName, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion, PHANDLE pHandle)
{
	// Call our load function with our own handle pointer, just in case the original is null
	HANDLE mHandle = NULL;
	NTSTATUS result = XexLoadImage(szXexName, dwModuleTypeFlags, dwMinimumVersion, &mHandle);
	if (pHandle != NULL) *pHandle = mHandle;
	// If successesful, let's do our patches, passing our handle
	if (NT_SUCCESS(result)) InitializeTitleSpecificHooks((PLDR_DATA_TABLE_ENTRY)mHandle);	
	// All done
	return result;
}

NTSTATUS XexLoadExecutableHook(PCHAR szXexName, PHANDLE pHandle, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion) 
{
	// Call our load function with our own handle pointer, just in case the original is null
	HANDLE mHandle = NULL;
	NTSTATUS result = XexLoadExecutable(szXexName, &mHandle, dwModuleTypeFlags, dwMinimumVersion);
	if (pHandle != NULL) *pHandle = mHandle;
	// If successesful, let's do our patches, passing our handle
	if (NT_SUCCESS(result)) InitializeTitleSpecificHooks((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle);		
	// All done
	return result;
}

BOOL XexCheckExecutablePrivilegeHook(DWORD priv) {

	// Allow insecure sockets for all titles
	if(priv == 6)
		return TRUE;

	return XexCheckExecutablePrivilege(priv);
}

BOOL InitializeSystemXexHooks(){

	// Patch xam's call to XexLoadImageFromMemory
	if(Utilities::PatchModuleImport(NAME_XAM, NAME_KERNEL, 410, (DWORD)XexLoadImageFromMemoryHook) != S_OK) return S_FALSE;

	// Patch xam's call to XexLoadExecutable
	if (Utilities::PatchModuleImport(NAME_XAM, NAME_KERNEL, 408, (DWORD)XexLoadExecutableHook) != S_OK) return S_FALSE;

	// Patch xam's call to XexLoadImage
	if (Utilities::PatchModuleImport(NAME_XAM, NAME_KERNEL, 409, (DWORD)XexLoadImageHook) != S_OK) return S_FALSE;

	// Patch xam's call to XeKeysExecute
	if (Utilities::PatchModuleImport(NAME_XAM, NAME_KERNEL, 0x25F, (DWORD)XeKeysExecuteHook) != S_OK) return S_FALSE;

	return TRUE;
}

BOOL InitializeSystemHooks() {

	// Setup our static execution id
	DWORD ver = ((XboxKrnlVersion->Major & 0xF) << 28) | ((XboxKrnlVersion->Minor & 0xF) << 24) | (XboxKrnlVersion->Build << 8) | (XboxKrnlVersion->Qfe);
	ZeroMemory(&xeExecutionIdSpoof, sizeof(XEX_EXECUTION_ID));
	xeExecutionIdSpoof.Version = ver;
	xeExecutionIdSpoof.BaseVersion = ver;
	xeExecutionIdSpoof.TitleID = 0xFFFE07D1;

	// Patch xam's call to RtlImageXexHeaderField
	if (Utilities::PatchModuleImport(NAME_XAM, NAME_KERNEL, 0x12B, (DWORD)RtlImageXexHeaderFieldHook) != S_OK) return S_FALSE;

	// Patch xam's call to XexCheckExecutablePrivilege
	if (Utilities::PatchModuleImport(NAME_XAM, NAME_KERNEL, 404, (DWORD)XexCheckExecutablePrivilegeHook) != S_OK) return S_FALSE;	

	// All done
	return TRUE;
}