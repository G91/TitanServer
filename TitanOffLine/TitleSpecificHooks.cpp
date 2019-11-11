#include "stdafx.h"
#include "TitleSpecificHooks.h"
#include "SystemHooks.h"
#include "hammer.h"

extern HANDLE hXam;

extern BOOL isPlatinum;
extern BOOL isBypassed;
extern BOOL IsDevkit;
extern BOOL dashLoaded;

extern DWORD ApplyPatches(CHAR* FilePath, const VOID* DefaultPatches = NULL);
extern int applyPatchData(DWORD* patchData);

extern void printBytes(PBYTE bytes, DWORD len);

DWORD XSecurityCreateProcessHook(DWORD dwHardwareThread)
{
	return ERROR_SUCCESS;
}

VOID XSecurityCloseProcessHook(){}
VOID __cdecl APCWorker(void* Arg1, void* Arg2, void* Arg3) {

	// Call our completion routine if we have one
	if(Arg2)
		((LPOVERLAPPED_COMPLETION_ROUTINE)Arg2)((DWORD)Arg3, 0, (LPOVERLAPPED)Arg1);
}

DWORD XSecurityVerifyHook(DWORD dwMilliseconds, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {

	// Queue our completion routine
	if(lpCompletionRoutine)	
		NtQueueApcThread((HANDLE)-2, (PIO_APC_ROUTINE)APCWorker, lpOverlapped, (PIO_STATUS_BLOCK)lpCompletionRoutine, 0);

	// All done
	return ERROR_SUCCESS;
}

DWORD XSecurityGetFailureInfoHook(PXSECURITY_FAILURE_INFORMATION pFailureInformation)
{
	if (pFailureInformation->dwSize != 0x18) return ERROR_NOT_ENOUGH_MEMORY;
	pFailureInformation->dwBlocksChecked = 0;
	pFailureInformation->dwFailedReads = 0;
	pFailureInformation->dwFailedHashes = 0;
	pFailureInformation->dwTotalBlocks = 0;
	pFailureInformation->fComplete = TRUE;
	return ERROR_SUCCESS;
}

DWORD XexGetProcedureAddressHook(HANDLE hand, DWORD dwOrdinal, PVOID* pvAddress)
{	
	// Check our module
	if(hand == hXam) {
		switch(dwOrdinal) {
			case 0x9BB:
				if (!isPlatinum) break;
				*pvAddress = XSecurityCreateProcessHook;
				return 0;
			case 0x9BC:
				if (!isPlatinum) break;
				*pvAddress = XSecurityCloseProcessHook;
				return 0;
			case 0x9BD:
				if (!isPlatinum) break;
				*pvAddress = XSecurityVerifyHook;
				return 0;
			case 0x9BE:
				if (!isPlatinum) break;
				*pvAddress = XSecurityGetFailureInfoHook;
				return 0;
		}
	}

	// Call our real function if we aren't interested
	return XexGetProcedureAddress(hand, dwOrdinal, pvAddress);
}

typedef HRESULT (*pXamInputGetState)(QWORD r3,QWORD r4,QWORD r5);
pXamInputGetState XamInputGetState = (pXamInputGetState)Utilities::ResolveFunction(NAME_XAM, 401);

static BOOL isFrozen = FALSE;
HRESULT XamInputGetStateHook(QWORD r3,QWORD r4,QWORD r5){
	if(isFrozen){
		return 0;
	}
	HRESULT ret = XamInputGetState(r3, r4, r5);
}

static DWORD lastTitleID=0;
VOID InitializeTitleSpecificHooks(PLDR_DATA_TABLE_ENTRY ModuleHandle) 
{
	// Hook any calls to XexGetProcedureAddress
	Utilities::PatchModuleImport(ModuleHandle, NAME_KERNEL, 407, (DWORD)XexGetProcedureAddressHook);

	// If this module tries to load more modules, this will let us get those as well
	Utilities::PatchModuleImport(ModuleHandle, NAME_KERNEL, 408, (DWORD)XexLoadExecutableHook);

	Utilities::PatchModuleImport(ModuleHandle, NAME_KERNEL, 409, (DWORD)XexLoadImageHook);

	Utilities::PatchModuleImport(ModuleHandle, NAME_XAM, 401, (DWORD)XamInputGetStateHook);

    XEX_EXECUTION_ID* pExecutionId = (XEX_EXECUTION_ID*)RtlImageXexHeaderField(ModuleHandle->XexHeaderBase, 0x00040006);
    if (pExecutionId == 0) return;

	if(wcscmp(ModuleHandle->BaseDllName.Buffer, L"dash.xex") == 0  || wcscmp(ModuleHandle->BaseDllName.Buffer, L"xshell.xex") == 0 || pExecutionId->TitleID == FREESTYLEDASH){
		dashLoaded=TRUE;
		lastTitleID = pExecutionId->TitleID;
	}else if(pExecutionId->TitleID == COD_BLACK_OPS_2){
		if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0){
			BLACKOPS2::Start_BLACKOPS2_Bypass();
		}
	}
}


