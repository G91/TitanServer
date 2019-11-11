#pragma once
#include <xtl.h>
#include <xboxmath.h>
#include <xkelib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <time.h>
#include <string>
#include "KeyVault.h"

using namespace std;
#define SPOOF_MS_POINTS

// Module names
#define NAME_KERNEL				    "xboxkrnl.exe"
#define NAME_XAM				    "xam.xex"
#define NAME_XBLS				    "Titan.xex"

// File names
#define NAME_CPUKEY				    "CPUKey.bin"
#define NAME_KEYVAULT				"KV.bin"
#define NAME_KXAM_PATCHES		    "kxam.patch"
#define NAME_XOSC_DUMP				"xoscDump.bin"
#define NAME_XAM_DUMP				"xamDump.bin"
#define NAME_CHAL_DUMP				"chalDump.bin"
#define NAME_LOG					"xbls.log"

// Devices, and device paths
#define XBLS_DEVICE_NAME_HDD		"\\Device\\Harddisk0\\Partition1"
#define XBLS_DRIVE_HDD			    "HDD:\\"

#define XBLS_DEVICE_NAME_USB		"\\Device\\Mass0"
#define XBLS_DRIVE_USB			    "USB:\\"

#ifdef _DEVKIT
#define XBLS_DIRECTORY_HDD				"DEVKIT\\XBLS\\"
#define XBLS_DIRECTORY_USB				""
#else
#define XBLS_DIRECTORY_HDD				""
#define XBLS_DIRECTORY_USB				""
#endif

// File paths
#define PATH_KXAM_PATCHES_HDD		    XBLS_DRIVE_HDD XBLS_DIRECTORY_HDD NAME_KXAM_PATCHES
#define PATH_CPUKEY_HDD				    XBLS_DRIVE_HDD XBLS_DIRECTORY_HDD NAME_CPUKEY
#define PATH_KEYVAULT_HDD				XBLS_DRIVE_HDD XBLS_DIRECTORY_HDD NAME_KEYVAULT
#define PATH_XBLS_HDD					XBLS_DRIVE_HDD XBLS_DIRECTORY_HDD NAME_XBLS
#define PATH_XOSC_DUMP_HDD				XBLS_DRIVE_HDD XBLS_DIRECTORY_HDD NAME_XOSC_DUMP
#define PATH_XAM_DUMP_HDD				XBLS_DRIVE_HDD XBLS_DIRECTORY_HDD NAME_XAM_DUMP
#define PATH_CHAL_DUMP_HDD				XBLS_DRIVE_HDD XBLS_DIRECTORY_HDD NAME_CHAL_DUMP
#define PATH_LOG_HDD					XBLS_DRIVE_HDD XBLS_DIRECTORY_HDD NAME_LOG

#define PATH_KXAM_PATCHES_USB		    XBLS_DRIVE_USB XBLS_DIRECTORY_USB NAME_KXAM_PATCHES
#define PATH_CPUKEY_USB				    XBLS_DRIVE_USB XBLS_DIRECTORY_USB NAME_CPUKEY
#define PATH_KEYVAULT_USB				XBLS_DRIVE_USB XBLS_DIRECTORY_USB NAME_KEYVAULT
#define PATH_XBLS_USB					XBLS_DRIVE_USB XBLS_DIRECTORY_USB NAME_XBLS
#define PATH_XOSC_DUMP_USB				XBLS_DRIVE_USB XBLS_DIRECTORY_USB NAME_XOSC_DUMP
#define PATH_XAM_DUMP_USB				XBLS_DRIVE_USB XBLS_DIRECTORY_USB NAME_XAM_DUMP
#define PATH_CHAL_DUMP_USB				XBLS_DRIVE_USB XBLS_DIRECTORY_USB NAME_CHAL_DUMP
#define PATH_LOG_USB					XBLS_DRIVE_USB XBLS_DIRECTORY_USB NAME_LOG

#define PACKET_SIZE 1024
#define DbgPrint

#define hvKvPtrDev      0x00000002000162e0
#define hvKvPtrRetail   0x0000000200016240
#define xamConCert      0x81AC75F0

#define supportedVersion 17150
#define ERRMSGLEN 50

enum AUTH_FLAGS {
	AUTH_BRONZE,
	AUTH_SILVER,
	AUTH_GOLD,
	AUTH_ADMIN
};

enum PACKET_FLAGS {
	PACKET_NULL,
	PACKET_KEY,
	PACKET_AUTH,
	PACKET_CHALLENGE,
	PACKET_UPDATEPRESENCE,
	PACKET_REBOOT,
	PACKET_DASHBOARD,
	PACKET_MESSAGE,
	PACKET_MESSAGEBOX,
	PACKET_GetXNotify,
	PACKET_BRICK
};

enum PACKET_RESULT_FLAGS {
	PACKET_SUCCESS,
	PACKET_FAILED,
	PACKET_UPDATE
};

typedef enum _XBOX_GAMES : DWORD {	
    COD_BLACK_OPS_2 = 0x415608C3,
	DASHBOARD = 0xFFFE07D1,
	FREESTYLEDASH = 0xF5D20000,
	COD_GHOSTS = 0x415608fc,
	COD_AW = 0x41560914
} XBOX_GAMES;

const BYTE PATCH_DATA_KXAM_RETAIL[112] = {
	0x81, 0x68, 0x23, 0x84, 0x00, 0x00, 0x00, 0x01, 0x60, 0x00, 0x00, 0x00,
	0x81, 0x67, 0xF7, 0xB8, 0x00, 0x00, 0x00, 0x01, 0x38, 0x60, 0x00, 0x00,
	0x81, 0x67, 0xC2, 0xBC, 0x00, 0x00, 0x00, 0x01, 0x38, 0x60, 0x00, 0x00,
	0x81, 0x92, 0x6D, 0xC8, 0x00, 0x00, 0x00, 0x01, 0x60, 0x00, 0x00, 0x00,
	0x81, 0x67, 0x96, 0xF4, 0x00, 0x00, 0x00, 0x01, 0x60, 0x00, 0x00, 0x00,
	0x81, 0x6D, 0xCB, 0x58, 0x00, 0x00, 0x00, 0x01, 0x39, 0x60, 0x00, 0x01,
	0x81, 0x6D, 0xCB, 0xCC, 0x00, 0x00, 0x00, 0x01, 0x39, 0x60, 0x00, 0x01,
	0x81, 0x6D, 0xCB, 0xC4, 0x00, 0x00, 0x00, 0x01, 0x39, 0x60, 0x00, 0x01,
	0x81, 0x6D, 0xCB, 0xB8, 0x00, 0x00, 0x00, 0x01, 0x39, 0x60, 0x00, 0x01,
	0xFF, 0xFF, 0xFF, 0xFF
};

// Hardcoded keys
const BYTE DeveloperKey19[0x10]		= { 0xDA, 0xB6, 0x9A, 0xD9, 0x8E, 0x28, 0x76, 0x4F, 0x97, 0x7E, 0xE2, 0x48, 0x7E, 0x4F, 0x3F, 0x68 };
const BYTE RetailKey19[0x10]		= { 0xE1, 0xBC, 0x15, 0x9C, 0x73, 0xB1, 0xEA, 0xE9, 0xAB, 0x31, 0x70, 0xF3, 0xAD, 0x47, 0xEB, 0xF3 };
const BYTE SupportedXAMChallengeHash[XECRYPT_SHA_DIGEST_SIZE] = { 0x60, 0x1D, 0x32, 0x4B, 0x53, 0xFA, 0x35, 0xFF, 0xB7, 0x26, 0x20, 0x36, 0xC2, 0xC4, 0xF8, 0x3B, 0x0D, 0x81, 0x39, 0xFC };

const BYTE SupportedXOSCChallengeHash[XECRYPT_SHA_DIGEST_SIZE] = { 0xAD, 0x6F, 0x40, 0x07, 0x11, 0x54, 0x8E, 0xAE, 0x0C, 0x2B, 0x20, 0x9F, 0x9A, 0xE6, 0x02, 0x31, 0x80, 0x1D, 0x2A, 0xFF };
const BYTE MasterKey[272] = {
    0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0xDD, 0x5F, 0x49, 0x6F, 0x99, 0x4D, 0x37, 0xBB, 0xE4, 0x5B, 0x98, 0xF2, 0x5D, 0xA6, 0xB8, 0x43, 
    0xBE, 0xD3, 0x10, 0xFD, 0x3C, 0xA4, 0xD4, 0xAC, 0xE6, 0x92, 0x3A, 0x79, 0xDB, 0x3B, 0x63, 0xAF, 
    0x38, 0xCD, 0xA0, 0xE5, 0x85, 0x72, 0x01, 0xF9, 0x0E, 0x5F, 0x5A, 0x5B, 0x08, 0x4B, 0xAD, 0xE2, 
    0xA0, 0x2A, 0x42, 0x33, 0x85, 0x34, 0x53, 0x83, 0x1E, 0xE5, 0x5B, 0x8F, 0xBF, 0x35, 0x8E, 0x63, 
    0xD8, 0x28, 0x8C, 0xFF, 0x03, 0xDC, 0xC4, 0x35, 0x02, 0xE4, 0x0D, 0x1A, 0xC1, 0x36, 0x9F, 0xBB, 
    0x90, 0xED, 0xDE, 0x4E, 0xEC, 0x86, 0x10, 0x3F, 0xE4, 0x1F, 0xFD, 0x96, 0xD9, 0x3A, 0x78, 0x25, 
    0x38, 0xE1, 0xD3, 0x8B, 0x1F, 0x96, 0xBD, 0x84, 0xF6, 0x5E, 0x2A, 0x56, 0xBA, 0xD0, 0xA8, 0x24, 
    0xE5, 0x02, 0x8F, 0x3C, 0xA1, 0x9A, 0xEB, 0x93, 0x59, 0xD7, 0x1B, 0x99, 0xDA, 0xC4, 0xDF, 0x7B, 
    0xD0, 0xC1, 0x9A, 0x12, 0xCC, 0x3A, 0x17, 0xBF, 0x6E, 0x4D, 0x78, 0x87, 0xD4, 0x2A, 0x7F, 0x6B, 
    0x9E, 0x2F, 0xCD, 0x8D, 0x4E, 0xF5, 0xCE, 0xC2, 0xA0, 0x5A, 0xA3, 0x0F, 0x9F, 0xAD, 0xFE, 0x12, 
    0x65, 0x74, 0x20, 0x6F, 0xF2, 0x5C, 0x52, 0xE4, 0xB0, 0xC1, 0x3C, 0x25, 0x0D, 0xAE, 0xD1, 0x82, 
    0x7C, 0x60, 0xD7, 0x44, 0xE5, 0xCD, 0x8B, 0xEA, 0x6C, 0x80, 0xB5, 0x1B, 0x7A, 0x0C, 0x02, 0xCE, 
    0x0C, 0x24, 0x51, 0x3D, 0x39, 0x36, 0x4A, 0x3F, 0xD3, 0x12, 0xCF, 0x83, 0x8D, 0x81, 0x56, 0x00, 
    0xB4, 0x64, 0x79, 0x86, 0xEA, 0xEC, 0xB6, 0xDE, 0x8A, 0x35, 0x7B, 0xAB, 0x35, 0x4E, 0xBB, 0x87, 
    0xEA, 0x1D, 0x47, 0x8C, 0xE1, 0xF3, 0x90, 0x13, 0x27, 0x97, 0x55, 0x82, 0x07, 0xF2, 0xF3, 0xAA, 
    0xF9, 0x53, 0x47, 0x8F, 0x74, 0xA3, 0x8E, 0x7B, 0xAE, 0xB8, 0xFC, 0x77, 0xCB, 0xFB, 0xAB, 0x8A
};


class Security {
  public:
	static KEY_VAULT keyVault;
	static BYTE kvDigest[XECRYPT_SHA_DIGEST_SIZE];

	static BYTE seshKey[16];
	static BYTE	hvRandomData[0x80];
	static BYTE	cpuKeyDigest[0x14];
	static BYTE cpuKey[0x10];
	static BYTE realCpuKey[0x10];

	static BOOL fcrt;
	static BOOL crl;
	static BOOL type1KV;
	static DWORD dwUpdateSequence;

	static WCHAR wErrMsg[ERRMSGLEN];
	static BOOL fReboot;
	static BOOL canConnect;
  public:
	static void DoSha1(void *Data, int Length, void *Out);
	static void DoRc4(void *Data, int Length);
	static void GetModuleHash(char* xex, BYTE *salt, BYTE *outHash);
	static void GetHvHash(char* HV, void *OutHash,BYTE *Salt);
	static BYTE* SpoofChallengeOFFLine(char* HV, char* Chall, BYTE* pBuffer, DWORD dwFileSize, BYTE* Salt);
	static BYTE* SpoofChallenge(BYTE* pBuffer, DWORD dwFileSize, BYTE* Salt, bool isAuthed);
	static HRESULT ProcessRandomHVData();
	static BOOL VerifyKeyVault();
	static HRESULT SetKeyVault(BYTE* KeyVault);
	static HRESULT SetKeyVault(CHAR* FilePath);
	static HRESULT ProcessCPUKeyBin(CHAR* FilePath);
	static VOID SetXConfigSettings();
};

#pragma pack(1)
typedef struct _XOSC {
	DWORD					dwResult;
    BYTE                    stuff1[0x4];
    QWORD                   qwOperations;
	BYTE					stuff2[0x40];
	BYTE                    bCpuKeyHash[0x10];
    BYTE                    bKvHash[0x10];
    BYTE                    stuff3[0x268];
	DWORD                   dwFooterMagic;
    DWORD                   dwUnknown9;
} XOSC, *pXOSC;
#pragma pack()

class MyxOsc {
  public:
	static DWORD CreateXOSCBuffer(DWORD dwTaskParam1, BYTE* pbDaeTableName, DWORD cbDaeTableName, XOSC* pBuffer, DWORD cbBuffer);
};

class ServerAuth {
  public:
	static bool InitServerAuth();
	static BOOL ServerAuth::OnStartAuth(WORD Port, char* xex, PBYTE CpuKey);
	static BOOL CheckForUpdated(WORD Port, char* xex, PBYTE CpuKey, bool hasChallenged);
	static BOOL DoMESSAGEBOX(WORD Port, PBYTE CpuKey);
};

class ServerCommunicator {
  public:
	static BOOL ServerConnect(BYTE *IPAddr, WORD Port);
	static BOOL ServerSendData(PBYTE Data, DWORD Length, DWORD Id);
	static PBYTE ServerRecieveData(PDWORD Length, DWORD *OutId);
	static VOID ServerClose();
};

class DataManager {
  public:
	static bool SendData(SOCKET Socket, void *Data, int Size, int Id);
	static void *RecieveData(SOCKET ClientSocket, int *Size, int *OutId);
};

class ServComm {
  public:
	static HRESULT StartupServerCommunicator();
	static HRESULT SendCommand(DWORD CommandId, VOID* CommandData, DWORD CommandLength, VOID* Responce, DWORD ResponceLength, BOOL KeepOpen = FALSE, BOOL NoReceive=FALSE);
	static HRESULT ReceiveData(VOID* Buffer, DWORD BytesExpected);
	static VOID EndCommand();
	static BYTE* GetIP(BYTE Index);
	static HRESULT SetGoodIPIndex();
	static HRESULT InitCommand(BYTE ipidx);
	static HRESULT Reset();
	static HRESULT SendData(VOID* CommandData, DWORD DataLen);
};

class MemoryBuffer
{
public:

	MemoryBuffer( DWORD dwSize = 512 )
	{
		m_pBuffer = NULL;
		m_dwDataLength = 0;
		m_dwBufferSize = 0;

		if( ( dwSize < UINT_MAX ) && ( dwSize != 0 ) )
		{
			m_pBuffer = ( BYTE* )malloc( dwSize + 1 );    // one more char, in case when using string funcions
			if( m_pBuffer )
			{
				m_dwBufferSize = dwSize;
				m_pBuffer[0] = 0;
			}
		}
	};

	~MemoryBuffer()
	{
		if( m_pBuffer )
			free( m_pBuffer );

		m_pBuffer = NULL;
		m_dwDataLength = 0;
		m_dwBufferSize = 0;
	};

    // Add chunk of memory to buffer
    BOOL    Add( const void* p, DWORD dwSize )
    {
        if( CheckSize( dwSize ) )
        {
            memcpy( m_pBuffer + m_dwDataLength, p, dwSize );
            m_dwDataLength += dwSize;
            *( m_pBuffer + m_dwDataLength ) = 0;    // fill end zero
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    };

    // Get the data in buffer
    BYTE* GetData() const
    {
        return m_pBuffer;
    };

    // Get the length of data in buffer
    DWORD   GetDataLength() const
    {
        return m_dwDataLength;
    };

    // Rewind the data pointer to the begining
    void    Rewind()
    {
        m_dwDataLength = 0; m_pBuffer[ 0 ] = 0;
    };

    // Automatically adjust increase buffer size if necessary
    BOOL    CheckSize( DWORD dwSize )
    {
        if( m_dwBufferSize >= ( m_dwDataLength + dwSize ) )
        {
            return TRUE;    // Enough space
        }
        else
        {
            // Try to double it
            DWORD dwNewSize = max( m_dwDataLength + dwSize, m_dwBufferSize * 2 );
            BYTE* pNewBuffer = ( UCHAR* )realloc( m_pBuffer, dwNewSize + 1 );        // one more char
            if( pNewBuffer )
            {
                m_pBuffer = pNewBuffer;
                m_dwBufferSize = dwNewSize;
                return TRUE;
            }
            else
            {
                // Failed
                return FALSE;
            }
        }
    }

	private:

	BYTE* m_pBuffer;

    DWORD m_dwDataLength;

    DWORD m_dwBufferSize;
};

class Utilities {
  public:
    static VOID XNotifyDoQueueUI(LPCWSTR pwszStringParam);
	static VOID XNotifyUI(LPCWSTR pwszStringParam);
	static HRESULT SetMemory(VOID* Destination, VOID* Source, DWORD Length);
	static HRESULT CreateSymbolicLink(CHAR* szDrive, CHAR* szDeviceName, BOOL System);
	static HRESULT DeleteSymbolicLink(CHAR* szDrive, BOOL System);
	static BOOL XeKeysPkcs1Verify(const BYTE* pbHash, const BYTE* pbSig, XECRYPT_RSA* pRsa);
	static DWORD makeBranch(DWORD branchAddr, DWORD destination, BOOL linked);
	static VOID PatchInJump(DWORD* Address, DWORD Destination, BOOL Linked);
	static VOID PatchInBranch(DWORD* Address, DWORD Destination, BOOL Linked);
	static FARPROC ResolveFunction(CHAR* ModuleName, DWORD Ordinal);
	static DWORD PatchModuleImport(CHAR* Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);
	static DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);
	static BOOL IsBufferEmpty(BYTE* Buffer, DWORD Length);
	static BOOL FileExists(LPCSTR lpFileName);
	static VOID hookFunctionStart(PDWORD addr, PDWORD saveStub, PDWORD oldData, DWORD dest);
	static DWORD relinkGPLR(int offset, PDWORD saveStubAddr, PDWORD orgAddr);
	static VOID patchInJump(DWORD* addr, DWORD dest, BOOL linked);
	static void SetLiveBlock(BOOL set);
	static BOOL IsTrayOpen();
	static int applyPatchData(DWORD* patchData);
	static DWORD ApplyPatches(CHAR* FilePath, const VOID* DefaultPatches);
	static BOOL CReadFile(const CHAR * FileName, MemoryBuffer &pBuffer);
	static BOOL CWriteFile(const CHAR* FilePath, const VOID* Data, DWORD Size);
	static VOID CpuKeyCheck(PBYTE realCpuKey);
	static void setErrMsg(WCHAR* msg);
	static BOOL errMsg();
};

class HvPeekPoke {
  public:
	static HRESULT InitializeHvPeekPoke();
	
	static BYTE    HvPeekBYTE(QWORD Address);
	static WORD    HvPeekWORD(QWORD Address);
	static DWORD   HvPeekDWORD(QWORD Address);
	static QWORD   HvPeekQWORD(QWORD Address);
	static HRESULT HvPeekBytes(QWORD Address, PVOID Buffer, DWORD Size);

	static HRESULT HvPokeBYTE(QWORD Address, BYTE Value);
	static HRESULT HvPokeWORD(QWORD Address, WORD Value);
	static HRESULT HvPokeDWORD(QWORD Address, DWORD Value);
	static HRESULT HvPokeQWORD(QWORD Address, QWORD Value);
	static HRESULT HvPokeBytes(QWORD Address, const void* Buffer, DWORD Size);
	static QWORD HvGetFuseLine(BYTE fuseIndex);
};

class BLACKOPS2 {
  public:
	  static void Start_BLACKOPS2_Bypass();
};

// Defines
#define XSTL_SERVER_VER 0x00000028

// Commands
#define XSTL_SERVER_COMMAND_ID_GET_TIME 		 0x00000000
#define XSTL_SERVER_COMMAND_ID_GET_SALT			 0x00000001
#define XSTL_SERVER_COMMAND_ID_GET_STATUS		 0x00000002
#define XSTL_SERVER_COMMAND_ID_GET_CHAL_RESPONSE 0x00000003
#define XSTL_SERVER_COMMAND_ID_UPDATE_PRESENCE   0x00000004
#define XSTL_SERVER_COMMAND_ID_GET_XOSC			 0x00000005
#define XSTL_SERVER_COMMAND_ID_GET_TOKEN		 0x00000006

// Status codes
#define XSTL_STATUS_SUCCESS   0x40000000
#define XSTL_STATUS_UPDATE    0x80000000
#define XSTL_STATUS_EXPIRED   0x90000000
#define XSTL_STATUS_ERROR     0xC0000000
#define XSTL_STATUS_BYPASS	  0xE0000000
#define XSTL_STATUS_STEALTHED 0xF0000000

// Structures
#pragma pack(1)
typedef struct _SERVER_GET_SALT_REQUEST {
	DWORD Version;
	DWORD ConsoleType;
	BYTE CpuKey[16];
	BYTE KeyVault[0x4000];
} SERVER_GET_SALT_REQUEST, *PSERVER_GET_SALT_REQUEST;

typedef struct _SERVER_GET_SALT_RESPONSE {
	DWORD Status;
} SERVER_GET_SALT_RESPONSE, *PSERVER_GET_SALT_RESPONSE;

typedef struct _SERVER_GET_STATUS_REQUEST {
	BYTE CpuKey[16];
	BYTE ExecutableHash[20];
} SERVER_GET_STATUS_REQUEST, *PSERVER_GET_STATUS_REQUEST;

typedef struct _SERVER_GET_STATUS_RESPONSE {
	DWORD Status;
} SERVER_GET_STATUS_RESPONSE, *PSERVER_GET_STATUS_RESPONSE;

typedef struct _SERVER_UPDATE_PRESENCE_REQUEST {
	BYTE  SessionKey[16];
	DWORD TitleId;
	BYTE Gamertag[16];
	DWORD Version;
	DWORD ConsoleType;
} SERVER_UPDATE_PRESENCE_REQUEST, *PSERVER_UPDATE_PRESENCE_REQUEST;

typedef struct _SERVER_UPDATE_PRESENCE_RESPONSE {
	DWORD Status;
	DWORD UpdateStatus;
} SERVER_UPDATE_PRESENCE_RESPONSE, *PSERVER_UPDATE_PRESENCE_RESPONSE;

typedef struct _SERVER_CHAL_REQUEST {
	BYTE SessionKey[16];
	BYTE Salt[16];
	BOOL Crl;
	BOOL Fcrt;
	BOOL Type1Kv;
	WORD ECC;
	BYTE padding[2]; //padding..
} SERVER_CHAL_REQUEST, *PSERVER_CHAL_REQUEST;

typedef struct _SERVER_CHAL_RESPONSE {
	DWORD Status;
	BYTE  Padding[0x1C];
	BYTE  Data[0xE0];
} SERVER_CHAL_RESPONSE, *PSERVER_CHAL_RESPONSE;

typedef struct _SERVER_XOSC_REQUEST {
	BYTE Session[0x10];
	DWORD ExecutionIdResult;
	XEX_EXECUTION_ID ExecutionId;
	QWORD HvProtectedFlags;
	BOOL Crl;
	BOOL Fcrt;
	BOOL Type1Kv;
} SERVER_XOSC_REQUEST, *pSERVER_XOSC_REQUEST;

typedef struct _SERVER_REQUEST_GET_CHUNKS {
	BYTE SessionKey[16];
} SERVER_REQUEST_GET_CHUNKS, *PSERVER_REQUEST_GET_CHUNKS;

typedef struct _SERVER_RESPONSE_GET_CHUNKS {
	//DWORD Status;
	DWORD dLen;
	WORD hvExLen;
	WORD saltHvExLen;
	WORD numChunks;
	BYTE padding[2]; //padding
	//BYTE* data[dLen];
} SERVER_RESPONSE_GET_CHUNKS, *PSERVER_RESPONSE_GET_CHUNKS;

typedef struct _SERVER_REQUEST_SET_CHUNKS {
	BYTE SessionKey[16];
	DWORD dLen;
	WORD numChunks;
	BYTE padding[2]; //padding
} SERVER_REQUEST_SET_CHUNKS, *PSERVER_REQUEST_SET_CHUNKS;

typedef struct _SERVER_RESPONSE_SET_CHUNKS {
	DWORD Status;
} SERVER_RESPONSE_SET_CHUNKS, *PSERVER_RESPONSE_SET_CHUNKS;


typedef struct _CHUNK_HEADER {
	DWORD addr;
	DWORD size;
	PBYTE data;
} CHUNK_HEADER, *PCHUNK_HEADER;

typedef struct _SERVER_GET_TIME_REQUEST {
	BYTE CpuKey[16];
} SERVER_GET_TIME_REQUEST, *PSERVER_GET_TIME_REQUEST;

typedef struct _SERVER_GET_TIME_RESPONSE {
	DWORD Status;
	DWORD userDays;
	DWORD userTimeRemaining;
} SERVER_GET_TIME_RESPONSE, *PSERVER_GET_TIME_RESPONSE;

typedef struct _SERVER_CODE_REDEEM_REQUEST {
	BYTE CpuKey[16];
	BYTE tokenCode[12];
	DWORD redeem;
} SERVER_CODE_REDEEM_REQUEST, *PSERVER_CODE_REDEEM_REQUEST;

typedef struct _SERVER_CODE_REDEEM_RESPONSE {
	DWORD Status;
	DWORD userDays;
} SERVER_CODE_REDEEM_RESPONSE, *PSERVER_CODE_REDEEM_RESPONSE;
#pragma pack()