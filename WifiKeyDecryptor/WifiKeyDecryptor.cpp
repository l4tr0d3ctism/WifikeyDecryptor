// wifikeyDecryptor.cpp : Defines the entry point for the console application.
#include <tchar.h>
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <locale>

#pragma comment (lib, "Crypt32.lib")
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)


using namespace std;
wstring_convert< codecvt<wchar_t, char, mbstate_t> > conv;

void listDir(const char * dirn);
string xmlfile, keyMaterial;
char filePath[1024];
wstring Wstr;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef LONG KPRIORITY; // Thread priority

typedef struct _SYSTEM_PROCESS_INFORMATION_DETAILD {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION_DETAILD, *PSYSTEM_PROCESS_INFORMATION_DETAILD;

typedef NTSTATUS(WINAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(
	IN       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT   PVOID SystemInformation,
	IN       ULONG SystemInformationLength,
	OUT OPTIONAL  PULONG ReturnLength
	);

//
// The function changes a privilege named pszPrivilege for
// the current process. If bEnablePrivilege is FALSE, the privilege
// will be disabled, otherwise it will be enabled.
//
BOOL SetCurrentPrivilege(LPCTSTR pszPrivilege,   // Privilege to enable/disable
	BOOL bEnablePrivilege)  // to enable or disable privilege
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);
	BOOL bSuccess = FALSE;

	if (!LookupPrivilegeValue(NULL, pszPrivilege, &luid)) return FALSE;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
		&hToken
		)) return FALSE;

	//
	// first pass.  get current privilege setting
	//
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious);

	if (GetLastError() == ERROR_SUCCESS) {
		//
		// second pass.  set privilege based on previous setting
		//
		tpPrevious.PrivilegeCount = 1;
		tpPrevious.Privileges[0].Luid = luid;

		if (bEnablePrivilege)
			tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
		else
			tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
				tpPrevious.Privileges[0].Attributes);

		AdjustTokenPrivileges(
			hToken,
			FALSE,
			&tpPrevious,
			cbPrevious,
			NULL,
			NULL);

		if (GetLastError() == ERROR_SUCCESS) bSuccess = TRUE;

		CloseHandle(hToken);
	}
	else {
		DWORD dwErrorCode = GetLastError();

		CloseHandle(hToken);
		SetLastError(dwErrorCode);
	}

	return bSuccess;
}

DWORD GetProcessIdByProcessName(LPCWSTR pszProcessName)
{
	SIZE_T bufferSize = 1024 * sizeof(SYSTEM_PROCESS_INFORMATION_DETAILD);
	PSYSTEM_PROCESS_INFORMATION_DETAILD pspid = NULL;
	HANDLE hHeap = GetProcessHeap();
	PBYTE pBuffer = NULL;
	ULONG ReturnLength;
	PFN_NT_QUERY_SYSTEM_INFORMATION pfnNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");
	NTSTATUS status;
	int uLen = lstrlenW(pszProcessName)*sizeof(WCHAR);

	__try {
		pBuffer = (PBYTE)HeapAlloc(hHeap, 0, bufferSize);
#pragma warning(disable: 4127)
		while (TRUE) {
#pragma warning(default: 4127)
			status = pfnNtQuerySystemInformation(SystemProcessInformation, (PVOID)pBuffer,
				bufferSize, &ReturnLength);
			if (status == STATUS_SUCCESS)
				break;
			else if (status != STATUS_INFO_LENGTH_MISMATCH) { // 0xC0000004L
				_tprintf(TEXT("ERROR 0x%X\n"), status);
				return 1;   // error
			}

			bufferSize *= 2;
			pBuffer = (PBYTE)HeapReAlloc(hHeap, 0, (PVOID)pBuffer, bufferSize);
		}

		for (pspid = (PSYSTEM_PROCESS_INFORMATION_DETAILD)pBuffer;;
		pspid = (PSYSTEM_PROCESS_INFORMATION_DETAILD)(pspid->NextEntryOffset + (PBYTE)pspid)) {

			if (pspid->ImageName.Length == uLen && lstrcmpiW(pspid->ImageName.Buffer, pszProcessName) == 0)
				return (DWORD)pspid->UniqueProcessId;

			if (pspid->NextEntryOffset == 0) break;
		}
	}
	__finally {
		pBuffer = (PBYTE)HeapFree(hHeap, 0, pBuffer);
	}
	return 0;
}

int convw() {
	wstring val = conv.from_bytes(keyMaterial);
	Wstr = val;
	return 0;
}

int wifikey() {
	BOOL bIsSuccess, bImpersonated = FALSE;
	HANDLE hProcess = NULL, hProcessToken = NULL;
	DATA_BLOB DataOut, DataVerify;
	// !!! in the next line you should copy the string from <keyMaterial>
	WCHAR szKey[800];
	convw();

	swprintf_s(szKey, (Wstr.length() + 1), L"%s", Wstr.c_str());




	BYTE byKey[1024];
	DWORD cbBinary, dwFlags, dwSkip;
	DWORD dwProcessId = GetProcessIdByProcessName(L"winlogon.exe");
	if (dwProcessId == 0) return 1;

	bIsSuccess = SetCurrentPrivilege(SE_DEBUG_NAME, TRUE);
	if (!bIsSuccess) return GetLastError();

	__try {
		hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwProcessId);
		if (!hProcess) __leave;
		bIsSuccess = OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hProcessToken);
		if (!bIsSuccess) __leave;
		bIsSuccess = ImpersonateLoggedOnUser(hProcessToken);
		if (!bIsSuccess) __leave;
		bImpersonated = TRUE;

		cbBinary = sizeof(byKey);
		bIsSuccess = CryptStringToBinary(szKey, lstrlenW(szKey), CRYPT_STRING_HEX, // CRYPT_STRING_HEX_ANY
			byKey, &cbBinary, &dwSkip, &dwFlags);
		if (!bIsSuccess) __leave;
		DataOut.cbData = cbBinary;
		DataOut.pbData = (BYTE*)byKey;

		if (CryptUnprotectData(&DataOut, NULL, NULL, NULL, NULL, 0, &DataVerify)) {
			_tprintf(TEXT("The decrypted data is: %hs\n"), DataVerify.pbData);
		}
	}
	__finally {
		if (bImpersonated)
			RevertToSelf();
		if (hProcess)
			CloseHandle(hProcess);
		if (hProcessToken)
			CloseHandle(hProcessToken);
	}
	return 0;
}

void listDir(const char * dirn)
{
	char dirnPath[1024];
	string search = "				<keyMaterial>";
	string search2 = "			<name>";
	string ssidname, line;

	sprintf_s((dirnPath), "%s\\*", dirn);
	WIN32_FIND_DATAA f;
	HANDLE h = FindFirstFileA(dirnPath, &f);
	if (h == INVALID_HANDLE_VALUE) { return; }
	do
	{
		const char * name = f.cFileName;
		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) { continue; }
		char filePath[1024];
		sprintf_s(filePath, "%s%s%s", dirn, "\\", name);

		ifstream myfile(filePath);
		if (myfile.is_open())
		{
			while (getline(myfile, line))
			{
				if (line.find(search2, 0) != string::npos) {
					ssidname = line;
					ssidname = ssidname.replace(0, 9, "");
					ssidname.resize(ssidname.size() - 7);
					cout << "SSID = " << ssidname << endl;
				}


				if (line.find(search, 0) != string::npos) {
					keyMaterial = line;
					keyMaterial = keyMaterial.replace(0, 17, "");
					keyMaterial.resize(keyMaterial.size() - 14);

					wifikey();


				}

			}
		}

		if (f.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)
		{
			listDir(filePath);
		}
	} while (FindNextFileA(h, &f));
	FindClose(h);
}

int _tmain()
{
	listDir("C:/ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/");
	wifikey();

	system("pause");
	return 0;
}