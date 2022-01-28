// dll_injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#pragma warning(disable:4996)
#include <iostream>
#include <string>
#include <Windows.h>

#define DEC_HEX(x) std::dec << (x) << "(0x" << std::hex << (x) << ")"

VOID PrintError(const std::string& log);

BOOL CRTInject(DWORD dwPID, const std::string& strDllPath, BOOL wait);

BOOL SetPrivilege(LPCSTR privname, BOOL enable);

int main()
{
	DWORD dwPID = 0;
	std::string strDllPath;
	BOOL result;

	SetPrivilege("SeDebugPrivilege", TRUE);
	// choose taget
	std::cout << "Input target PID: ";
	std::cin >> dwPID;
	// input dll path
	std::cout << "Dll Path: ";
	std::cin >> strDllPath;
	std::cout << "[+] Inject " << strDllPath << " into process " << DEC_HEX(dwPID) << std::endl;
	result = CRTInject(dwPID, strDllPath, TRUE);
	if (result == FALSE)
	{
		std::cout << "CRT failed." << std::endl;
	}
	return 0;
}

VOID PrintError(const std::string& log)
{
	DWORD dwErrCode = GetLastError();
	std::cout << "Error Code: " << DEC_HEX(dwErrCode) << log << std::endl;
}

BOOL CRTInject(DWORD dwPID, const std::string& strDllPath, BOOL wait)
{
	HANDLE hTarget = NULL;
	HANDLE hThread = NULL;
	LPVOID lpvLoadLibraryA = NULL;
	LPVOID lpvBaseAddr = NULL;
	SIZE_T bytesWritten = 0;
	BOOL result;
	DWORD dwTID = 0;
	const char* cstrDllPath = strDllPath.c_str();

	// open process by pid
	hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (hTarget == NULL || hTarget == INVALID_HANDLE_VALUE)
	{
		PrintError("Cannot open target");
		return FALSE;
	}
	// get proc address of LoadLibraryA
	lpvLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (lpvLoadLibraryA == NULL)
	{
		PrintError("Cannot get address of LoadLibraryA");
		return FALSE;
	}
	// write dll path into target process memory
	lpvBaseAddr = VirtualAllocEx(
		hTarget, NULL, strDllPath.size() + 10, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
	);
	if (lpvBaseAddr == NULL)
	{
		PrintError("Cannot alloc memory");
		return FALSE;
	}
	result = WriteProcessMemory(
		hTarget, lpvBaseAddr, cstrDllPath, strDllPath.size(), &bytesWritten
	);
	if (result == FALSE || bytesWritten == 0)
	{
		PrintError("Cannot write dll path");
		return FALSE;
	}
	hThread = CreateRemoteThread(
		hTarget, NULL, 0, (LPTHREAD_START_ROUTINE)lpvLoadLibraryA, lpvBaseAddr, 0, &dwTID
	);
	if (hThread == NULL || hThread == INVALID_HANDLE_VALUE)
	{
		PrintError("Cannot create remote thread");
		return FALSE;
	}
	std::cout << "[+] Thread ID: " << DEC_HEX(dwTID) << std::endl;
	if (wait)
	{
		WaitForSingleObject(hThread, INFINITE);
		WaitForSingleObject(hTarget, INFINITE);
	}
	CloseHandle(hThread);
	return TRUE;
}

BOOL SetPrivilege(LPCSTR privname, BOOL enable)
{
	LUID luid;
	HANDLE hToken;
	TOKEN_PRIVILEGES token_privs;
	BOOL result;

	if (!LookupPrivilegeValueA(NULL, privname, &luid))
	{
		return FALSE;
	}
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
	{
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
			return FALSE;
	}
	token_privs.PrivilegeCount = 1;
	token_privs.Privileges[0].Luid = luid;
	token_privs.Privileges[0].Attributes = (enable ? SE_PRIVILEGE_ENABLED : 0);
	result = AdjustTokenPrivileges(hToken, FALSE, &token_privs, 0, NULL, NULL);
	CloseHandle(hToken);
	return result;
}