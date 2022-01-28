#pragma once
#pragma once
#include "pch.h"
#include <cstdio>
#include <cstdlib>

FARPROC farprocWriteFile;
#if defined(_WIN64)
char WriteFileOriginBytes[12];
#elif defined(_WIN32)
char WriteFileOriginBytes[6];
#endif
SIZE_T bytesWritten;
HANDLE hOutFile;


BOOL WINAPI HookedWriteFile(
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);

VOID WINAPI HookWriteFile();

BOOL WINAPI HookedWriteFile(
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
)
{
	printf("You called WriteFile.\n");
	// unhook
	WriteProcessMemory(GetCurrentProcess(), farprocWriteFile, WriteFileOriginBytes, sizeof(WriteFileOriginBytes), &bytesWritten);
	for (DWORD i = 0; i < nNumberOfBytesToWrite; i++)
		printf("0x%02x, ", reinterpret_cast<const char*>(lpBuffer)[i]);
	// call real WriteFile
	BOOL result = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	hOutFile = CreateFileA(
		"./output.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
	);
	if (hOutFile != NULL && hOutFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwBytesWritten = 0;
		WriteFile(hOutFile, lpBuffer, nNumberOfBytesToWrite, &dwBytesWritten, NULL);
		CloseHandle(hOutFile);
	}
	// rehook
	HookWriteFile();
	return result;
}

VOID WINAPI HookWriteFile()
{
	SIZE_T bytesRead = 0;
	farprocWriteFile = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");
	if (farprocWriteFile == NULL)
	{
		printf("Cannot find WriteFile\n");
		return;
	}
	ReadProcessMemory(GetCurrentProcess(), farprocWriteFile, WriteFileOriginBytes, sizeof(WriteFileOriginBytes), &bytesRead);
	if (bytesRead == 0)
	{
		printf("Cannot read WriteFile\n");
		return;
	}
#if defined(_WIN64)
	char patch[12] = { 0 };
	LPVOID hookedWriteFile = &HookedWriteFile;
	LPVOID pHookedWriteFile = &hookedWriteFile;
	CopyMemory(patch, "\x48\xB8", 2);
	CopyMemory(patch + 2, &hookedWriteFile, 8);
	CopyMemory(patch + 10, "\xFF\xE0", 2);
#elif defined(_WIN32)
	char patch[6] = { 0 };
	LPVOID hookedWriteFile = &HookedWriteFile;
	CopyMemory(patch, "\x68", 1);
	CopyMemory(patch + 1, &hookedWriteFile, 4);
	CopyMemory(patch + 5, "\xC3", 1);
#endif
	WriteProcessMemory(GetCurrentProcess(), farprocWriteFile, patch, sizeof(patch), &bytesWritten);
	if (bytesWritten == 0)
	{
		printf("Cannot hook WriteFile\n");
		return;
	}
}