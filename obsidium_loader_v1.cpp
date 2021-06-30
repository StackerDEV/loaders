#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <TlHelp32.h>
#include "memory.h"
#include <iostream>
#include <string>
#include <vector>
#include <stdlib.h>
#include <stdio.h>
#include "bass.h"

DWORD music;
OPENFILENAME ofn;

#pragma comment(lib, "psapi.lib")
//#define ADDRESS (LPVOID)0x6151FA
unsigned char buffer[1024] = { 0 };
SIZE_T nSize;
PROCESS_INFORMATION procInfo = { 0 };

typedef LONG(NTAPI *NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG(NTAPI *NtResumeProcess)(IN HANDLE ProcessHandle);

char* getAddressOfData(DWORD pid, const char *data, size_t len)
{
	HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (process)
	{
		SYSTEM_INFO si;
		GetSystemInfo(&si);

		MEMORY_BASIC_INFORMATION info;
		std::vector<char> chunk;
		char* p = 0;
		while (p < si.lpMaximumApplicationAddress)
		{
			if (VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info))
			{
				p = (char*)info.BaseAddress;
				chunk.resize(info.RegionSize);
				SIZE_T bytesRead;
				if (ReadProcessMemory(process, p, &chunk[0], info.RegionSize, &bytesRead))
				{
					for (size_t i = 0; i < (bytesRead - len); ++i)
					{
						if (memcmp(data, &chunk[i], len) == 0)
						{
							return (char*)p + i;
						}
					}
				}
				p += info.RegionSize;
			}
		}
	}
	return 0;
}

static void suspendThreads(DWORD pid, int on)
{
	NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(GetModuleHandle(L"ntdll"), "NtSuspendProcess");
	NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(GetModuleHandle(L"ntdll"), "NtResumeProcess");

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (on)
	{
		pfnNtResumeProcess(processHandle);
	}
	else
	{
		pfnNtSuspendProcess(processHandle);
	}
	CloseHandle(processHandle);
}

void suspend(DWORD processId, INT State)
{
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);
	Thread32First(hThreadSnapshot, &threadEntry);

	do
	{
		if (threadEntry.th32OwnerProcessID == processId)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
				threadEntry.th32ThreadID);

			if (State == 1) {
				SuspendThread(hThread);
			}
			else {
				ResumeThread(hThread);
			}
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnapshot, &threadEntry));

	CloseHandle(hThreadSnapshot);
}

void patchTarget()
{
	//suspend(procInfo.dwProcessId, 1); // TOO SLOW, NTDLL NEEDED
	suspendThreads(procInfo.dwProcessId, false);
	printf("[+] Obsidium seems unpacked in VAS.\n");
	printf("[+] Suspending all threads..\n");
	printf("[+] Attempting to patch this shit fuck\n");

	char pattern0[] = { 0x54, 0x01, 0x68, 0x8C, 0x75, 0x53, 0x01, 0xB9, 0x08, 0x26, 0xBF, 0x01, 0xE8, 0x46, 0x2E, 0x04, 0x00, 0x85, 0xC0, 0x74, 0x12 }; //org
	char patch0[] = { 0x54, 0x01, 0x68, 0x8C, 0x75, 0x53, 0x01, 0xB9, 0x08, 0x26, 0xBF, 0x01, 0xE8, 0x46, 0x2E, 0x04, 0x00, 0x85, 0xC0, 0xEB, 0x12 }; //mod
	char* fAdr0 = getAddressOfData(procInfo.dwProcessId, pattern0, sizeof(pattern0));
	if (fAdr0)
	{
		printf("[+] Pattern 0 found.. \n");
		nSize = 22;
		WriteProcessMemory(procInfo.hProcess, fAdr0, patch0, 21, &nSize);
	}
	else
	{
		printf("[-] Error pattern 0  not found! \n");
	}

	char pattern1[] = { 0x75, 0x40, 0x6A, 0x2B, 0xE8, 0xC0, 0x5D, 0x2F, 0x00, 0x8B, 0xD8, 0x83 }; //org
	char patch1[] = { 0x90, 0x90, 0x6A, 0x2B, 0xE8, 0xC0, 0x5D, 0x2F, 0x00, 0x8B, 0xD8, 0x83 };	 //mod
	char* fAdr1 = getAddressOfData(procInfo.dwProcessId, pattern1, sizeof(pattern1));
	if (fAdr1)
	{
		printf("[+] Pattern 1 found.. \n");
		nSize = 12;
		WriteProcessMemory(procInfo.hProcess, fAdr1, patch1, 12, &nSize);
	}
	else
	{
		printf("[-] Error pattern 1  not found! \n");
	}

	char pattern2[] = { 0x0F, 0x84, 0xA4, 0x00, 0x00, 0x00, 0x6A, 0x2B, 0x6A, 0x00, 0x53, 0xE8 }; //org
	char patch2[] = { 0xE9, 0xA5, 0x00, 0x00, 0x00, 0x90, 0x6A, 0x2B, 0x6A, 0x00, 0x53, 0xE8 }; //mod
	char* fAdr2 = getAddressOfData(procInfo.dwProcessId, pattern2, sizeof(pattern2));
	if (fAdr2)
	{
		printf("[+] Pattern 2 found.. \n");
		nSize = 12;
		WriteProcessMemory(procInfo.hProcess, fAdr2, patch2, 12, &nSize);
	}
	else
	{
		printf("[-] Error pattern 2  not found! \n");
	}

	suspend_threads(procInfo.dwProcessId, true);	
	printf("[+] Resuming all threads..\n");
	printf("[+] Success!\n");
	system("pause");
}

void printModules(DWORD processID)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (NULL == hProcess)
		return;

	// enum all modules in proc
	while (1)
	{
		if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
		{
			for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				wchar_t szModName[MAX_PATH];
				if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
					sizeof(szModName) / sizeof(TCHAR)))
				{
					if (_wcsicmp(L"C:\\Windows\\System32\\riched20.dll", szModName) == 0)
					{
						patchTarget();
					}
				}
			}
		}
	}
	CloseHandle(hProcess);
	return;
}

int main(int argc, char* argv[])
{
	SetConsoleTitle(L".:: Try before you buy ! ::.");
	system("Color 4");
	printf("x loader\n\n\n");
	DWORD aProcesses[1024];
	DWORD cbNeeded;
	DWORD cProcesses;
	int cP = 0;

	DWORD chan, act, time, level;
	BOOL ismod;
	QWORD pos;
	int a, device = -1;

	if (!BASS_Init(device, 44100, 0, 0, NULL))
		printf("Can't initialize device");

	if (HIWORD(BASS_GetVersion()) != BASSVERSION) {
		printf("An incorrect version of BASS was loaded");
		return 0;
	}
	chan = BASS_MusicLoad(FALSE, "xf.xm", 0, 0, BASS_MUSIC_RAMPS | BASS_MUSIC_POSRESET | BASS_MUSIC_PRESCAN, 1);

	if (argc != 2) {
		BASS_ChannelPlay(chan, FALSE);
	}
		
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		return 1;

	cProcesses = cbNeeded / sizeof(DWORD);
	STARTUPINFO startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	cP = CreateProcess(L"x.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &procInfo);
    cP = 1 ? printf("[+] Process created.\n") : printf("[-] Failed to start the process. Make sure the loader is in the same folder as \"x.exe\"\n");
	printf("[+] Obsidium -> Waiting for target to unpack.\n");
	printModules(procInfo.dwProcessId);
	system("pause");
	BASS_Free();
	return 0;
}