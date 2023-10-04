#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <fstream>
#include <iostream>
#include <ctype.h>
#include "getPEB.h"

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
    //printf("Address : %x", addressDll);

    //LPWSTR nametest = convertCharArrayToLPCWSTR("test");
    PVOID functionAddress = getProcAddressCustom(NtDllAddress, NtAllocateVirtualMemory_HASH);
    printf("address : %x", functionAddress);
    //printf("%x", DJB2hash(nametest));
}