#include <stdio.h>
#include <windows.h>
#include <winternl.h>

PPEB getPeb()
{
#if _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
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

wchar_t* convertCharArrayToLPCWSTR(const char* charArray)
{
    wchar_t* wString = new wchar_t[4096];
    MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
    return wString;
}

int main()
{
    LPWSTR nameNtdll = convertCharArrayToLPCWSTR("ntdll.dll");
    HMODULE addressDll = getModuleHandleCustom(nameNtdll);
    //printf("Address : %x", addressDll);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)addressDll;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)addressDll + dosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER optionalHeader = &ntHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY dataDir = &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)addressDll + dataDir->VirtualAddress);

    PDWORD AddressOfFunctions = (PDWORD)((PBYTE) addressDll + exportDir->AddressOfFunctions);
    PDWORD AddressOfNames = (PDWORD)((PBYTE)addressDll + exportDir->AddressOfNames);
    PWORD AddressOfFunctionsOrdinals = (PWORD)((PBYTE)addressDll + exportDir->AddressOfNameOrdinals);

    for (int i = 0; i < exportDir->NumberOfFunctions; ++i)
    {
        PCSTR name = (PSTR)((PBYTE)addressDll + AddressOfNames[i]);

        WORD ordinalName = (WORD)((PBYTE)addressDll + AddressOfFunctions[i]);
        
        PVOID addr = (PVOID)((PBYTE)addressDll + AddressOfFunctions[ordinalName]);

        printf("%s : %p \n", name, addr);
    }
}