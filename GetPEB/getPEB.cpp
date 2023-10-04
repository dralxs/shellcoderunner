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

HMODULE newGetModuleHandle(LPWSTR name)
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
    LPWSTR nameKernel32 = convertCharArrayToLPCWSTR("KERNEL32.DLL");
    HMODULE addressDll = newGetModuleHandle(nameKernel32);

    printf("Address : %x", addressDll);
}