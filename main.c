#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winnt.h>

// Function declarations
__declspec(dllexport) void* load_PE(char* PE_data);
__declspec(dllexport) void run_PE_from_file(const char* file_path);

// Entry point for the DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// Function to load a PE from a file and execute its entry point
__declspec(dllexport) void run_PE_from_file(const char* file_path) {
    FILE* exe_file = fopen(file_path, "rb");
    if (!exe_file) {
        printf("Error opening file\n");
        return;
    }

    // Get file size: put pointer at the end
    fseek(exe_file, 0L, SEEK_END);
    long int file_size = ftell(exe_file);
    fseek(exe_file, 0L, SEEK_SET);

    // Allocate memory and read the whole file
    char* exe_file_data = malloc(file_size + 1);
    if (!exe_file_data) {
        printf("Memory allocation error\n");
        fclose(exe_file);
        return;
    }

    // Read whole file
    size_t n_read = fread(exe_file_data, 1, file_size, exe_file);
    if (n_read != file_size) {
        printf("Reading error (%zu)\n", n_read);
        free(exe_file_data);
        fclose(exe_file);
        return;
    }

    fclose(exe_file);

    // Load the PE in memory
    printf("[+] Loading PE file\n");
    void* start_address = load_PE(exe_file_data);
    free(exe_file_data);

    if (start_address) {
        // Call its entry point
        ((void (*)(void)) start_address)();
    }
}

void* load_PE(char* PE_data) {
    IMAGE_DOS_HEADER* p_DOS_HDR = (IMAGE_DOS_HEADER*)PE_data;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*)(((char*)p_DOS_HDR) + p_DOS_HDR->e_lfanew);

    DWORD hdr_image_base = p_NT_HDR->OptionalHeader.ImageBase;
    DWORD size_of_image = p_NT_HDR->OptionalHeader.SizeOfImage;
    DWORD entry_point_RVA = p_NT_HDR->OptionalHeader.AddressOfEntryPoint;
    DWORD size_of_headers = p_NT_HDR->OptionalHeader.SizeOfHeaders;

    char* ImageBase = (char*)VirtualAlloc(NULL, size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (ImageBase == NULL) {
        return NULL;
    }

    memcpy(ImageBase, PE_data, p_NT_HDR->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(p_NT_HDR + 1);

    for (int i = 0; i < p_NT_HDR->FileHeader.NumberOfSections; ++i) {
        char* dest = ImageBase + sections[i].VirtualAddress;

        if (sections[i].SizeOfRawData > 0) {
            memcpy(dest, PE_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        }
        else {
            memset(dest, 0, sections[i].Misc.VirtualSize);
        }
    }

    IMAGE_DATA_DIRECTORY* data_directory = p_NT_HDR->OptionalHeader.DataDirectory;

    IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*)(ImageBase + data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (int i = 0; import_descriptors[i].OriginalFirstThunk != 0; ++i) {
        char* module_name = ImageBase + import_descriptors[i].Name;
        HMODULE import_module = LoadLibraryA(module_name);
        if (import_module == NULL) {
            return NULL;
        }

        IMAGE_THUNK_DATA* lookup_table = (IMAGE_THUNK_DATA*)(ImageBase + import_descriptors[i].OriginalFirstThunk);
        IMAGE_THUNK_DATA* address_table = (IMAGE_THUNK_DATA*)(ImageBase + import_descriptors[i].FirstThunk);

        for (int i = 0; lookup_table[i].u1.AddressOfData != 0; ++i) {
            void* function_handle = NULL;
            DWORD lookup_addr = lookup_table[i].u1.AddressOfData;

            if ((lookup_addr & IMAGE_ORDINAL_FLAG) == 0) {
                IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*)(ImageBase + lookup_addr);
                char* funct_name = (char*)&(image_import->Name);
                function_handle = (void*)GetProcAddress(import_module, funct_name);
            }
            else {
                function_handle = (void*)GetProcAddress(import_module, (LPSTR)lookup_addr);
            }

            if (function_handle == NULL) {
                return NULL;
            }

            address_table[i].u1.Function = (DWORD)function_handle;
        }
    }

    DWORD delta_VA_reloc = ((DWORD)ImageBase) - p_NT_HDR->OptionalHeader.ImageBase;

    if (data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 && delta_VA_reloc != 0) {
        IMAGE_BASE_RELOCATION* p_reloc = (IMAGE_BASE_RELOCATION*)(ImageBase + data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (p_reloc->VirtualAddress != 0) {
            DWORD size = (p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            WORD* reloc = (WORD*)(p_reloc + 1);
            for (int i = 0; i < size; ++i) {
                int type = reloc[i] >> 12;
                int offset = reloc[i] & 0x0fff;
                DWORD* change_addr = (DWORD*)(ImageBase + p_reloc->VirtualAddress + offset);

                switch (type) {
                case IMAGE_REL_BASED_HIGHLOW:
                    *change_addr += delta_VA_reloc;
                    break;
                default:
                    break;
                }
            }
            p_reloc = (IMAGE_BASE_RELOCATION*)(((DWORD)p_reloc) + p_reloc->SizeOfBlock);
        }
    }

    DWORD oldProtect;
    VirtualProtect(ImageBase, p_NT_HDR->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect);

    for (int i = 0; i < p_NT_HDR->FileHeader.NumberOfSections; ++i) {
        char* dest = ImageBase + sections[i].VirtualAddress;
        DWORD s_perm = sections[i].Characteristics;
        DWORD v_perm = 0;

        if (s_perm & IMAGE_SCN_MEM_EXECUTE) {
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        }
        else {
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }
        VirtualProtect(dest, sections[i].Misc.VirtualSize, v_perm, &oldProtect);
    }

    return (void*)(ImageBase + entry_point_RVA);
}
