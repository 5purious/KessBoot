/*
 *  MIT License
 *
 *  Copyright (c) 2022 Ian Marco Moffett
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */


#include <efi.h>
#include <efilib.h>
#include <elf.h>
#include <stddef.h>

// KessServices

struct KessServices {
} services;


void Panic(CHAR16* Msg, EFI_SYSTEM_TABLE* SystemTable) {
    Print(L"** PANIC **\n");
    Print(Msg);
    Print(L"\nPress any key to shutdown the system.\n");

    EFI_INPUT_KEY Key;

    while (SystemTable->ConIn->ReadKeyStroke(SystemTable->ConIn, &Key) == EFI_NOT_READY);
    SystemTable->RuntimeServices->ResetSystem(EfiResetShutdown, 0, 0, NULL);
}


EFI_FILE* LoadFile(EFI_FILE* Directory, CHAR16* Path, EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable) {
    EFI_FILE* FileRes;

    // Fetch loaded image protocol.
    EFI_LOADED_IMAGE_PROTOCOL* LoadedImage;
    SystemTable->BootServices->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (void**)&LoadedImage);

    // Get filesystem protocol.
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* FS;
    SystemTable->BootServices->HandleProtocol(LoadedImage->DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, (void**)&FS);

    // Check if we want to open root of filesystem.
    if (Directory == NULL)
        FS->OpenVolume(FS, &Directory);

    EFI_STATUS Status = Directory->Open(Directory, &FileRes, Path, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);

    // Something funky happened.
    if (Status != EFI_SUCCESS)
        return NULL;

    return FileRes;
}


int MemCMP(const void* APtr, const void* BPtr, size_t n) {
    const unsigned char* a = APtr;
    const unsigned char* b = BPtr;

    for (size_t i = 0; i < n; ++i) {
        if (a[i] < b[i])
            return -1;
        else if (a[i] > b[i])
            return 1;
    }

    return 0;
}


// Boots up the system.
void Boot(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable) {
    // Load kernel.
    
    EFI_FILE* Kernel = LoadFile(NULL, L"kernel.elf", ImageHandle, SystemTable);

    if (Kernel == NULL) {
        Panic(L"Could not loaded the kernel!\n", SystemTable);
    }

    // Get file information.
    UINTN FileInfoSize;
    EFI_FILE_INFO* FileInfo;
    Elf64_Ehdr Header;
    Kernel->GetInfo(Kernel, &gEfiFileInfoGuid, &FileInfoSize, NULL);

    // Allocate memory for file information.
    SystemTable->BootServices->AllocatePool(EfiLoaderData, FileInfoSize, (void**)&FileInfo);

    // Get info.
    Kernel->GetInfo(Kernel, &gEfiFileInfoGuid, &FileInfoSize, (void**)&FileInfo);

    // Read file into memory.
    UINTN Size = sizeof(Header);
    Kernel->Read(Kernel, &Size, &Header);

    // Do some checks.
    if (MemCMP(&Header.e_ident[EI_MAG0], ELFMAG, SELFMAG) != 0 || 
            Header.e_ident[EI_CLASS] != ELFCLASS64 ||
            Header.e_ident[EI_DATA] != ELFDATA2LSB ||
            Header.e_type != ET_EXEC || 
            Header.e_machine != EM_X86_64 || 
            Header.e_version != EV_CURRENT)

        Panic(L"Kernel header bad!", SystemTable);

    // Get program headers.
    Elf64_Phdr* Phdrs;
    Kernel->SetPosition(Kernel, Header.e_phoff);
    Size = Header.e_phnum * Header.e_phentsize;

    // Allocate memory for program headers.
    SystemTable->BootServices->AllocatePool(EfiLoaderData, Size, (void**)&Phdrs);

    // Read program headers into memory.
    Kernel->Read(Kernel, &Size, Phdrs);
    
    for (Elf64_Phdr* Phdr = Phdrs; (char*)Phdr < (char*)Phdrs + Header.e_phnum * Header.e_phentsize; Phdr = (Elf64_Phdr*)((char*)Phdr + Header.e_phentsize)) {
        // Check if type is PT_LOAD.
        if (Phdr->p_type == PT_LOAD) {
            int pages = (Phdr->p_memsz + 0x1000 - 1) / 0x1000;
            Elf64_Addr Segment = Phdr->p_paddr;

            SystemTable->BootServices->AllocatePages(AllocateAddress, EfiLoaderData, pages, &Segment);
            Kernel->SetPosition(Kernel, Phdr->p_offset);

            UINTN Size = Phdr->p_filesz;
            Kernel->Read(Kernel, &Size, (void*)Segment);
            break;
        }
    }

    // MEMORY MAP TIME!!!
    EFI_MEMORY_DESCRIPTOR* Map = NULL;
    UINTN MapSize, MapKey;
    UINTN DescriptorSize;
    UINT32 DescriptorVersion;

    SystemTable->BootServices->GetMemoryMap(&MapSize, Map, &MapKey, &DescriptorSize, &DescriptorVersion);

    // Allocate memory for mmap.
    SystemTable->BootServices->AllocatePool(EfiLoaderData, MapSize, (void**)&Map);
    
    // Fetch map.
    EFI_STATUS Status = SystemTable->BootServices->GetMemoryMap(&MapSize, Map, &MapKey, &DescriptorSize, &DescriptorVersion);

    if (Status != EFI_SUCCESS) {
        Print(L"[!] Status: %d\n", Status);
        Panic(L"GetMemoryMap() returned a non-zero value.", SystemTable);
    } 

    // Reset ConOut (clears screen).
    SystemTable->ConOut->Reset(SystemTable->ConOut, 1);

    // ExitBootServices.
    SystemTable->BootServices->ExitBootServices(ImageHandle, MapKey);
    SystemTable->BootServices->ExitBootServices(ImageHandle, MapKey);

    void(*KernelEntry)(void) = ((__attribute__((sysv_abi)) void(*)())Header.e_entry);
    KernelEntry();

}


EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable) {
    InitializeLib(ImageHandle, SystemTable); 

    // Disable watchdog timer.
    SystemTable->BootServices->SetWatchdogTimer(0, 0xFFFFFFFF, 0, NULL);

    Boot(ImageHandle, SystemTable);

    return EFI_SUCCESS;
}
