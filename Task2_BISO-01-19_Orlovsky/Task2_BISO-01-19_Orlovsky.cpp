// Task2_BISO-01-19_Orlovsky.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.

#include <iostream>
#include <Windows.h>
#include <stdio.h>
using namespace std;

int main(int args, char* argv[])
{
    HANDLE hFile;
    PVOID pBuffer = NULL;
    DWORD dwFileSize = 0;
    DWORD dwOffset = 0;
    PIMAGE_SECTION_HEADER sectionHeader = {};
    PIMAGE_SECTION_HEADER importSection = {};
    IMAGE_IMPORT_DESCRIPTOR* importDescriptor = {};
    PIMAGE_THUNK_DATA thunkData = {};
    DWORD thunk = NULL;
    DWORD rawOffset = NULL;

    hFile = CreateFile(L"Task2_BISO-01-19_Orlovsky.exe", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        dwFileSize = GetFileSize(hFile, 0);
        pBuffer = LocalAlloc(LPTR, dwFileSize);
        if (pBuffer)
        {
            DWORD dwBytesReads = 0;
            ReadFile(hFile, pBuffer, dwFileSize, &dwBytesReads, NULL);

        }
    }

    // IMAGE_DOS_HEADER
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuffer;
    printf("DOS HEADER\n");
    printf("\t%#08x\tMagic number\n", pDos->e_magic);                       //Сигнатура заголовка
    printf("\t%#08x\tFile adress of new exe header\n", pDos->e_lfanew);     //Адрес в файле нового .exe заголовка (PE)
    printf("\t%#08x\tFile address of relocation table\n\n", pDos->e_lfarlc);//Адрес в файле на таблицу переадресации

    // IMAGE_NT_HEADERS
    PIMAGE_NT_HEADERS32 pNT = (PIMAGE_NT_HEADERS32)((DWORD)pBuffer + pDos->e_lfanew);
    printf("NT HEADERS\n");
    printf("\t%#08x\tSignature\n\n", pNT->Signature);

    // FILE_HEADER
    printf("FILE HEADER\n");
    printf("\t%#08x\tMachine\n", pNT->FileHeader.Machine);
    printf("\t%#08x\tNumber Of Sections\n", pNT->FileHeader.NumberOfSections);
    printf("\t%#08x\tSize Of Optional Header\n", pNT->FileHeader.SizeOfOptionalHeader);
    printf("\t%#08x\tNumber Of Symbols\n", pNT->FileHeader.NumberOfSymbols);
    printf("\t%#08x\tCharacteristics\n", pNT->FileHeader.Characteristics);
    printf("\t%#08x\tTime Date Stamp\n\n", pNT->FileHeader.TimeDateStamp);

    // OPTIONAL_HEADER
    printf("OPTIONAL HEADER");
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> Magic: %#08x\n", pNT->OptionalHeader.Magic);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> MajorLinkerVersion: %#08x\n", pNT->OptionalHeader.MajorLinkerVersion);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> MinorLinkerVersion: %#08x\n", pNT->OptionalHeader.MinorLinkerVersion);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> SizeOfCode: %#08x\n", pNT->OptionalHeader.SizeOfCode);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> SizeOfInitializedData: %#08x\n", pNT->OptionalHeader.SizeOfInitializedData);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> SizeOfUninitializedData: %#08x\n", pNT->OptionalHeader.SizeOfUninitializedData);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> AddressOfEntryPoint: %#08x\n", pNT->OptionalHeader.AddressOfEntryPoint);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> BaseOfCode: %#08x\n", pNT->OptionalHeader.BaseOfCode);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> BaseOfData: %#08x\n", pNT->OptionalHeader.BaseOfData);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> ImageBase: %#08x\n", pNT->OptionalHeader.ImageBase);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> SectionAlignment: %#08x\n", pNT->OptionalHeader.SectionAlignment);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> FileAlignment: %#08x\n", pNT->OptionalHeader.FileAlignment);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> MajorOperatingSystemVersion: %#08x\n", pNT->OptionalHeader.MajorOperatingSystemVersion);
    printf("\t%#08x\tNT HEADER -> OptionalHeader -> MinorOperatingSystemVersion: %#08x\n", pNT->OptionalHeader.MinorOperatingSystemVersion);
    printf("\t%#08x\tSizeOfImage\n", pNT->OptionalHeader.SizeOfImage);
    printf("\t%#08x\tSizeOfHeaders\n", pNT->OptionalHeader.SizeOfHeaders);
    printf("\t%#08x\tCheckSum\n", pNT->OptionalHeader.CheckSum);
    printf("\t%#08x\tSubsystem\n", pNT->OptionalHeader.Subsystem);
    printf("\t%#08x\tDll Characteristics\n", pNT->OptionalHeader.DllCharacteristics);
    printf("\t%#08x\tData Directory\n\n", pNT->OptionalHeader.DataDirectory);

    // DATA_DIRECTORIES
    printf("NT HEADER -> OptionalHeader -> ExportDirectoryAddress: %#08x\n", pNT->OptionalHeader.DataDirectory[0].VirtualAddress, pNT->OptionalHeader.DataDirectory[0].Size);
    printf("NT HEADER -> OptionalHeader -> ImportDirectoryAddress: %#08x\n\n", pNT->OptionalHeader.DataDirectory[1].VirtualAddress, pNT->OptionalHeader.DataDirectory[1].Size);


    PIMAGE_SECTION_HEADER pSection;

    // SECTION_HEADERS
    // get offset to first section headeer
    DWORD sectionLocation = (DWORD)pNT + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)pNT->FileHeader.SizeOfOptionalHeader;
    DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

    DWORD importDirectoryRVA = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;




    for (size_t i = 0; i < pNT->FileHeader.NumberOfSections; i++)
    {
        pSection = (PIMAGE_SECTION_HEADER)sectionLocation;
        printf("Name: %s \n", pSection->Name);
        printf("Virtual Size (Not RAW): %#08x\t %d\n", pSection->Misc.VirtualSize,
            pSection->Misc.VirtualSize);
        printf("Virtual Adress: %#08x\n", pSection->VirtualAddress);
        printf("Size of Raw Data: %#08x\t\t %d\n", pSection->SizeOfRawData, 
            pSection->SizeOfRawData);
        printf("Pointer to RAW Data: %#08x\t %d\n", pSection->PointerToRawData,
            pSection->PointerToRawData);
        printf("Characteristics: %#08x\n\n", pSection->Characteristics);

        if (importDirectoryRVA >= pSection->VirtualAddress && importDirectoryRVA < pSection->VirtualAddress + pSection->Misc.VirtualSize) {
            importSection = pSection;
        }
        sectionLocation += sectionSize;

        pSection++;
    }

    rawOffset = (DWORD)pBuffer + importSection->PointerToRawData;

    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset + (pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));

    printf("DLL Imports\n");
    for (; importDescriptor->Name != 0; importDescriptor++) {
        // imported dll modules
        printf("\t%s\n", rawOffset + (importDescriptor->Name - importSection->VirtualAddress));
        thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
        thunkData = (PIMAGE_THUNK_DATA)(rawOffset + (thunk - importSection->VirtualAddress));

        // dll exported functions
        for (; thunkData->u1.AddressOfData != 0; thunkData++) {
            //a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯
            if (thunkData->u1.AddressOfData > 0x80000000) {
                //show lower bits of the value to get the ordinal ¯\_(ツ)_/¯
                printf("\t\tOrdinal: %x\n", (WORD)thunkData->u1.AddressOfData);
            }
            else {
                printf("\t\t%s\n", (rawOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
            }
        }
    }


    return 0;
}
