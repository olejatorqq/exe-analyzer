﻿// Task2_BISO-01-19_Orlovsky.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.

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
    printf("OPTIONAL HEADER\n");
    printf("\t%#08x\tMagic\n", pNT->OptionalHeader.Magic);
    printf("\t%#08x\tMajor Linker Version\n", pNT->OptionalHeader.MajorLinkerVersion);
    printf("\t%#08x\tMinor Linker Version\n", pNT->OptionalHeader.MinorLinkerVersion);
    printf("\t%#08x\tSize Of Code\n", pNT->OptionalHeader.SizeOfCode);
    printf("\t%#08x\tSize Of Initialized Data\n", pNT->OptionalHeader.SizeOfInitializedData);
    printf("\t%#08x\tSize Of Uninitialized Data\n", pNT->OptionalHeader.SizeOfUninitializedData);
    printf("\t%#08x\tAddress Of Entry Point\n", pNT->OptionalHeader.AddressOfEntryPoint);
    printf("\t%#08x\tBase Of Code\n", pNT->OptionalHeader.BaseOfCode);
    printf("\t%#08x\tBase Of Data\n", pNT->OptionalHeader.BaseOfData);
    printf("\t%#08x\tImage Base\n", pNT->OptionalHeader.ImageBase);
    printf("\t%#08x\tSection Alignment\n", pNT->OptionalHeader.SectionAlignment);
    printf("\t%#08x\tFile Alignment\n", pNT->OptionalHeader.FileAlignment);
    printf("\t%#08x\tMajor Operating System Version\n", pNT->OptionalHeader.MajorOperatingSystemVersion);
    printf("\t%#08x\tMinor Operating System Version\n", pNT->OptionalHeader.MinorOperatingSystemVersion);
    printf("\t%#08x\tSize Of Image\n", pNT->OptionalHeader.SizeOfImage);
    printf("\t%#08x\tSize Of Headers\n", pNT->OptionalHeader.SizeOfHeaders);
    printf("\t%#08x\tCheck Sum\n", pNT->OptionalHeader.CheckSum);
    printf("\t%#08x\tSubsystem\n", pNT->OptionalHeader.Subsystem);
    printf("\t%#08x\tDll Characteristics\n", pNT->OptionalHeader.DllCharacteristics);
    printf("\t%#08x\tData Directory\n\n", pNT->OptionalHeader.DataDirectory);

    // DATA DIRECTORIES
    printf("DATA DIRECTORIES\n");
    printf("\t%#08x\tExport Directory Address\n", pNT->OptionalHeader.DataDirectory[0].VirtualAddress, pNT->OptionalHeader.DataDirectory[0].Size);
    printf("\t%#08x\tImport Directory Address\n\n", pNT->OptionalHeader.DataDirectory[1].VirtualAddress, pNT->OptionalHeader.DataDirectory[1].Size);


    PIMAGE_SECTION_HEADER pSection;

    // SECTION_HEADERS
    printf("SECTION HEADER\n");

    // Получение смещения к первой секции заголовка
    DWORD sectionLocation = (DWORD)pNT + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)pNT->FileHeader.SizeOfOptionalHeader;
    DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

    // Получение смещения RVA
    DWORD importDirectoryRVA = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;


    for (size_t i = 0; i < pNT->FileHeader.NumberOfSections; i++)
    {
        pSection = (PIMAGE_SECTION_HEADER)sectionLocation;
        printf("\t%s\n", pSection->Name);
        printf("\t%#08x %d\tVirtual Size (Not RAW)\n", pSection->Misc.VirtualSize,
            pSection->Misc.VirtualSize);
        printf("\t%#08x\tVirtual Adress\n", pSection->VirtualAddress);
        printf("\t%#08x %d\tSize of Raw Data\n", pSection->SizeOfRawData, 
            pSection->SizeOfRawData);
        printf("\t%#08x %d\tPointer to RAW Data\n", pSection->PointerToRawData,
            pSection->PointerToRawData);
        printf("\t%#08x\tCharacteristics\n\n", pSection->Characteristics);

        // Сохранение раздела, содержащего таблицу каталога импорта
        if (importDirectoryRVA >= pSection->VirtualAddress && importDirectoryRVA < pSection->VirtualAddress + pSection->Misc.VirtualSize) {
            importSection = pSection;
        }
        sectionLocation += sectionSize;

    }

    // Получение смещения файла для таблицы импорта
    rawOffset = (DWORD)pBuffer + importSection->PointerToRawData;

    // Получение указателя на смещение файла дескриптора импорта
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset + (pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));

    // DLL_IMPORTS
    printf("DLL IMPORTS\n");
    for (; importDescriptor->Name != 0; importDescriptor++) {
        // Импортирование DLL модулей
        printf("\t%s\n", rawOffset + (importDescriptor->Name - importSection->VirtualAddress));
        thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
        thunkData = (PIMAGE_THUNK_DATA)(rawOffset + (thunk - importSection->VirtualAddress));

        // Функции dll
        for (; thunkData->u1.AddressOfData != 0; thunkData++) {
            // Проверка импорта функции через ее порядковый номер
            if (thunkData->u1.AddressOfData > 0x80000000) {
                // Младшие биты для получение порядкового номера
                printf("\t\tOrdinal: %x\n", (WORD)thunkData->u1.AddressOfData);
            }
            else {
                printf("\t\t%s\n", (rawOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
            }
        }
        printf("\n");
    }


    return 0;
}
