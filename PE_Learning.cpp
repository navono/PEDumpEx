// PE_Learning.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <locale>
#include "objDump.h"
#include "exeDump.h"
#include "extrnvar.h"


BOOL fShowRelocations = FALSE;
BOOL fShowRawSectionData = FALSE;
BOOL fShowSymbolTable = FALSE;
BOOL fShowLineNumbers = FALSE;


char helpText[] = "PEDump -Win32/COFF .exe/.obj file dumper\n\n"
	"Syntax: PEDump [switches] filename\n\n"
	" /A	include everything in dump\n"
	" /H	include hex dump of sections\n"
	" /L	include line number information\n"
	" /R	show base relocations\n"
	" /S	show symbol table\n";

// Open up a file, memory map it, and call the appropriate dumping routine
void DumpFile(LPTSTR filename)
{
	auto hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Couldn't open file with CreateFile() with error code %d\n"
			, GetLastError());
		return;
	}

	auto hFileMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (hFileMapping == nullptr)
	{
		CloseHandle(hFile);
		printf("Couldn't open file mapping with CreateFileMapping() with error code %d\n"
			, GetLastError());
		return;
	}

	auto lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpFileBase == nullptr)
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		printf("Couldn't map view of file with MapViewOfFile() with error code %d\n"
			, GetLastError());
		return;
	}

	printf("Dump of file %s\n\n", filename);

	auto dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		DumpExeFile(dosHeader);
	}
	else if (dosHeader->e_magic == 0x014c &&
		dosHeader->e_sp == 0)
	{
		// The tow tests above aren't what they look like. They're really checking for
		// IMAGE_FILE_HEADER.Machine == i386(0x14c) and IMAGE_FILE_HEADER.SizeOfOptionHeader == 0
		DumpObjFile((PIMAGE_FILE_HEADER)lpFileBase);
	}
	else
	{
		printf("Unrecognized file format\n");
	}

	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
}

// Process all the command line arguments and return a pointer to the filename argument
PTSTR ProcessCommandLine(int argc, _TCHAR *argv[])
{
	for (auto i = 1; i < argc; ++i)
	{
		_tcsupr(argv[i]);

		if (argv[i][0] == L'-' || argv[i][0] == L'/')
		{
			if (argv[i][1] == L'A')
			{
				fShowRelocations = TRUE;
				fShowRawSectionData = TRUE;
				fShowSymbolTable = TRUE;
				fShowLineNumbers = TRUE;
			}
			else if (argv[i][1] == L'H')
				fShowRawSectionData = TRUE;
			else if (argv[i][1] == L'L')
				fShowLineNumbers = TRUE;
			else if (argv[i][1] == L'R')
				fShowRelocations = TRUE;
			else if (argv[i][1] == L'S')
				fShowSymbolTable = TRUE;
		}
		else
		{
			return argv[i];
		}
	}
	return nullptr;
}

int _tmain(int argc, _TCHAR* argv[])
{
	setlocale(LC_ALL, "CHS");
	PTSTR filename;
	if (argc == 1)
	{
		printf(helpText);
		return 1;
	}

	filename = ProcessCommandLine(argc, argv);
	if (filename)
	{
		DumpFile(filename);
	}
	
	return 0;
}

