//--------------------
// PROGRAM: PEDUMP
// FILE:    EXEDUMP.C
// AUTHOR:  Matt Pietrek - 1993
//--------------------

// msdn.microsoft.com/en-us/magazine/ms809762.aspx

#include <windows.h>
#include <stdio.h>
#include "common.h"
#include "extrnvar.h"

typedef PIMAGE_COFF_SYMBOLS_HEADER PIMAGE_DEBUG_INFO;

PIMAGE_DEBUG_INFO PCOFFDebugInfo = 0;

char *SzDebugFormats[] = {
"UNKNOWN/BORLAND","COFF","CODEVIEW","FPO","MISC","EXCEPTION","FIXUP" };

#define NB10_SIG	'01BN'
#define RSDS_SIG	'SDSR'
typedef struct CV_HEADER
{
	DWORD Signature;		// CodeView signature, equal to 'NB10'
	DWORD Offset;			// CodeView offset. Set to 0, because debug information is stored in a separate file
} CV_HEADER, *PCV_HEADER;

typedef struct CV_INFO_PDB20
{
	CV_HEADER CvHeader;		
	DWORD Signature;		// The time when debug information was created(in seconds since 1970.01.01)
	DWORD Age;				// Ever-incrementing value, which is initially set to 1 and incremented every time when
							// a part of the PDB file is updated without rewriting the whole file
	BYTE PdbFilename[];		// Null-terminated name of the PDB file. It can also contain full or partial path to the file
}CV_INFO_PDB20, *PCV_INFO_PDB20;

typedef struct CV_INFO_PDB70
{
	DWORD CvSignature;		// CodeView signature, equal to 'RSDS'
	GUID Signature;			// A unique identifier, which changes with every rebuild of the executable and PDB file
	DWORD Age;
	BYTE PdbFilename[];
}CV_INFO_PDB70, *PCV_INFO_PDB70;


//
// Dump the debug directory in a PE file.
//
void DumpDebugDirectory(DWORD base, PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_DEBUG_DIRECTORY debugDir;
	PIMAGE_SECTION_HEADER sectionHeader;
	unsigned cDebugFormats, i;
	DWORD offsetInto_rdata;
	DWORD va_debug_dir;
	PSTR szDebugFormat;

	// This line was so long that we had to break it up
	va_debug_dir = pNTHeader->OptionalHeader.
						DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].
						VirtualAddress;
	if ( va_debug_dir == 0 )
		return;

	// If we found a .debug section, and the debug directory is at the
	// beginning of this section, it looks like a Borland file
	sectionHeader = GetSectionHeader(".debug", pNTHeader);
	if ( sectionHeader && (sectionHeader->VirtualAddress == va_debug_dir) )
	{
		debugDir = (PIMAGE_DEBUG_DIRECTORY)(sectionHeader->PointerToRawData+base);
		cDebugFormats = pNTHeader->OptionalHeader.
							DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	}
	else	// Look for microsoft debug directory in the .rdata section
	{
		sectionHeader = GetSectionHeader(".rdata", pNTHeader);
		if ( !sectionHeader )
			return;

		// See if there's even any debug directories to speak of...
		cDebugFormats = pNTHeader->OptionalHeader.
							DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size
						/ sizeof(IMAGE_DEBUG_DIRECTORY);
		if ( cDebugFormats == 0 )
			return;
		offsetInto_rdata = va_debug_dir - sectionHeader->VirtualAddress;
		debugDir = MakePtr(PIMAGE_DEBUG_DIRECTORY, base,
							sectionHeader->PointerToRawData + offsetInto_rdata);
	}

	// www.debuginfo.com/articles/debuginfomatch.html
	// blog.csdn.net/liwen930723/articles/details/52662089

	if (!debugDir->AddressOfRawData || debugDir->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
	{
		return;
	}

	// PIMAGE_SECTION_HEADER.VirtualAddress和PIMAGE_SECTION_HEADER.PointerToRawData都指的是节的起始地址，不同之处在于：
	// VirtualAddress用在内存中指明该节的起始地址，而PointerToRawData用于在（PE）文件中指明该节的起始地址
	// 由于文件的对齐值和内存的对齐值不一样，所以，如果直接用RVA去定位的话，可能是错误的。
	// 原因是使用程序去加载PE文件，那么在PE文件中的地址就是使用文件偏移地址。而不是RVA。
	// 所以要做下面的RVA到文件偏移地址的转换

	//auto delta = (INT)(sectionHeader->VirtualAddress - sectionHeader->PointerToRawData);
	//CV_HEADER *CvInfo = MakePtr(PCV_HEADER, base, debugDir->AddressOfRawData - delta);

	auto delta2 = (INT)(debugDir->AddressOfRawData - sectionHeader->VirtualAddress);
	CV_HEADER *CvInfo = MakePtr(PCV_HEADER, base, sectionHeader->PointerToRawData + delta2);

	// CvInfo地址就是文件偏移地址：

	auto fileOffset = (PCV_HEADER)(base + sectionHeader->PointerToRawData + (debugDir->AddressOfRawData - sectionHeader->VirtualAddress));
	auto memOffset = sectionHeader->VirtualAddress + debugDir->PointerToRawData - sectionHeader->PointerToRawData;

	// bbs.pediy.com/showthread.php?t=109449
	// 内存偏移 - 该段起始的RVA = 文件偏移 - 该段的PointerToRawData
	// 因此：
	// 内存偏移 = 该段起始的RVA + (文件偏移 - 该段的PointerToRawData)
	// 文件偏移 = 该段的PointerToRawData + (内存偏移 - 该段起始的RVA)

	auto s1 = (debugDir->AddressOfRawData - sectionHeader->VirtualAddress) == (debugDir->PointerToRawData - sectionHeader->PointerToRawData);

	if (CvInfo->Signature == NB10_SIG)	// VC 6.0
	{
		auto pdb20 = (PCV_INFO_PDB20)CvInfo;

		auto nameSize = strlen((char*)(pdb20->PdbFilename));
		char *pName = new char[nameSize + 1];
		ZeroMemory(pName, nameSize + 1);

		memcpy(pName, pdb20->PdbFilename, nameSize);
		pName[nameSize+1] = '\0';
	}
	else if (CvInfo->Signature == RSDS_SIG)	// VS2003+
	{
		auto pdb70 = (PCV_INFO_PDB70)CvInfo;

		auto nameSize = strlen((char*)(pdb70->PdbFilename));
		char *pName = new char[nameSize + 1];
		ZeroMemory(pName, nameSize + 1);
		
		memcpy(pName, pdb70->PdbFilename, nameSize);
		pName[nameSize+1] = '\0';
		auto s = 10;
	}
    	
	printf(
	"Debug Formats in File\n"
    "  Type            Size     Address  FilePtr  Charactr TimeData Version\n"
    "  --------------- -------- -------- -------- -------- -------- --------\n"
	);
	
	for ( i=0; i < cDebugFormats; i++ )
	{
		szDebugFormat = (debugDir->Type <= 6)
						? SzDebugFormats[debugDir->Type] : "???";

		printf("  %-15s %08X %08X %08X %08X %08X %u.%02u\n",
			szDebugFormat, debugDir->SizeOfData, debugDir->AddressOfRawData,
			debugDir->PointerToRawData, debugDir->Characteristics,
			debugDir->TimeDateStamp, debugDir->MajorVersion,
			debugDir->MinorVersion);

		// If COFF debug info, save its address away for later.  We
		// do the check for "PointerToSymbolTable" because some files
		// have bogus values for the COFF header offset.
		if ( (debugDir->Type == IMAGE_DEBUG_TYPE_COFF) &&
		     pNTHeader->FileHeader.PointerToSymbolTable )
		{
			PCOFFDebugInfo =
				(PIMAGE_DEBUG_INFO)(base+ debugDir->PointerToRawData);
		}
		
		debugDir++;
	}
}

// Function prototype (necessary because two functions recurse)
void DumpResourceDirectory
(
	PIMAGE_RESOURCE_DIRECTORY resDir, DWORD resourceBase,
	DWORD level, DWORD resourceType
);

// The predefined resource types
char *SzResourceTypes[] = {
"???_0", "CURSOR", "BITMAP", "ICON", "MENU", "DIALOG", "STRING", "FONTDIR",
"FONT", "ACCELERATORS", "RCDATA", "MESSAGETABLE", "GROUP_CURSOR",
"???_13", "GROUP_ICON", "???_15", "VERSION"
};

// Get an ASCII string representing a resource type
void GetResourceTypeName(DWORD type, PSTR buffer, UINT cBytes)
{
	if ( type <= 16 )
		strncpy(buffer, SzResourceTypes[type], cBytes);
	else
		sprintf(buffer, "%X", type);
}

//
// If a resource entry has a string name (rather than an ID), go find
// the string and convert it from unicode to ascii.
//
void GetResourceNameFromId(DWORD id, DWORD resourceBase, PSTR buffer, UINT cBytes)
{
	PIMAGE_RESOURCE_DIR_STRING_U prdsu;

	// If it's a regular ID, just format it.
	if ( !(id & IMAGE_RESOURCE_NAME_IS_STRING) )
	{
		sprintf(buffer, "%X", id);
		return;
	}
	
	id &= 0x7FFFFFFF;
	prdsu = (PIMAGE_RESOURCE_DIR_STRING_U)(resourceBase + id);

	// prdsu->Length is the number of unicode characters
	WideCharToMultiByte(CP_ACP, 0, prdsu->NameString, prdsu->Length,
						buffer, cBytes,	0, 0);
	buffer[ min(cBytes-1,prdsu->Length) ] = 0;	// Null terminate it!!!
}

//
// Dump the information about one resource directory entry.  If the
// entry is for a subdirectory, call the directory dumping routine
// instead of printing information in this routine.
//
void DumpResourceEntry(PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry, DWORD resourceBase, DWORD level)
{
	UINT i;
	char nameBuffer[128];
		
	if ( resDirEntry->OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY )
	{
		DumpResourceDirectory( (PIMAGE_RESOURCE_DIRECTORY)
			((resDirEntry->OffsetToData & 0x7FFFFFFF) + resourceBase),
			resourceBase, level, resDirEntry->Name);
		return;
	}

	// Spit out the spacing for the level indentation
	for ( i=0; i < level; i++ )
		printf("    ");

	if ( resDirEntry->Name & IMAGE_RESOURCE_NAME_IS_STRING )
	{
		GetResourceNameFromId(resDirEntry->Name, resourceBase, nameBuffer,
							  sizeof(nameBuffer));
		printf("Name: %s  Offset: %08X\n",
			nameBuffer, resDirEntry->OffsetToData);
	}
	else
	{
		printf("ID: %08X  Offset: %08X\n",
				resDirEntry->Name, resDirEntry->OffsetToData);
	}
}

//
// Dump the information about one resource directory.
//
void DumpResourceDirectory(PIMAGE_RESOURCE_DIRECTORY resDir, DWORD resourceBase, DWORD level, DWORD resourceType)
{
	PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry;
	char szType[64];
	UINT i;

	// Spit out the spacing for the level indentation
	for ( i=0; i < level; i++ )
		printf("    ");

	// Level 1 resources are the resource types
	if ( level == 1 && !(resourceType & IMAGE_RESOURCE_NAME_IS_STRING) )
	{
		GetResourceTypeName( resourceType, szType, sizeof(szType) );
	}
	else	// Just print out the regular id or name
	{
		GetResourceNameFromId( resourceType, resourceBase, szType,
							   sizeof(szType) );
	}
	
	printf(
		"ResDir (%s) Named:%02X ID:%02X TimeDate:%08X Vers:%u.%02u Char:%X\n",
		szType,	resDir->NumberOfNamedEntries, resDir->NumberOfIdEntries,
		resDir->TimeDateStamp, resDir->MajorVersion,
		resDir->MinorVersion,resDir->Characteristics);

	resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDir+1);
	
	for ( i=0; i < resDir->NumberOfNamedEntries; i++, resDirEntry++ )
		DumpResourceEntry(resDirEntry, resourceBase, level+1);

	for ( i=0; i < resDir->NumberOfIdEntries; i++, resDirEntry++ )
		DumpResourceEntry(resDirEntry, resourceBase, level+1);
}

//
// Top level routine called to dump out the entire resource hierarchy
//
void DumpResourceSection(DWORD base, PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_RESOURCE_DIRECTORY resDir;
	
	resDir = (PIMAGE_RESOURCE_DIRECTORY)GetSectionPtr(".rsrc", pNTHeader, (DWORD)base);
	if ( !resDir )
		return;
	
 	printf("Resources\n");
	DumpResourceDirectory(resDir, (DWORD)resDir, 0, 0);
}

//
// Dump the imports table (the .idata section) of a PE file
//
void DumpImportsSection(DWORD base, PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_IMPORT_DESCRIPTOR importDesc;
	PIMAGE_SECTION_HEADER sectionHeader;
	PIMAGE_THUNK_DATA thunk;
	PIMAGE_IMPORT_BY_NAME pOrdinalName;
	DWORD exportsStartRVA, exportsEndRVA;

	sectionHeader = GetSectionHeader(".idata", pNTHeader);
	if ( !sectionHeader )
		return;

	// 因为.idata只有导入表，所以DataDirectory的RVA等于
	// 通过.idata在节表中查找的节头的RVA
	auto importRVA = pNTHeader->OptionalHeader.
		DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].
		VirtualAddress;
	auto offsetInto_rdata = importRVA - sectionHeader->VirtualAddress;
	auto import2 = MakePtr(PIMAGE_IMPORT_DESCRIPTOR, base,
		sectionHeader->PointerToRawData + offsetInto_rdata);

	importDesc = MakePtr(PIMAGE_IMPORT_DESCRIPTOR, base, sectionHeader->PointerToRawData);

	// 这里所有的地址都是文件地址，也就是基于base的地址。所以需要转换。
	// 目的变量的文件偏移量 = （目的变量的RVA - 节头的RVA） + 节头的PointerToRawData
	// 最后将【目的变量的文件偏移量】 + base地址
	auto delta = (INT)(sectionHeader->VirtualAddress - sectionHeader->PointerToRawData);
	
 	printf("Imports Table:\n");
	
	while ( 1 )
	{
		// See if we've reached an empty IMAGE_IMPORT_DESCRIPTOR
		if ( (importDesc->TimeDateStamp==0 ) && (importDesc->Name==0) )
			break;
		
		printf("  %s\n", (PBYTE)(importDesc->Name) - delta + base);

		printf("  Hint/Name Table: %08X\n", importDesc->Characteristics);
 		printf("  TimeDateStamp:   %08X\n", importDesc->TimeDateStamp);
 		printf("  ForwarderChain:  %08X\n", importDesc->ForwarderChain);
 		printf("  First thunk RVA: %08X\n", importDesc->FirstThunk);

		// OriginalFirstThunk称之为ILT。（Import Lookup Table）
		// FirstThunk称之为IAT。（Import Address Table）
		
		thunk = (PIMAGE_THUNK_DATA)importDesc->FirstThunk;
		thunk = (PIMAGE_THUNK_DATA)( (PBYTE)thunk - delta + base);
		
		// If the pointer that thunk points to is outside of the .idata
		// section, it looks like this file is "pre-fixed up" with regards
		// to the thunk table.  In this situation, we'll need to fall back
		// to the hint-name (aka, the "Characteristics") table.
		exportsStartRVA = sectionHeader->VirtualAddress;
		exportsEndRVA = exportsStartRVA + sectionHeader->SizeOfRawData;
		if ( (*(PDWORD)thunk <= exportsStartRVA) ||
			 (*(PDWORD)thunk >= exportsEndRVA) )
		{
			if ( importDesc->Characteristics == 0 )	// Borland doesn't have
				return;								// this table!!!
					
			thunk = (PIMAGE_THUNK_DATA)importDesc->Characteristics;
			if ( ((DWORD)thunk <= exportsStartRVA) ||
				 ((DWORD)thunk >= exportsEndRVA) )
				return;

			thunk = (PIMAGE_THUNK_DATA)( (PBYTE)thunk - delta + base);
		}

		printf("  Ordn  Name\n");
		
		while ( 1 )	// Loop forever (or until we break out)
		{
			if ( thunk->u1.AddressOfData == 0 )
				break;

			if ( thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
			{
				printf("  %4u\n", thunk->u1.Ordinal & 0xFFFF);
				break;
			}
			else
			{
				pOrdinalName = (PIMAGE_IMPORT_BY_NAME)thunk->u1.AddressOfData;
				pOrdinalName = (PIMAGE_IMPORT_BY_NAME)
								((PBYTE)pOrdinalName - delta + base);
					
				printf("  %4u  %s\n", pOrdinalName->Hint, pOrdinalName->Name);
			}
			
			thunk++;			// Advance to next thunk
		}

		importDesc++;	// advance to next IMAGE_IMPORT_DESCRIPTOR
		printf("\n");
	}
}

//
// Dump the exports table (the .edata section) of a PE file
//
void DumpExportsSection(DWORD base, PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_EXPORT_DIRECTORY exportDir;
	PIMAGE_SECTION_HEADER sectionHeader;
	INT delta; 
	PSTR filename;
	DWORD i;
	PDWORD functions;
	PWORD ordinals;
	PSTR *name;

	auto exportRVA = pNTHeader->OptionalHeader.
		DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].
		VirtualAddress;
	if (exportRVA == 0)
	{
		return;
	}

	sectionHeader = GetSectionHeader(".rdata", pNTHeader);
	if ( !sectionHeader )
		return;

	auto offset = exportRVA - sectionHeader->VirtualAddress;
	exportDir = MakePtr(PIMAGE_EXPORT_DIRECTORY, base,
		sectionHeader->PointerToRawData + offset);


	//sectionHeader = GetSectionHeader(".edata", pNTHeader);
	//if ( !sectionHeader )
	//	return;

	//exportDir = MakePtr(PIMAGE_EXPORT_DIRECTORY, base,
	//					 sectionHeader->PointerToRawData);


	delta = (INT)(sectionHeader->VirtualAddress - sectionHeader->PointerToRawData);
	
	filename = (PSTR)(exportDir->Name - delta + base);
		
 	printf("exports table:\n\n");
	printf("  Name:            %s\n", filename);
	printf("  Characteristics: %08X\n", exportDir->Characteristics);
	printf("  TimeDateStamp:   %08X\n", exportDir->TimeDateStamp);
	printf("  Version:         %u.%02u\n", exportDir->MajorVersion,
			exportDir->MinorVersion);
	printf("  Ordinal base:    %08X\n", exportDir->Base);
	printf("  # of functions:  %08X\n", exportDir->NumberOfFunctions);
	printf("  # of Names:      %08X\n", exportDir->NumberOfNames);
	
	functions = (PDWORD)((DWORD)exportDir->AddressOfFunctions - delta + base);
	ordinals = (PWORD)((DWORD)exportDir->AddressOfNameOrdinals - delta + base);
	name = (PSTR *)((DWORD)exportDir->AddressOfNames - delta + base);

	printf("\n  Entry Pt  Ordn  Name\n");
	for ( i=0; i < exportDir->NumberOfNames; i++ )
	{
		printf("  %08X  %4u  %s\n", *functions,
				*ordinals + exportDir->Base,
				(*name - delta + base));
		name++;			// Bump each pointer to the next array element
		ordinals++;
		functions++;
	}
}

// The names of the available base relocations
char *SzRelocTypes[] = {
"ABSOLUTE","HIGH","LOW","HIGHLOW","HIGHADJ","MIPS_JMPADDR",
"I860_BRADDR","I860_SPLIT" };

//
// Dump the base relocation table of a PE file
//
void DumpBaseRelocationsSection(DWORD base, PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_BASE_RELOCATION baseReloc;
	
	//PIMAGE_SECTION_HEADER
	baseReloc = (PIMAGE_BASE_RELOCATION)GetSectionPtr(".reloc", pNTHeader, base);
	if ( !baseReloc )
		return;

	auto reloRVA = pNTHeader->OptionalHeader.
		DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].
		VirtualAddress;

	//auto offset = reloRVA - baseReloc->VirtualAddress;
	auto reloBase = MakePtr(PIMAGE_BASE_RELOCATION, base,
		reloRVA);


	printf("base relocations:\n\n");

	while ( baseReloc->SizeOfBlock != 0 )
	{
		unsigned i,cEntries;
		PWORD pEntry;
		char *szRelocType;
		WORD relocType;
		
		cEntries = (baseReloc->SizeOfBlock - sizeof(*baseReloc))/sizeof(WORD);
		pEntry = MakePtr( PWORD, baseReloc, sizeof(*baseReloc) );
		
		printf("Virtual Address: %08X  size: %08X\n",
				baseReloc->VirtualAddress, baseReloc->SizeOfBlock);
		
		// <Inject your code to a Portable Executable file> in codeproject
		for ( i=0; i < cEntries; i++ )
		{
			// Extract the top 4 bits of the relocation entry.  Turn those 4
			// bits into an appropriate descriptive string (szRelocType)
			relocType = (*pEntry & 0xF000) >> 12;
			szRelocType = relocType < 8 ? SzRelocTypes[relocType] : "unknown";

			auto reloRVA = baseReloc->VirtualAddress + (*pEntry & 0x0FFF);
			
			printf("  %s\n", (PSTR*)((DWORD)(reloRVA + base)));

			printf("  %08X %s\n",
					(*pEntry & 0x0FFF) /*+ baseReloc->VirtualAddress*/,
					szRelocType);
			pEntry++;	// Advance to next relocation entry
		}
		
		baseReloc = MakePtr( PIMAGE_BASE_RELOCATION, baseReloc,
							 baseReloc->SizeOfBlock);
	}
}

//
// Dump the COFF debug information header
//
void DumpCOFFHeader(PIMAGE_DEBUG_INFO pDbgInfo)
{
	printf("COFF Debug Info Header\n");
	printf("  NumberOfSymbols:      %08X\n", pDbgInfo->NumberOfSymbols);
	printf("  LvaToFirstSymbol:     %08X\n", pDbgInfo->LvaToFirstSymbol);
	printf("  NumberOfLinenumbers:  %08X\n", pDbgInfo->NumberOfLinenumbers);
	printf("  LvaToFirstLinenumber: %08X\n", pDbgInfo->LvaToFirstLinenumber);
	printf("  RvaToFirstByteOfCode: %08X\n", pDbgInfo->RvaToFirstByteOfCode);
	printf("  RvaToLastByteOfCode:  %08X\n", pDbgInfo->RvaToLastByteOfCode);
	printf("  RvaToFirstByteOfData: %08X\n", pDbgInfo->RvaToFirstByteOfData);
	printf("  RvaToLastByteOfData:  %08X\n", pDbgInfo->RvaToLastByteOfData);
}

//
// top level routine called from PEDUMP.C to dump the components of a PE file
//
void DumpExeFile( PIMAGE_DOS_HEADER dosHeader )
{
	PIMAGE_NT_HEADERS pNTHeader;
	DWORD base = (DWORD)dosHeader;
	
	pNTHeader = MakePtr( PIMAGE_NT_HEADERS, dosHeader,
								dosHeader->e_lfanew );

	// First, verify that the e_lfanew field gave us a reasonable
	// pointer, then verify the PE signature.
	if ( IsBadReadPtr(pNTHeader, sizeof(IMAGE_NT_HEADERS)) ||
	     pNTHeader->Signature != IMAGE_NT_SIGNATURE )
	{
		printf("Unhandled EXE type, or invalid .EXE\n");
		return;
	}
	
	DumpHeader((PIMAGE_FILE_HEADER)&pNTHeader->FileHeader);
	printf("\n");

	DumpOptionalHeader((PIMAGE_OPTIONAL_HEADER)&pNTHeader->OptionalHeader);
	printf("\n");

	DumpSectionTable( (PIMAGE_SECTION_HEADER)(pNTHeader+1),
						pNTHeader->FileHeader.NumberOfSections, TRUE);
	printf("\n");

	DumpDebugDirectory(base, pNTHeader);
	printf("\n");

 	DumpResourceSection(base, pNTHeader);
	printf("\n");

	DumpImportsSection(base, pNTHeader);
	printf("\n");
	
	DumpExportsSection(base, pNTHeader);
	printf("\n");

	if ( fShowRelocations )
	{
		DumpBaseRelocationsSection(base, pNTHeader);
		printf("\n");
	} 

	//
	// Initialize these vars here since we'll need them in DumpLineNumbers
	//
	PCOFFSymbolTable = MakePtr(PIMAGE_SYMBOL, base,
						pNTHeader->FileHeader.PointerToSymbolTable);
	COFFSymbolCount = pNTHeader->FileHeader.NumberOfSymbols;

	if ( fShowSymbolTable && PCOFFDebugInfo )
	{
		DumpCOFFHeader( PCOFFDebugInfo );
		printf("\n");
	}
	
	if ( fShowLineNumbers && PCOFFDebugInfo )
	{
		DumpLineNumbers( MakePtr(PIMAGE_LINENUMBER, PCOFFDebugInfo,
							PCOFFDebugInfo->LvaToFirstLinenumber),
							PCOFFDebugInfo->NumberOfLinenumbers);
		printf("\n");
	}

	if ( fShowSymbolTable )
	{
		if ( pNTHeader->FileHeader.NumberOfSymbols 
			&& pNTHeader->FileHeader.PointerToSymbolTable)
		{
			DumpSymbolTable(PCOFFSymbolTable, COFFSymbolCount);
			printf("\n");
		}
	}
	
	if ( fShowRawSectionData )
	{
		DumpRawSectionData( (PIMAGE_SECTION_HEADER)(pNTHeader+1),
							dosHeader,
							pNTHeader->FileHeader.NumberOfSections);
	}
}
