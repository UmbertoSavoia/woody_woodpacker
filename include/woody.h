#ifndef WOODY_H

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <elf.h>
#include <zlib.h>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define NC "\033[0m"

#define PATH_PAYLOAD64 "./payload/inject64.o"
#define PATH_PAYLOAD32 "./payload/inject32.o"

typedef struct s_mem_image
{
	void 	*addr;
	size_t	size;
}				t_mem_image;

/*
 * PE type and struct
 */

//#define PAYLOAD_PE "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"
//#define PAYLOAD_PE_SIZE 276
#define PAYLOAD_PE "\xeb\x1b\x5e\xbf\x90\xd4\xb5\x9e\xb9\xb0\x53\xb6\x9e\x6a\xf5\xff\xd7\x6a\x00\x6a\x00\x6a\x0e\x56\x50\xff\xd1\xeb\x13\xe8\xe0\xff\xff\xff\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\xe9\xff\xff\xff\xff"
#define PAYLOAD_PE_SIZE 53

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define SECTION_NAME_SIZE 8
#define LIBPE_PTR_ADD(p, o)						((void *)((char *)(p) + (o)))
#define LIBPE_SIZEOF_MEMBER(type, member)		sizeof(((type *)0)->member)

typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned long		LONG;
typedef uint64_t			ULONGLONG;
typedef void*				HANDLE;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	uint16_t  e_magic;                     // Magic number
	uint16_t  e_cblp;                      // Bytes on last page of file
	uint16_t  e_cp;                        // Pages in file
	uint16_t  e_crlc;                      // Relocations
	uint16_t  e_cparhdr;                   // Size of header in paragraphs
	uint16_t  e_minalloc;                  // Minimum extra paragraphs needed
	uint16_t  e_maxalloc;                  // Maximum extra paragraphs needed
	uint16_t  e_ss;                        // Initial (relative) SS value
	uint16_t  e_sp;                        // Initial SP value
	uint16_t  e_csum;                      // Checksum
	uint16_t  e_ip;                        // Initial IP value
	uint16_t  e_cs;                        // Initial (relative) CS value
	uint16_t  e_lfarlc;                    // File address of relocation table
	uint16_t  e_ovno;                      // Overlay number
	uint16_t  e_res[4];                    // Reserved words
	uint16_t  e_oemid;                     // OEM identifier (for e_oeminfo)
	uint16_t  e_oeminfo;                   // OEM information; e_oemid specific
	uint16_t  e_res2[10];                  // Reserved words
	//WORD   e_lfanew;                    // File address of new exe header
	uint32_t e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	uint16_t Machine; // MachineType
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics; // ImageCharacteristics
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER; //COFF

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	uint16_t	Magic;
	uint8_t		MajorLinkerVersion;
	uint8_t		MinorLinkerVersion;
	uint32_t 	SizeOfCode;
	uint32_t 	SizeOfInitializedData;
	uint32_t 	SizeOfUninitializedData;
	uint32_t 	AddressOfEntryPoint;
	uint32_t 	BaseOfCode;
	uint64_t 	ImageBase;
	uint32_t 	SectionAlignment;
	uint32_t 	FileAlignment;
	uint16_t 	MajorOperatingSystemVersion;
	uint16_t 	MinorOperatingSystemVersion;
	uint16_t 	MajorImageVersion;
	uint16_t 	MinorImageVersion;
	uint16_t 	MajorSubsystemVersion;
	uint16_t 	MinorSubsystemVersion;
	uint32_t 	Reserved1;
	uint32_t 	SizeOfImage;
	uint32_t 	SizeOfHeaders;
	uint32_t 	CheckSum;
	uint16_t 	Subsystem; // WindowsSubsystem
	uint16_t 	DllCharacteristics;
	uint64_t 	SizeOfStackReserve;
	uint64_t 	SizeOfStackCommit;
	uint64_t 	SizeOfHeapReserve;
	uint64_t 	SizeOfHeapCommit;
	uint32_t 	LoaderFlags;  //must be zero
	uint32_t 	NumberOfRvaAndSizes;
	//IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct {
	uint8_t Name[SECTION_NAME_SIZE]; // TODO: Should we use char instead?
	union {
		uint32_t PhysicalAddress; // same value as next field
		uint32_t VirtualSize;
	} Misc;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations; // always zero in executables
	uint32_t PointerToLinenumbers; // deprecated
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers; // deprecated
	uint32_t Characteristics; // SectionCharacteristics
} IMAGE_SECTION_HEADER;

typedef struct s_pe_file
{
	// DOS header
	IMAGE_DOS_HEADER *dos_hdr;
	// Signature
	uint32_t *signature_ptr;
	// COFF header
	IMAGE_FILE_HEADER *coff_hdr;
	// Optional header
	IMAGE_OPTIONAL_HEADER64 *optional_hdr;
	// Sections
	IMAGE_SECTION_HEADER *sections; // array up to MAX_SECTIONS
	uint16_t num_sections;
	uint64_t entrypoint;
	uint64_t imagebase;
}				t_pe_file;


// FILE:

/*
 * Utils
 */
void 	exit_error(const char *msg, int exit_code);
void 	*map_file_in_memory(const char *file_path, size_t *size_file);
int 	check_file(t_mem_image *binary);
void 	*copy_file(t_mem_image *org, size_t *size);
char	*ft_substr(char const *s, unsigned int start, size_t len);

/*
 * Elf 64bit
 */
void 		*extractor_payload64(const char *filepath, size_t *size);
int			find_section_to_infect64(Elf64_Phdr *phdr, int n_phdr, size_t size_payload);
void 		insert_payload64(Elf64_Phdr *phdr, int i, t_mem_image *binary, t_mem_image *payload, char *key);
int 		find_section64(const char *name, t_mem_image *binary, size_t *size_section);
void		encrypt_text_section64(t_mem_image *binary, char *key);
Elf64_Addr	find_virtual_addr64(t_mem_image *binary, int *error);
void 		insert_decrypter_in_payload64(t_mem_image *binary, t_mem_image *payload, Elf64_Off start, char *key);

/**
 * Elf 32bit
 */
void 		*extractor_payload32(const char *filepath, size_t *size);
int			find_section_to_infect32(Elf32_Phdr *phdr, int n_phdr, size_t size_payload);
void 		insert_payload32(Elf32_Phdr *phdr, int i, t_mem_image *binary, t_mem_image *payload, char *key);
int 		find_section32(const char *name, t_mem_image *binary, size_t *size_section);
void		encrypt_text_section32(t_mem_image *binary, char *key);
Elf32_Addr	find_virtual_addr32(t_mem_image *binary, int *error);
void 		insert_decrypter_in_payload32(t_mem_image *binary, t_mem_image *payload, Elf32_Off start, char *key);

/*
 * PE 64bit
 */
int 	find_section_to_infect_PE64(t_mem_image *binary, t_pe_file *pe_file, t_mem_image *payload, uint32_t *new_entry);
void 	insert_payload_PE64(t_mem_image *binary, t_pe_file *pe_file, int index_section, t_mem_image *payload, uint32_t new_entry);

/*
 * Compression
 */
void 	compress_file(char *file);
void 	decompress_file(char *file);

#endif