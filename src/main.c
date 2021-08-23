#include "../include/woody.h"
// exit 35

void 	launcher(int arch, t_mem_image *binary_map, t_mem_image *payload, char *key, t_pe_file *pe_file)
{
	int section_to_infect = 0;
	Elf64_Ehdr *ehdr64 = 0;
	Elf32_Ehdr *ehdr32 = 0;
	uint32_t new_entry = 0;

	if (arch == 64) // ELF64
	{
		ehdr64 = binary_map->addr;
		payload->addr = extractor_payload64(PATH_PAYLOAD64, &payload->size);
		printf(GREEN"[*] Extracted payload\n"NC);
		if ((section_to_infect = find_section_to_infect64(binary_map->addr + ehdr64->e_phoff,
														  ehdr64->e_phnum, payload->size)) == -1)
			exit_error("Unable to find a usable infection point", 14);
		printf(GREEN"[*] Section to infect found\n"NC);
		insert_payload64(binary_map->addr + ehdr64->e_phoff, section_to_infect, binary_map, payload, key);
		printf(GREEN"[*] Payload inserted\n"NC);
		encrypt_text_section64(binary_map, key);
		printf(GREEN"[*] Encrypted binary\n"NC);
	}
	else if (arch == 32) //ELF32
	{
		ehdr32 = binary_map->addr;
		payload->addr = extractor_payload32(PATH_PAYLOAD32, &payload->size);
		printf(GREEN"[*] Extracted payload\n"NC);
		if ((section_to_infect = find_section_to_infect32(binary_map->addr + ehdr32->e_phoff,
														  ehdr32->e_phnum, payload->size)) == -1)
			exit_error("Unable to find a usable infection point", 23);
		printf(GREEN"[*] Section to infect found\n"NC);
		insert_payload32(binary_map->addr + ehdr32->e_phoff, section_to_infect, binary_map, payload, key);
		printf(GREEN"[*] Payload inserted\n"NC);
		encrypt_text_section32(binary_map, key);
		printf(GREEN"[*] Encrypted binary\n"NC);
	}
	else if (arch == 65) // PE 64bit
	{
		IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER*)binary_map->addr;
		uint32_t *signature_ptr = LIBPE_PTR_ADD(dos_header,dos_header->e_lfanew);
		IMAGE_FILE_HEADER *coff = LIBPE_PTR_ADD(signature_ptr, sizeof(uint32_t));
		IMAGE_OPTIONAL_HEADER64 *optional_header = LIBPE_PTR_ADD(coff, sizeof(IMAGE_FILE_HEADER));
		uint32_t sections_offset = sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + coff->SizeOfOptionalHeader;
		IMAGE_SECTION_HEADER *sections = LIBPE_PTR_ADD(signature_ptr, sections_offset);

		*pe_file = (t_pe_file){ dos_header, signature_ptr, coff, optional_header, sections, coff->NumberOfSections, 0, 0 };
		if ((section_to_infect = find_section_to_infect_PE64(binary_map, pe_file, payload, &new_entry)) == -1)
			exit_error("Unable to find a usable infection point", 32);
		printf(GREEN"[*] Section to infect found\n"NC);
		insert_payload_PE64(binary_map, pe_file, section_to_infect, payload, new_entry);
		printf(GREEN"[*] Payload inserted\n"NC);
	}
}

int 	check_args(int ac, char **av)
{
	if (ac < 2)
		return 1;
	else if ( (ac == 2) && (!memcmp(av[1], "-c", 2) || !memcmp(av[1], "-d", 2)) )
		return 1;
	else if ( ((ac == 3) && ( (memcmp(av[1], "-c", 2) != 0) )) && (ac == 3) && ( (memcmp(av[1], "-d", 2) != 0) ) )
		return 1;
	else if ( (ac == 4) && memcmp(av[2], "-k", 2) )
		return 1;
	else if ( ac > 4 )
		return 1;
	else
		return 0;
}

int 	usage(void)
{
	printf("\n\n");
	printf("\033[1mFor inject file elf64, elf32, pe32+(pe64)\n\033[0m");
	printf("usage: ./woody_woodpacker <filename> [-k key]\n");
	printf("\n");
	printf("\033[1m  -k\n\033[0m");
	printf("\tdefine a specific key for encrypting the binary file\n");

	printf("\n");
	printf("\033[1mFor compress or decompress binary file\n\033[0m");
	printf("usage: ./woody_woodpacker [-c] [-d] <filename>\n");
	printf("\n");
	printf("\033[1m  -c\n\033[0m");
	printf("\tcompress the binary file\n");
	printf("\033[1m  -d\033[0m\n");
	printf("\tdecompress the binary file\n");

	printf("\n\n");
	return 1;
}

int 	main(int ac, char **av)
{
	t_mem_image	binary_map = {0}, binary_map_org = {0}, payload = {0};
	t_pe_file	pe_file = {0};
	int			arch = 0;
	char 		*key = 0;

	if (check_args(ac, av) && usage())
		exit_error("Invalid Argument", 1);
	if (!memcmp(av[1], "-c", 2))
		compress_file(av[2]);
	else if (!memcmp(av[1], "-d", 2))
		decompress_file(av[2]);
	( (ac == 4) && (strlen(av[3]) >= 10) ) ? (key = ft_substr(av[3], 0, 9)) : (key = strdup("0123456789"));
	binary_map_org.addr = map_file_in_memory(av[1], &binary_map_org.size);
	arch = check_file(&binary_map_org);
	binary_map.addr = copy_file(&binary_map_org, &binary_map.size);

	launcher(arch, &binary_map, &payload, key, &pe_file);

	free(payload.addr);
	free(key);
	if (munmap(binary_map.addr, binary_map.size) == -1)
		exit_error("Error unmapping memory", 4);
	if (munmap(binary_map_org.addr, binary_map_org.size) == -1)
		exit_error("Error unmapping memory", 18);
}