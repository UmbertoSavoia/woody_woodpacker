#include "../include/woody.h"
// exit 33

void 	launcher(int arch, t_mem_image *binary_map, t_mem_image *payload, char *key, t_pe_file *pe_file)
{
	int section_to_infect = 0;
	Elf64_Ehdr *ehdr64 = 0;
	Elf32_Ehdr *ehdr32 = 0;
	uint32_t offset = 0;

	if (arch == 64) // ELF64
	{
		ehdr64 = binary_map->addr;
		payload->addr = extractor_payload64(PATH_PAYLOAD64, &payload->size);
		if ((section_to_infect = find_section_to_infect64(binary_map->addr + ehdr64->e_phoff,
														  ehdr64->e_phnum, payload->size)) == -1)
			exit_error("Unable to find a usable infection point", 14);
		insert_payload64(binary_map->addr + ehdr64->e_phoff, section_to_infect, binary_map, payload, key);
		encrypt_text_section64(binary_map, key);
	}
	else if (arch == 32) //ELF32
	{
		ehdr32 = binary_map->addr;
		payload->addr = extractor_payload32(PATH_PAYLOAD32, &payload->size);
		if ((section_to_infect = find_section_to_infect32(binary_map->addr + ehdr32->e_phoff,
														  ehdr32->e_phnum, payload->size)) == -1)
			exit_error("Unable to find a usable infection point", 23);
		insert_payload32(binary_map->addr + ehdr32->e_phoff, section_to_infect, binary_map, payload, key);
		encrypt_text_section32(binary_map, key);
	}
	else if (arch == 65) // PE 64bit
	{
		if ((section_to_infect = find_section_to_infect_PE64(binary_map, pe_file, payload, &offset)) == -1)
			exit_error("Unable to find a usable infection point", 32);
	}
}

int 	main(int ac, char **av)
{
	t_mem_image	binary_map = {0}, binary_map_org = {0}, payload = {0};
	t_pe_file	pe_file;
	int			arch = 0;
	char 		*key = 0;

	if ((ac < 2) || (ac == 3) || ( (ac == 4) && (memcmp(av[2], "-k", 2) != 0) ) || ac > 4)
		exit_error("Invalid Argument", 1);
	( (ac == 4) && (strlen(av[3]) >= 10) ) ? (key = ft_substr(av[3], 0, 9)) : (key = strdup("0123456789"));
	binary_map_org.addr = map_file_in_memory(av[1], &binary_map_org.size);
	arch = check_file(&binary_map_org, &pe_file);
	binary_map.addr = copy_file(&binary_map_org, &binary_map.size);

	launcher(arch, &binary_map, &payload, key, &pe_file);

	free(payload.addr);
	free(key);
	if (munmap(binary_map.addr, binary_map.size) == -1)
		exit_error("Error unmapping memory", 4);
	if (munmap(binary_map_org.addr, binary_map_org.size) == -1)
		exit_error("Error unmapping memory", 18);
}