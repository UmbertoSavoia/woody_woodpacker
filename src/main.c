#include "../include/woody.h"
// exit 15
/*
 * TODO provare nel payload a mettere i registri a 32bit e vedere se tutto funziona anche a 64bit
 * TODO aggiungere nel make la compilazione del payload a 32bit
 */

int 	main(int ac, char **av)
{
	t_mem_image	binary_map;
	t_mem_image payload;
	int			arch = 0, section_to_infect = 0;;
	Elf64_Ehdr *ehdr64 = 0;

	if (ac != 2)
		exit_error("Invalid Argument", 1);
	binary_map.addr = map_file_in_memory(av[1], &binary_map.size);
	arch = check_elf(&binary_map);

	if (arch == 64)
	{
		ehdr64 = binary_map.addr;
		payload.addr = extractor_payload64(PATH_PAYLOAD64, &payload.size);
		if ((section_to_infect = find_section_to_infect64(binary_map.addr + ehdr64->e_phoff,
														 ehdr64->e_phnum, payload.size)) == -1)
			exit_error("Unable to find a usable infection point", 14);
		insert_payload64(binary_map.addr + ehdr64->e_phoff, section_to_infect, &binary_map, &payload);
	}

	free(payload.addr);
	if (munmap(binary_map.addr, binary_map.size) == -1)
		exit_error("Error unmapping memory", 4);
}