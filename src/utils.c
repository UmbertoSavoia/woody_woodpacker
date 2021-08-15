#include "../include/woody.h"

/**
 * Funzione di uscita con relativo codice per il debug
 * @param msg messaggio di uscita
 * @param exit_code codice di errore
 */
void 	exit_error(const char *msg, int exit_code)
{
	printf(RED"%s\n"NC, msg);
	exit(exit_code);
}

/**
 * Tramite mmap mappa un file passatogli come argomento
 * in memoria
 * @param file_path Path del file da mappare
 * @param size_file Size del file caricato
 * @return puntatore all'area di memoria
 */
void 	*map_file_in_memory(const char *file_path, size_t *size_file)
{
	int		fd = 0;
	void*	ret = 0;

	if ((fd = open(file_path, O_RDWR)) < 0)
		exit_error("Error open file", 2);
	*size_file = lseek(fd, 0, SEEK_END);
	if ((ret = mmap(0, *size_file, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
		exit_error("Error mapping file", 3);
	close(fd);
	return ret;
}

/**
 * Check sulla validità del file elf64
 * @param binary struttura con indirizzo e size del file in memeria
 * @return 32 se 32bit / 64 se 64bit
 */
int 	check_elf(t_mem_image *binary)
{
	char 		mag_elf[4] = { 0x7F, 'E', 'L', 'F'};
	int 		arch = 0;
	Elf64_Ehdr	*ehdr64;
	Elf32_Ehdr	*ehdr32;

	if (memcmp(binary->addr, mag_elf, 4))
		exit_error("It is not ELF file", 4);
	if ((((char*)binary->addr)[EI_CLASS] != ELFCLASS64) && ((char*)binary->addr)[EI_CLASS] != ELFCLASS32)
		exit_error("Unsupported architecture", 5);
	arch = ((char*)binary->addr)[EI_CLASS] == ELFCLASS64 ? 64 : 32;

	if (arch == 32)
	{
		ehdr32 = binary->addr;
		if (ehdr32->e_entry == 0)
			exit_error("Not an executable file", 6);
		if (ehdr32->e_phoff <= 0 || ehdr32->e_phnum <= 0)
			exit_error("Invalid ELF header", 7);
		if (ehdr32->e_phoff + ehdr32->e_phnum * sizeof(Elf32_Phdr) > binary->size)
			exit_error("Invalid program segment header table", 8);
	}
	else if (arch == 64)
	{
		ehdr64 = binary->addr;
		if (ehdr64->e_entry == 0)
			exit_error("Not an executable file", 9);
		if (ehdr64->e_phoff <= 0 || ehdr64->e_phnum <= 0)
			exit_error("Invalid ELF header", 10);
		if (ehdr64->e_phoff + ehdr64->e_phnum * sizeof(Elf64_Phdr) > binary->size)
			exit_error("Invalid program segment header table", 11);
	}
	return arch;
}

