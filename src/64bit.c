#include "../include/woody.h"

/**
 * Estrae il payload compilato in binario dal codice assembly
 * @param filepath Path del binario in assembly
 * @param size verrà assegnato dalla funzione per conoscere la size del payload
 * @return Ptr al payload salvato in memoria
 */
void 	*extractor_payload64(const char *filepath, size_t *size)
{
	int			fd = 0;
	Elf64_Half	i = 0;
	Elf64_Ehdr	*cast_addr = 0;
	size_t		size_file = 0;
	void 		*ret = 0, *map_file = 0;
	char 		*name = 0;

	if ((fd = open(filepath, O_RDWR)) < 0)
		exit_error("Error open file", 11);
	size_file = lseek(fd, 0, SEEK_END);
	if ((map_file = mmap(0, size_file, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
		exit_error("Error mapping file", 12);
	close(fd);
	cast_addr = map_file;

	for (Elf64_Shdr *tmp = map_file + cast_addr->e_shoff; i < cast_addr->e_shnum; ++i)
	{
		name = tmp[cast_addr->e_shstrndx].sh_offset + map_file + tmp[i].sh_name;
		if (!strcmp(name, ".text"))
		{
			if (!(ret = malloc(tmp[i].sh_size)))
				exit_error("Error malloc", 13);
			memcpy(ret, map_file + tmp[i].sh_offset, tmp[i].sh_size);
			*size = tmp[i].sh_size;
			break;
		}
	}
	if (munmap(map_file, size_file) == -1)
		exit_error("Error unmapping memory", 19);
	return ret;
}

/**
 * Cerca in quale sezione inserire il payload
 * @param phdr Indirizzo del primo blocco dei Program Header
 * @param n_phdr Numero di quanti Program Header esistono
 * @param size_payload Dimensione del payload
 * @return Indice del Program Header da infettare mentre in caso di errore -1
 */
int		find_section_to_infect64(Elf64_Phdr *phdr, int n_phdr, size_t size_payload)
{
	Elf64_Off	start = 0, end = 0;
	int 		j = 0;

	for (int i = 0; i < n_phdr; ++i)
	{
		// Cerco la sezione controllando se le dimensioni siano giuste e che sia una sezione eseguibile
		if (phdr[i].p_filesz > 0 && phdr[i].p_filesz == phdr[i].p_memsz && (phdr[i].p_flags & PF_X))
		{
			start = phdr[i].p_offset + phdr[i].p_filesz;
			end = start + size_payload;
			// Controllo se dove andremo a mettere il codice ci sta altro codice,
			// dunque se è una sezione vuota
			for (j = 0; j < n_phdr; ++j)
			{
				if (phdr[j].p_offset >= start && phdr[j].p_offset < end && phdr[j].p_filesz > 0)
					break;
			}
			if (j == n_phdr)
				return i;
		}
	}
	return -1;
}

/**
 * Inserisce il payload nel binario da infettare
 * @param phdr Ptr al primo blocco dei Program Header
 * @param i Indice del Program Header da infettare
 * @param binary binario da infettare
 * @param payload Struttura del payload
 */
void 	insert_payload64(Elf64_Phdr *phdr, int i, t_mem_image *binary, t_mem_image *payload)
{
	Elf64_Ehdr *ehdr = binary->addr;
	Elf64_Off 	start = 0, offset = 0;

	if (phdr[i].p_offset + phdr[i].p_filesz >= binary->size)
		exit_error("Invalid program segment in header table", 15);
	start = phdr[i].p_vaddr + phdr[i].p_filesz;
	offset = ehdr->e_entry - (start + payload->size);
	//Modifico gli ultimi 4 byte del payload che si riferiscono alla funzione jmp
	*(Elf64_Word*)(payload->addr + payload->size - 4) = (Elf64_Word)offset;
	ehdr->e_entry = start;

	//Inserisco il payload nel binario
	memcpy(binary->addr + phdr[i].p_offset + phdr[i].p_filesz, payload->addr, payload->size);
	phdr[i].p_filesz += payload->size;
	phdr[i].p_memsz += payload->size;
}