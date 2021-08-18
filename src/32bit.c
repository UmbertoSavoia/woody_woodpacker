#include "../include/woody.h"

/**
 * Estrae il payload compilato in binario dal codice assembly
 * @param filepath Path del binario in assembly
 * @param size verrà assegnato dalla funzione per conoscere la size del payload
 * @return Ptr al payload salvato in memoria
 */
void 	*extractor_payload32(const char *filepath, size_t *size)
{
	int			fd = 0;
	Elf32_Half	i = 0;
	Elf32_Ehdr	*cast_addr = 0;
	size_t		size_file = 0;
	void 		*ret = 0, *map_file = 0;
	char 		*name = 0;

	if ((fd = open(filepath, O_RDWR)) < 0)
		exit_error("Error open file", 24);
	size_file = lseek(fd, 0, SEEK_END);
	if ((map_file = mmap(0, size_file, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
		exit_error("Error mapping file", 25);
	close(fd);
	cast_addr = map_file;

	for (Elf32_Shdr *tmp = map_file + cast_addr->e_shoff; i < cast_addr->e_shnum; ++i)
	{
		name = tmp[cast_addr->e_shstrndx].sh_offset + map_file + tmp[i].sh_name;
		if (!strcmp(name, ".text"))
		{
			if (!(ret = malloc(tmp[i].sh_size)))
				exit_error("Error malloc", 26);
			memcpy(ret, map_file + tmp[i].sh_offset, tmp[i].sh_size);
			*size = tmp[i].sh_size;
			break;
		}
	}
	if (munmap(map_file, size_file) == -1)
		exit_error("Error unmapping memory", 27);
	return ret;
}

/**
 * Cerca in quale sezione inserire il payload
 * @param phdr Indirizzo del primo blocco dei Program Header
 * @param n_phdr Numero di quanti Program Header esistono
 * @param size_payload Dimensione del payload
 * @return Indice del Program Header da infettare mentre in caso di errore -1
 */
int		find_section_to_infect32(Elf32_Phdr *phdr, int n_phdr, size_t size_payload)
{
	Elf32_Off	start = 0, end = 0;
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
 * Inserisce i campi necessari per il funzionamento del Decrypter nel payload
 * @param binary struttura del binario
 * @param payload struttura del payload
 * @param start nuovo punto di accesso dell'eseguibile
 * @param key chiave di cifratura
 */
void 	insert_decrypter_in_payload32(t_mem_image *binary, t_mem_image *payload, Elf32_Off start, char *key)
{
	size_t		size_text = 0;
	int			index_section = 0;
	Elf32_Word	virtual_addr = 0;
	int 		error = 0;
	Elf32_Shdr	*tmp = binary->addr + ((Elf32_Ehdr*)binary->addr)->e_shoff;

	if ((index_section = find_section32(".text", binary, &size_text)) == -1)
		exit_error("Section not found", 28);
	virtual_addr = find_virtual_addr32(binary, &error) + tmp[index_section].sh_offset;
	if (error == -1)
		exit_error("Cannot find the PT_LOAD", 29);

	memcpy(payload->addr + 4, &start, sizeof(Elf32_Word)); // copiare l'entry per mprotect
	memcpy(payload->addr + 9, &size_text, sizeof(Elf32_Word)); // mprotect size section text
	memcpy(payload->addr + 14, &virtual_addr, sizeof(Elf32_Word)); // mprotect offset section text
	memcpy(payload->addr + payload->size - 43, key, 10);  // Inserisco la key nel payload
}

/**
 * Inserisce il payload nel binario da infettare
 * @param phdr Ptr al primo blocco dei Program Header
 * @param i Indice del Program Header da infettare
 * @param binary binario da infettare
 * @param payload Struttura del payload
 * @param key chiave di cifratura
 */
void 	insert_payload32(Elf32_Phdr *phdr, int i, t_mem_image *binary, t_mem_image *payload, char *key)
{
	// Inserisco il payload nel binario
	Elf32_Ehdr *ehdr = binary->addr;
	Elf32_Off 	start = 0, offset = 0;

	if (phdr[i].p_offset + phdr[i].p_filesz >= binary->size)
		exit_error("Invalid program segment in header table", 30);
	start = phdr[i].p_vaddr + phdr[i].p_filesz;
	offset = ehdr->e_entry - (start + payload->size);
	// Modifico gli ultimi 4 byte del payload che si riferiscono alla funzione jmp
	*(Elf32_Word*)(payload->addr + payload->size - 4) = (Elf32_Word)offset;
	ehdr->e_entry = start;

	(void)key;
	//insert_decrypter_in_payload32(binary, payload, start, key);

	// Inserisco il payload nel binario
	memcpy(binary->addr + phdr[i].p_offset + phdr[i].p_filesz, payload->addr, payload->size);
	phdr[i].p_filesz += payload->size;
	phdr[i].p_memsz += payload->size;
}

/**
 * Ricerca la sezione indicata come parametro
 * @param name nome della sezione da ricercare
 * @param binary struttura del binario
 * @param size_section variabile da riempire per conoscere la size della sezione
 * @return l'indice della sezione altrimenti -1
 */
int 	find_section32(const char *name, t_mem_image *binary, size_t *size_section)
{
	Elf32_Ehdr	*cast_addr = binary->addr;
	Elf32_Shdr	*tmp = binary->addr + cast_addr->e_shoff;
	char 		*name_tmp = 0;

	for (Elf32_Half i = 0; i < cast_addr->e_shnum; ++i)
	{
		name_tmp = tmp[cast_addr->e_shstrndx].sh_offset + binary->addr + tmp[i].sh_name;
		if (!strcmp(name_tmp, name))
		{
			*size_section = tmp[i].sh_size;
			return i;
		}
	}
	return -1;
}

/**
 * Ricerca la sezione .text e viene criptata tramite l'algoritmo XOR Cipher
 * @param binary struttura del binario
 * @param key chiave per cifrare la sezione .text
 */
void	encrypt_text_section32(t_mem_image *binary, char *key)
{
	int				index_section = 0;
	size_t			size_text = 0;
	Elf32_Shdr		*text = binary->addr + ((Elf32_Ehdr*)binary->addr)->e_shoff;
	unsigned char	*tmp = 0;
	char 			*save_pos_key = key;

	if ((index_section = find_section32(".text", binary, &size_text)) == -1)
		exit_error("Section not found", 31);
	tmp = text[index_section].sh_offset + binary->addr;
	for (size_t i = 0; i < size_text; ++i)
	{
		tmp[i] ^= *key;
		key++;
		if (!(*key))
			key = save_pos_key;
	}
}

/**
 * Ricerca l'indirizzo virtuale del PT_LOAD
 * @param binary struttura del binario
 * @param error variabile di controllo per gli errori
 * @return l'indirizzo virtuale, in caso di errore setta error a -1
 */
Elf32_Addr	find_virtual_addr32(t_mem_image *binary, int *error)
{
	Elf32_Ehdr *ehdr = binary->addr;
	Elf32_Phdr *phdr = binary->addr + ehdr->e_phoff;

	for (size_t i = 0; i < ehdr->e_phnum; ++i)
	{
		if (phdr[i].p_type == PT_LOAD)
			return phdr[i].p_vaddr;
	}
	*error = -1;
	return 0;
}