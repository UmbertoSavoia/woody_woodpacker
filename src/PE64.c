#include "../include/woody.h"

// nasm -f win32 file.s
// link /subsystem:console /defaultlib:kernel32.lib /entry:start file.obj

/**
 * Ricerca la sezione da infettare (.text) e controlla se ha abbastanza spazio per il payload
 * @param binary struttura del binario
 * @param pe_file struttura contenente le informazioni sul binario
 * @param payload payload
 * @param new_entry valore da modificare con la nuova entry
 * @return l'indice della sezione text o -1 in caso di errore
 */
int 	find_section_to_infect_PE64(t_mem_image *binary, t_pe_file *pe_file, t_mem_image *payload, uint32_t *new_entry)
{
	int i = 0;
	uint32_t offset = 0, count = 0;
	unsigned char *section_ptr = 0;

	if (!(payload->addr = malloc(49)))
		exit_error("Error malloc", 33);
	payload->size = PAYLOAD_PE_SIZE;
	memcpy(payload->addr, PAYLOAD_PE, PAYLOAD_PE_SIZE);

	// Cerco la sezione .text
	for (i = 0; i < pe_file->num_sections; ++i)
		if (!memcmp(pe_file->sections[i].Name, ".text", 5))
			break;
	if (i > pe_file->num_sections)
		return -1;
	// Verifico se è disponibile abbastanza spazio
	section_ptr = binary->addr + pe_file->sections[i].PointerToRawData;
	for(uint32_t j = 0; j < pe_file->sections[i].SizeOfRawData; ++j, ++section_ptr)
	{
		if (*section_ptr == 0x00)
		{
			if (count == 0)
				offset = pe_file->sections[i].PointerToRawData + j;
			count++;
			if (count == payload->size)
				break;
		}
		else
			count = 0;
	}
	if (count == 0)
		return -1;
	*new_entry = offset;
	return i;
}

void 	insert_payload_PE64(t_mem_image *binary, t_pe_file *pe_file, int index_section, t_mem_image *payload, uint32_t new_entry)
{
	uint32_t original_entry = pe_file->optional_hdr->AddressOfEntryPoint + pe_file->optional_hdr->ImageBase;

	// modifico l'entry nel binario
	pe_file->optional_hdr->AddressOfEntryPoint = new_entry + pe_file->sections[index_section].VirtualAddress - pe_file->sections[index_section].PointerToRawData;
	//memcpy(payload->addr - 4, &original_entry, sizeof(uint32_t));
	// inserisco nel payload l'indirizzo della vecchia entry
	*(uint32_t *)(payload->addr + payload->size - 4) = (uint32_t )original_entry;
	// copio il payload nel binario
	memcpy(binary->addr + new_entry, payload->addr, payload->size);

	puts("");
	for(int i = 0; i < PAYLOAD_PE_SIZE; ++i)
		printf("%x ", ((unsigned char*)payload->addr)[i]);
	puts("");
}