#include "../include/woody.h"

// nasm -f win32 file.s
// link /subsystem:console /defaultlib:kernel32.lib /entry:start file.obj

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