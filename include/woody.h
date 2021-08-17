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
 * Utils
 */
void 	exit_error(const char *msg, int exit_code);
void 	*map_file_in_memory(const char *file_path, size_t *size_file);
int 	check_elf(t_mem_image *binary);
void 	*copy_file(t_mem_image *org, size_t *size);
char	*ft_substr(char const *s, unsigned int start, size_t len);

/*
 * 64bit
 */
void 		*extractor_payload64(const char *filepath, size_t *size);
int			find_section_to_infect64(Elf64_Phdr *phdr, int n_phdr, size_t size_payload);
void 		insert_payload64(Elf64_Phdr *phdr, int i, t_mem_image *binary, t_mem_image *payload, char *key);
int 		find_section(const char *name, t_mem_image *binary, size_t *size_section);
void		encrypt_text_section64(t_mem_image *binary, char *key);
Elf64_Addr	find_virtual_addr64(t_mem_image *binary, int *error);
void 		insert_decrypter_in_payload(t_mem_image *binary, t_mem_image *payload, Elf64_Off start, char *key);

#endif