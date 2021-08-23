#include "../include/woody.h"

void 	compress_file(char *file)
{
	int fd_source = open(file, O_RDWR);
	int size = lseek(fd_source, 0, SEEK_END);
	void *source = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_source, 0);
	close(fd_source);

	size_t name_size = strlen(file) + 11;
	char *name_compress = malloc(name_size);
	memcpy(name_compress, file, strlen(file));
	memcpy(name_compress + strlen(file), "_compress", 9);

	int fd_dest = open(name_compress, O_RDWR | O_CREAT, 0777);
	uLong comp_size = compressBound(size);
	write(fd_dest, source, size);
	void *dest = mmap(0, comp_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_dest, 0);
	close(fd_dest);
	memset(dest, 0, size);

	if ((compress((Bytef *)dest, &comp_size, (Bytef *)source, size)) != Z_OK )
		exit_error("File compression error", 34);

	munmap(source, size);
	munmap(dest, comp_size);
	free(name_compress);
	exit(0);
}

void 	decompress_file(char *file)
{
	int fd_source = open(file, O_RDWR);
	int size = lseek(fd_source, 0, SEEK_END);
	void *source = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_source, 0);
	close(fd_source);

	size_t name_size = strlen(file) + 12;
	char *name_decompress = malloc(name_size);
	memcpy(name_decompress, file, strlen(file));
	memcpy(name_decompress + strlen(file), "_decompress", 11);
	int fd_dest = open(name_decompress, O_RDWR | O_CREAT, 0777);
	uLong decomp_size = compressBound(size);
	write(fd_dest, source, size);
	void *dest = mmap(0, decomp_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_dest, 0);
	close(fd_dest);
	memset(dest, 0, size);
	uLong tmp_size = size;

	if ((uncompress((Bytef *)dest, &tmp_size, (Bytef *)source, decomp_size)) != Z_OK )
		exit_error("File decompression error", 35);

	munmap(source, size);
	munmap(dest, decomp_size);
	free(name_decompress);
	exit(0);
}