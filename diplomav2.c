#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

unsigned char decryptor_template[31] = 
{
	0x60, /* pushad */
	0x9c, /* pushfd */
	0xbe, 0x00, 0x00, 0x00, 0x00, /* mov esi, <beginning of the fragment being decoded> */
	0x8b, 0xfe, /* mov edi, esi */
	0xb9, 0x00, 0x00, 0x00, 0x00, /* mov ecx, <length of fragment> */
	0xb3, 0x00, /* mov bl, <key> */
	0xac, /* lodsb */
	0x30, 0xd8, /* xor al, bl */
	0xaa, /* stosb */
	0xe2, 0xfa, /* loop to lodsb */
	0x9d, /* popfd */
	0x61, /* popad */
	0xbd, 0x00, 0x00, 0x00, 0x00, /* mov ebp, <original entry point> */
	0xff, 0xe5 /* jmp ebp */
};

unsigned char key = 0x66;

int find_section(void* elf, unsigned char* section_name)
{
	Elf32_Ehdr* ehdr;
	Elf32_Shdr* shdr;

	ehdr = (Elf32_Ehdr*) elf;
	shdr = (Elf32_Shdr*) (elf + ehdr->e_shoff);
	for (int i = 0; i < ehdr->e_shnum; i++)
		if (!strcmp(section_name, elf + (shdr[ehdr->e_shstrndx].sh_offset + shdr[i].sh_name)))
			return i;
	return -1;
}

void encrypt_section(void* elf, int section_ind)
{
	Elf32_Ehdr* ehdr;
	Elf32_Shdr* shdr;
	ehdr = (Elf32_Ehdr*) elf;
	shdr = (Elf32_Shdr*) (elf + ehdr->e_shoff);
	for (int i = shdr[section_ind].sh_offset; i < (shdr[section_ind].sh_offset + shdr[section_ind].sh_size); i++)
		*((unsigned char *)(elf + i)) = *((unsigned char*)(elf + i)) ^ key;
}

int find_note_segment(Elf32_Phdr const *phdr, int count)
{
	for (int i = 0; i < count; i++)
	{
		if (phdr[i].p_type == PT_NOTE)
			return i;
	}
	return -1;
}

static void bail(char const *prefix, char const *msg)
{
	fprintf(stderr, "%s: %s\n", prefix, msg);
	exit(EXIT_FAILURE);
}

void* map_file(char const *file_name)
{
	struct stat file_stat;
	void* ptr;
	int fd;

	fd = open(file_name, O_RDWR);
	if (fd < 0)
		bail(file_name, strerror(errno));
	if (fstat(fd, &file_stat))
		bail(file_name, strerror(errno));
	if (!S_ISREG(file_stat.st_mode))
		bail(file_name, "not an ordinary file.");
	ptr = mmap(NULL, file_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED)
		bail(file_name, strerror(errno));
	close(fd);
	return ptr;
}

int main(int argc, char* argv[])
{
	unsigned char* elf;
	unsigned char* decryptor;
	Elf32_Ehdr* ehdr;
	Elf32_Phdr* phdr;
	Elf32_Shdr* shdr;
	int note_ind;
	int text_ind;

	if (argc != 2) 
		bail("Usage", "./dplm <ELF_FILE>");
	elf = map_file(argv[1]);
	if (memcmp(elf, ELFMAG, SELFMAG))
		bail(argv[1], "not an ELF file.");
	if (elf[EI_CLASS] != ELFCLASS32)
		bail(argv[1], "not a 32-bit ELF file.");
	ehdr = (Elf32_Ehdr*) elf;
	if (ehdr->e_type != ET_EXEC)
		bail(argv[1], "not an executable file.");

	phdr = (Elf32_Phdr*) (elf + ehdr->e_phoff);
	shdr = (Elf32_Shdr*) (elf + ehdr->e_shoff);
	note_ind = find_note_segment(phdr, ehdr->e_phnum);
	if (note_ind == -1)
		bail(argv[1], "unable to find a usable infection point");

	text_ind = find_section(elf, ".text");
	encrypt_section(elf, text_ind);
	phdr[note_ind].p_type = PT_LOAD; // set PT_NOTE to PT_LOAD
	phdr[note_ind].p_flags = PF_X | PF_W; // set executable and writable flags
	
	//Init decryptor
	decryptor = malloc(sizeof(decryptor_template));
	memcpy(decryptor, decryptor_template, sizeof(decryptor_template));
	memcpy(decryptor +  3, (unsigned char*) &shdr[text_ind].sh_addr, sizeof(Elf32_Addr));
	memcpy(decryptor + 10, (unsigned char*) &shdr[text_ind].sh_size, sizeof(Elf32_Word));
	memcpy(decryptor + 15, (unsigned char*) &key, sizeof(key));
	memcpy(decryptor + 25, (unsigned char*) &shdr[text_ind].sh_addr, sizeof(Elf32_Addr));

	//Copy decryptor to PT_NOTE segment
	memset(elf + phdr[note_ind].p_offset, 0x00, phdr[note_ind].p_filesz);
	memcpy(elf + phdr[note_ind].p_offset, decryptor, sizeof(decryptor_template));

	ehdr->e_entry = phdr[note_ind].p_vaddr; // set EP
	return 0;
}