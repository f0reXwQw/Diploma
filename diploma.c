#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define EI_NIDENT	16

/* 32-bit ELF base types. */
typedef unsigned int Elf32_Addr;
typedef unsigned short Elf32_Half;
typedef unsigned int Elf32_Off;
typedef signed int Elf32_Sword;
typedef unsigned int Elf32_Word;

/* 32-bit ELF file header. */
typedef struct elf32_hdr
{
	unsigned char e_ident[EI_NIDENT];	/* ELF "magic number" */
	Elf32_Half	e_type;					/* Identifies object file type */
	Elf32_Half	e_machine;				/* Specifies target instruction set architecture */
	Elf32_Word	e_version;				/*  */
	Elf32_Addr	e_entry;				/* Entry point */
	Elf32_Off	e_phoff;				/* Points to the start of the program header table */
	Elf32_Off	e_shoff;				/* Points to the start of the section header table */
	Elf32_Word	e_flags;				/*  */
	Elf32_Half	e_ehsize;				/* Size of this header */
	Elf32_Half	e_phentsize;			/* Size of a program header table entry */
	Elf32_Half	e_phnum;				/* Number of entries in the program header table */
	Elf32_Half	e_shentsize;			/* Size of a section header table entry */
	Elf32_Half	e_shnum;				/* Number of entries in the section header table */
	Elf32_Half	e_shstrndx;				/* Index of the section header table entry that contains the section names */
}	Elf32_Ehdr;

/* 32-bit ELF program header. */
typedef struct elf32_Phdr
{
	Elf32_Word	p_type;					/* Identifies segment type */
	Elf32_Off	p_offset;				/* Offset of the segment in the file image */
	Elf32_Addr	p_vaddr;				/* Virtual address of the segment in memory */
	Elf32_Addr	p_paddr;				/* Reserved for segment's physical address */
	Elf32_Word	p_filesz;				/* Size in bytes of the segment in the file image */
	Elf32_Word	p_memsz;				/* Size in bytes of the segment in memory */
	Elf32_Word	p_flags;				/* Segment-dependent flags */
	Elf32_Word	p_align;				/*  */
}	Elf32_Phdr;

/* 32-bit ELF section header. */
typedef struct elf32_shdr 
{
	Elf32_Word	sh_name;				/* Section name, index in string tbl */
	Elf32_Word	sh_type;				/* Type of section */
	Elf32_Word	sh_flags;				/* Miscellaneous section attributes */
	Elf32_Addr	sh_addr;				/* Section virtual addr at execution */
	Elf32_Off	sh_offset;				/* Section file offset */
	Elf32_Word	sh_size;				/* Size of section in bytes */
	Elf32_Word	sh_link;				/* Index of another section */
	Elf32_Word	sh_info;				/* Additional section information */
	Elf32_Word	sh_addralign;			/* Section alignment */
	Elf32_Word	sh_entsize;				/* Entry size if section holds table */
}	Elf32_Shdr;

typedef struct binary_str
{
	char* string;
	unsigned int length;
}	Binary_str;

unsigned char decryptor_template[31] = "\x60\x9c\xbe" "$$$$" "\x8b\xfe\xb9" "$$$$" "\xb3" "$" "\xac\x30\xd8\xaa\xe2\xfa\x9d\x61\xbd" "$$$$" "\xff\xe5";

Elf32_Ehdr get_elf_header(FILE* elf_file)
{
	Elf32_Ehdr elf_hdr;
	fseek(elf_file, 0, SEEK_SET);
	fread(&elf_hdr, 1, sizeof(elf_hdr), elf_file);
	return elf_hdr;
}

Elf32_Shdr get_section_hdr(FILE* elf_file, unsigned char* section_name)
{
	Elf32_Ehdr elf_hdr = get_elf_header(elf_file);;
	Elf32_Shdr section_hdr;

	if (strcmp(section_name, ".shstrtab") == 0)
	{
		fseek(elf_file, elf_hdr.e_shoff + elf_hdr.e_shstrndx * sizeof(section_hdr), SEEK_SET);
		fread(&section_hdr, 1, sizeof(section_hdr), elf_file); // Read ELF section header (string table)
		return section_hdr;
	}
	else
	{
		Elf32_Shdr shstrtab_hdr = get_section_hdr(elf_file, ".shstrtab");
		char* sections_names = malloc(shstrtab_hdr.sh_size);
		fseek(elf_file, shstrtab_hdr.sh_offset, SEEK_SET);
		fread(sections_names, 1, shstrtab_hdr.sh_size, elf_file); // Read all sections names

		for (int i = 0; i < elf_hdr.e_shnum; i++)
		{
			const char* name = "";
			fseek(elf_file, elf_hdr.e_shoff + i * sizeof(section_hdr), SEEK_SET);
			fread(&section_hdr, 1, sizeof(section_hdr), elf_file);
			if (section_hdr.sh_name);
			{
				name = sections_names + section_hdr.sh_name;
				if (strcmp(section_name, name) == 0)
					return section_hdr;
			}
		}
		printf("There is no section with '%s' name\n", section_name);
		exit(0);
	}
}

void create_segment(FILE* elf_file, Elf32_Phdr new_phdr)
{
	FILE* tmp_file;
	Elf32_Ehdr elf_hdr = get_elf_header(elf_file);
	Elf32_Shdr section_hdr;
	Elf32_Phdr program_hdr;
	unsigned char* tmp_buff;

	if ((tmp_file = fopen("tmpfile2", "w+b")) == NULL)
	{
		perror("[E] Error opening file");
		exit(0);
	}

	fseek(elf_file, 0, SEEK_END);
	unsigned int size_of_file = ftell(elf_file); // Get file size

	tmp_buff = malloc(elf_hdr.e_phoff + elf_hdr.e_phnum * sizeof(Elf32_Phdr));
	fseek(elf_file, 0, SEEK_SET);
	fread(tmp_buff, 1, elf_hdr.e_phoff + elf_hdr.e_phnum * sizeof(Elf32_Phdr), elf_file);
	fwrite(tmp_buff, 1, elf_hdr.e_phoff + elf_hdr.e_phnum * sizeof(Elf32_Phdr), tmp_file); // Write ELF hdr + all phdrs

	fwrite(&new_phdr, sizeof(Elf32_Phdr), 1, tmp_file); // Write new phdr

	tmp_buff = realloc(tmp_buff, size_of_file - (elf_hdr.e_phoff + elf_hdr.e_phnum * sizeof(Elf32_Phdr)));

	fseek(elf_file, elf_hdr.e_phoff + elf_hdr.e_phnum * sizeof(Elf32_Phdr), SEEK_SET);
	fread(tmp_buff, 1, size_of_file - (elf_hdr.e_phoff + elf_hdr.e_phnum * sizeof(Elf32_Phdr)), elf_file);
	fwrite(tmp_buff, 1, size_of_file - (elf_hdr.e_phoff + elf_hdr.e_phnum * sizeof(Elf32_Phdr)), tmp_file); // Write remainig

	free(tmp_buff);
	//EDIT

	Elf32_Off new_shoff = elf_hdr.e_shoff + sizeof(new_phdr);
	fseek(tmp_file, 0x20, SEEK_SET);
	fwrite(&new_shoff, sizeof(new_shoff), 1, tmp_file); // Change e_shoff

	Elf32_Half new_phnum = elf_hdr.e_phnum + 1;
	fseek(tmp_file, 0x2C, SEEK_SET);
	fwrite(&new_phnum, sizeof(new_phnum), 1, tmp_file); // Increase number of segments by 1

	for (int i = 0; i < elf_hdr.e_shnum; i++)
	{
		fseek(elf_file, elf_hdr.e_shoff + i * sizeof(section_hdr), SEEK_SET);
		fread(&section_hdr, 1, sizeof(section_hdr), elf_file);

		Elf32_Off new_offset = section_hdr.sh_offset + sizeof(new_phdr);
		fseek(tmp_file, new_shoff + i * sizeof(section_hdr) + 0x10, SEEK_SET);
		fwrite(&new_offset, sizeof(new_offset), 1, tmp_file); // Increase sections' offsets by size of new phdr
	}

	for (int i = 0; i < elf_hdr.e_phnum; i++)
	{
		fseek(elf_file, elf_hdr.e_phoff + i * sizeof(program_hdr), SEEK_SET);
		fread(&program_hdr, 1, sizeof(program_hdr), elf_file);

		if (program_hdr.p_type == 0x6) // Segment containing program header table itself
		{
			Elf32_Word new_filesz = program_hdr.p_filesz + sizeof(Elf32_Phdr);
			Elf32_Word new_memsz = program_hdr.p_memsz + sizeof(Elf32_Phdr);
			fseek(tmp_file, elf_hdr.e_phoff + i * sizeof(program_hdr) + 0x10, SEEK_SET);
			fwrite(&new_filesz, sizeof(new_filesz), 1, tmp_file); // Increase size in file
			fseek(tmp_file, elf_hdr.e_phoff + i * sizeof(program_hdr) + 0x14, SEEK_SET);
			fwrite(&new_memsz, sizeof(new_memsz), 1, tmp_file); // Increase size in memory
		}

		if (program_hdr.p_offset >= elf_hdr.e_phoff + elf_hdr.e_phnum * sizeof(Elf32_Phdr))
		{
			Elf32_Off new_offset = program_hdr.p_offset + sizeof(new_phdr);
			fseek(tmp_file, elf_hdr.e_phoff + i * sizeof(program_hdr) + 0x04, SEEK_SET);
			fwrite(&new_offset, sizeof(new_offset), 1, tmp_file); // Increase offset by size of new phdr
		}	
	}
	fclose(tmp_file);
}

void create_section(FILE* elf_file, unsigned char new_section_name[], Binary_str new_section_content, Elf32_Word section_type,
					Elf32_Word section_flags)
{
	FILE* tmp_file;
	Elf32_Ehdr elf_hdr = get_elf_header(elf_file);
	Elf32_Shdr shstrtab_hdr = get_section_hdr(elf_file, ".shstrtab");
	Elf32_Shdr section_hdr;
	Elf32_Shdr newsection_hdr;
	Elf32_Phdr program_hdr;
	unsigned char* tmp_buff;

	if ((tmp_file = fopen("tmpfile", "w+b")) == NULL)
	{
		perror("[E] Error opening file");
		exit(0);
	}

	tmp_buff = malloc(shstrtab_hdr.sh_offset + shstrtab_hdr.sh_size); 

	fseek(elf_file, 0, SEEK_SET);
	fread(tmp_buff, 1, shstrtab_hdr.sh_offset + shstrtab_hdr.sh_size, elf_file);
	fwrite(tmp_buff, 1, shstrtab_hdr.sh_offset + shstrtab_hdr.sh_size, tmp_file); // Append until shstrtab end

	fwrite(new_section_name, 1, strlen(new_section_name) + 1, tmp_file); // Append new section name

	tmp_buff = realloc(tmp_buff, elf_hdr.e_shoff - (shstrtab_hdr.sh_offset + shstrtab_hdr.sh_size));
	
	fseek(elf_file, shstrtab_hdr.sh_offset + shstrtab_hdr.sh_size, SEEK_SET);
	fread(tmp_buff, 1, elf_hdr.e_shoff - (shstrtab_hdr.sh_offset + shstrtab_hdr.sh_size), elf_file);
	// Append between shstrtab and sections' headers
	fwrite(tmp_buff, 1, elf_hdr.e_shoff - (shstrtab_hdr.sh_offset + shstrtab_hdr.sh_size), tmp_file);

	fwrite(new_section_content.string, 1, new_section_content.length, tmp_file); // Append new section content

	tmp_buff = realloc(tmp_buff, elf_hdr.e_shnum * sizeof(Elf32_Shdr));

	fseek(elf_file, elf_hdr.e_shoff, SEEK_SET);
	fread(tmp_buff, 1, elf_hdr.e_shnum * sizeof(Elf32_Shdr), elf_file);
	fwrite(tmp_buff, 1, elf_hdr.e_shnum * sizeof(Elf32_Shdr), tmp_file); // Append all existing sections' headers

	free(tmp_buff);

	//EDIT BEGIN

	Elf32_Off new_shoff = elf_hdr.e_shoff + strlen(new_section_name) + 1 + new_section_content.length;
	fseek(tmp_file, 0x20, SEEK_SET);
	fwrite(&new_shoff, sizeof(new_shoff), 1, tmp_file); // Change e_shoff

	Elf32_Half new_shnum = elf_hdr.e_shnum + 1;
	fseek(tmp_file, 0x30, SEEK_SET);
	fwrite(&new_shnum, sizeof(new_shnum), 1, tmp_file); // Increase number of sections by 1

	Elf32_Addr max_section_addr = 0;
	Elf32_Word section_size = 0;

	for (int i = 0; i < elf_hdr.e_shnum; i++)
	{
		fseek(elf_file, elf_hdr.e_shoff + i * sizeof(section_hdr), SEEK_SET);
		fread(&section_hdr, 1, sizeof(section_hdr), elf_file);

		if (section_hdr.sh_addr > max_section_addr)
		{
			max_section_addr = section_hdr.sh_addr; // Calc virtual adress. Mb wrong way
			section_size = section_hdr.sh_size;
		}

		if (section_hdr.sh_offset > shstrtab_hdr.sh_offset)	// if section after shstrtab section, 
		{													// increase offset by length of new section name
			Elf32_Off new_offset = section_hdr.sh_offset + strlen(new_section_name) + 1;
			fseek(tmp_file, new_shoff + i * sizeof(section_hdr) + 0x10, SEEK_SET);
			fwrite(&new_offset, sizeof(new_offset), 1, tmp_file);
		}

		if (i == elf_hdr.e_shstrndx) // increase size of shstrtab section by length of new section name
		{
			Elf32_Word new_size = section_hdr.sh_size + strlen(new_section_name) + 1;
			fseek(tmp_file, new_shoff + i * sizeof(section_hdr) + 0x14, SEEK_SET);
			fwrite(&new_size, sizeof(new_size), 1, tmp_file);
		}
	}
	//EDIT END

	newsection_hdr.sh_name = shstrtab_hdr.sh_size;
	newsection_hdr.sh_type = section_type;
	newsection_hdr.sh_flags = section_flags;
	newsection_hdr.sh_addr = max_section_addr + section_size;
	newsection_hdr.sh_offset = elf_hdr.e_shoff + strlen(new_section_name) + 1;
	newsection_hdr.sh_size = new_section_content.length;
	newsection_hdr.sh_link = 0;
	newsection_hdr.sh_info = 0;
	newsection_hdr.sh_addralign = 0x04;
	newsection_hdr.sh_entsize = 0;

	fseek(tmp_file, 0, SEEK_END);
	fwrite(&newsection_hdr, sizeof(Elf32_Shdr), 1, tmp_file); // append new section header
	fclose(tmp_file);
}

void encrypt_section(FILE* elf_file, unsigned char* section_name)
{
	Elf32_Shdr section_hdr = get_section_hdr(elf_file, section_name);
	unsigned char* section_content = malloc(section_hdr.sh_size);
	fseek(elf_file, section_hdr.sh_offset, SEEK_SET);
	fread(section_content, 1, section_hdr.sh_size, elf_file);
	for (int i = 0; i < section_hdr.sh_size; i++)
		section_content[i] ^= 0x66;
	fseek(elf_file, section_hdr.sh_offset, SEEK_SET);
	fwrite(section_content, 1, section_hdr.sh_size, elf_file);
}

void set_ep(FILE* elf_file, Elf32_Addr entry_point)
{
	fseek(elf_file, 0x18, SEEK_SET);
	fwrite(&entry_point, sizeof(Elf32_Addr), 1, elf_file);
}

int main(int argc, char* argv[])
{
	FILE* elf_file;
	FILE* tmp_file;
	Elf32_Ehdr elf_hdr;
	Elf32_Shdr section_hdr;
	Elf32_Shdr shstrtab_hdr;
	Binary_str new_section_content;
	Elf32_Phdr phdr;

	if (argc != 2) 
	{
		printf("Usage: %s <ELF_FILE>\n", argv[0]);
		exit(0);
	}

	if ((elf_file = fopen(argv[1], "r+b")) == NULL) 
	{
		perror("[E] Error opening file");
		exit(0);
	}

	new_section_content.string = malloc(31);
	memcpy(new_section_content.string, decryptor_template, 31);
	new_section_content.length = 31;

	elf_hdr = get_elf_header(elf_file);
	section_hdr = get_section_hdr(elf_file, ".text");

	unsigned char key = 0x66;

	memcpy(new_section_content.string +  3, (unsigned char*)&(section_hdr.sh_addr), sizeof(Elf32_Addr));
	memcpy(new_section_content.string + 10, (unsigned char*)&(section_hdr.sh_size), sizeof(Elf32_Word));
	memcpy(new_section_content.string + 15, (unsigned char*)&(key), sizeof(unsigned char));
	memcpy(new_section_content.string + 25, (unsigned char*)&(section_hdr.sh_addr), sizeof(Elf32_Addr));

	create_section(elf_file, ".topkek", new_section_content, 1, 6);
	tmp_file = fopen("tmpfile", "r+b");
	encrypt_section(tmp_file, ".text");

	section_hdr = get_section_hdr(tmp_file, ".topkek");
	set_ep(tmp_file, section_hdr.sh_addr);

	Elf32_Phdr new_phdr;
	new_phdr.p_type = 1;
	new_phdr.p_offset = section_hdr.sh_offset + sizeof(new_phdr);
	new_phdr.p_vaddr = section_hdr.sh_addr;
	new_phdr.p_paddr = section_hdr.sh_addr;
	new_phdr.p_filesz = section_hdr.sh_size;
	new_phdr.p_memsz = section_hdr.sh_size;
	new_phdr.p_flags = 5;
	new_phdr.p_align = 0x1000;

	create_segment(tmp_file, new_phdr);

	fclose(tmp_file);
	fclose(elf_file);
	return 0;
}