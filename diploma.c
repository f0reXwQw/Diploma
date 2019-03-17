#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define EI_NIDENT       16

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
	Elf32_Half    e_type;	   			/* Identifies object file type */
	Elf32_Half    e_machine;   			/* Specifies target instruction set architecture */
	Elf32_Word    e_version;   			/*  */
	Elf32_Addr    e_entry;     			/* Entry point */
	Elf32_Off     e_phoff;     			/* Points to the start of the program header table */
	Elf32_Off     e_shoff;     			/* Points to the start of the section header table */
	Elf32_Word    e_flags;     			/*  */
	Elf32_Half    e_ehsize;    			/* Size of this header */
	Elf32_Half    e_phentsize; 			/* Size of a program header table entry */
	Elf32_Half    e_phnum;     			/* Number of entries in the program header table */
	Elf32_Half    e_shentsize; 			/* Size of a section header table entry */
	Elf32_Half    e_shnum;     			/* Number of entries in the section header table */
	Elf32_Half    e_shstrndx;  			/* Index of the section header table entry that contains the section names */
}	Elf32_Ehdr;

/* 32-bit ELF program header. */
typedef struct elf32_Phdr
{
	Elf32_Word    p_type;
	Elf32_Off     p_offset;
	Elf32_Addr    p_vaddr;
	Elf32_Addr    p_paddr;
	Elf32_Word    p_filesz;
	Elf32_Word    p_memsz;
	Elf32_Word    p_flags;
	Elf32_Word    p_align;
}	Elf32_Phdr;

/* 32-bit ELF section header. */
typedef struct elf32_shdr 
{
	Elf32_Word    sh_name;				/* Section name, index in string tbl */
	Elf32_Word    sh_type;				/* Type of section */
	Elf32_Word    sh_flags;				/* Miscellaneous section attributes */
	Elf32_Addr    sh_addr;				/* Section virtual addr at execution */
	Elf32_Off 	  sh_offset;			/* Section file offset */
	Elf32_Word    sh_size;				/* Size of section in bytes */
	Elf32_Word    sh_link;				/* Index of another section */
	Elf32_Word    sh_info;				/* Additional section information */
	Elf32_Word    sh_addralign;			/* Section alignment */
	Elf32_Word    sh_entsize;			/* Entry size if section holds table */
}	Elf32_Shdr;

Elf32_Shdr get_shstrtab_hdr(FILE* ElfFile)
{
	Elf32_Ehdr elfHdr;
	Elf32_Shdr sectHdr;
	char* SectNames = NULL;

	fseek(ElfFile, 0, SEEK_SET);
	fread(&elfHdr, 1, sizeof(Elf32_Ehdr), ElfFile);

	fseek(ElfFile, elfHdr.e_shoff + elfHdr.e_shstrndx * sizeof(sectHdr), SEEK_SET);
	fread(&sectHdr, 1, sizeof(sectHdr), ElfFile); /* Read ELF section header (string table) */

	return sectHdr;
}

void create_section(FILE* ElfFile, unsigned char newSectName[], unsigned char newSectContent[])
{
	FILE* tempFile;
	Elf32_Shdr shstrtabHdr;
	Elf32_Ehdr elfHdr;
	Elf32_Shdr sectHdr;
	Elf32_Shdr newSectHdr;
	unsigned char* tempBuffer;

	if ((tempFile = fopen("tmpfile", "ab")) == NULL)
	{
		perror("[E] Error opening file");
    	exit(0);
	}

	fseek(ElfFile, 0, SEEK_SET);
	fread(&elfHdr, 1, sizeof(Elf32_Ehdr), ElfFile); // Read ELF file header

	shstrtabHdr = get_shstrtab_hdr(ElfFile); // Read shstrtab section header

	newSectHdr.sh_name = shstrtabHdr.sh_size;
	newSectHdr.sh_type = 1;
	newSectHdr.sh_flags = 0x06;
	newSectHdr.sh_addr = 0;
	newSectHdr.sh_offset = elfHdr.e_shoff + strlen(newSectName) + 1;
	newSectHdr.sh_size = strlen(newSectContent);
	newSectHdr.sh_link = 0;
	newSectHdr.sh_info = 0;
	newSectHdr.sh_addralign = 0x04;
	newSectHdr.sh_entsize = 0;

	tempBuffer = malloc(shstrtabHdr.sh_offset + shstrtabHdr.sh_size); 

	fseek(ElfFile, 0, SEEK_SET);
	fread(tempBuffer, 1, shstrtabHdr.sh_offset + shstrtabHdr.sh_size, ElfFile);
	fwrite(tempBuffer, 1, shstrtabHdr.sh_offset + shstrtabHdr.sh_size, tempFile);

	fwrite(newSectName, 1, strlen(newSectName) + 1, tempFile); // append new section name

	tempBuffer = realloc(tempBuffer, elfHdr.e_shoff - (shstrtabHdr.sh_offset + shstrtabHdr.sh_size));
	
	fseek(ElfFile, shstrtabHdr.sh_offset + shstrtabHdr.sh_size, SEEK_SET);
	fread(tempBuffer, 1, elfHdr.e_shoff - (shstrtabHdr.sh_offset + shstrtabHdr.sh_size), ElfFile);
	fwrite(tempBuffer, 1, elfHdr.e_shoff - (shstrtabHdr.sh_offset + shstrtabHdr.sh_size), tempFile);

	fwrite(newSectContent, 1, strlen(newSectContent)/*!!!!!!!!*/, tempFile); // append new section content

	tempBuffer = realloc(tempBuffer, elfHdr.e_shnum * sizeof(Elf32_Shdr));

	fseek(ElfFile, elfHdr.e_shoff, SEEK_SET);
	fread(tempBuffer, 1, elfHdr.e_shnum * sizeof(Elf32_Shdr), ElfFile);
	fwrite(tempBuffer, 1, elfHdr.e_shnum * sizeof(Elf32_Shdr), tempFile); // append all existing sections' headers

	fwrite(&newSectHdr, sizeof(Elf32_Shdr), 1, tempFile); // append new section header
	fclose(tempFile);
	
	//EDIT
	if ((tempFile = fopen("tmpfile", "r+b")) == NULL)
	{
		perror("[E] Error opening file");
    	exit(0);
	}

	Elf32_Off new_shoff = elfHdr.e_shoff + strlen(newSectName) + 1 + strlen(newSectContent) /*!!!!!!*/;
	fseek(tempFile, 0x20, SEEK_SET);
	fwrite(&new_shoff, sizeof(new_shoff), 1, tempFile); // change e_shoff

	Elf32_Half new_shnum = elfHdr.e_shnum + 1;
	fseek(tempFile, 0x30, SEEK_SET);
	fwrite(&new_shnum, sizeof(new_shnum), 1, tempFile); // increase number of sections by 1

	for (int i = 0; i < elfHdr.e_shnum; i++)
  	{
    	fseek(ElfFile, elfHdr.e_shoff + i * sizeof(sectHdr), SEEK_SET);
    	fread(&sectHdr, 1, sizeof(sectHdr), ElfFile);

    	if (sectHdr.sh_offset > shstrtabHdr.sh_offset) // if section after shstrtab section, 
    	{											   // increase offset by length of new section name
    		Elf32_Off new_offset = sectHdr.sh_offset + strlen(newSectName) + 1;
    		fseek(tempFile, new_shoff + i * sizeof(sectHdr) + 0x10, SEEK_SET);
    		fwrite(&new_offset, sizeof(new_offset), 1, tempFile);
    	}

    	if (i == elfHdr.e_shstrndx) // increase size of shstrtab section by length of new section name
    	{
    		Elf32_Word new_size = sectHdr.sh_size + strlen(newSectName) + 1;
    		fseek(tempFile, new_shoff + i * sizeof(sectHdr) + 0x14, SEEK_SET);
    		fwrite(&new_size, sizeof(new_size), 1, tempFile);
    	}
  	}
  	fclose(tempFile);
}

int main(int argc, char* argv[])
{

	FILE* ElfFile;

	if (argc != 2) 
	{
    	printf("Usage: %s <ELF_FILE>\n", argv[0]);
    	exit(0);
  	}

  	if ((ElfFile = fopen(argv[1], "r+b")) == NULL) 
  	{
    	perror("[E] Error opening file");
    	exit(0);
  	}

  	unsigned char newSectName[] = ".topkek";
  	unsigned char newSectContent[] = "Dobriy vecher, Aleksandr Vladimirovich";
  	create_section(ElfFile, newSectName, newSectContent);
	return 0;
}