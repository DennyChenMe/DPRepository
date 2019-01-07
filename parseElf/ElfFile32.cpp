#include "ElfFile32.h"
#include <stdio.h>

ElfFile32::ElfFile32(unsigned char* pszPathName) {
	baseAddr = pszPathName;
	initall();
}

ElfFile32::~ElfFile32(){}

void ElfFile32::initall() {
	if (baseAddr == NULL)
	{
		return;
	}
	try
	{
		pEhdr = (Elf32_Ehdr*)baseAddr;
		m_dwShNum = pEhdr->e_shnum;
		pSectionHdr = (Elf32_Shdr*)(baseAddr + pEhdr->e_shoff);
		m_dwPhNum = pEhdr->e_phnum;
		pProgmHdr = (Elf32_Phdr*)(baseAddr + pEhdr->e_phoff);
	}
	catch (...)
	{
	}
}

void ElfFile32::printEhd() {
	if (!IS_ELF(*pEhdr))
	{
		return;
	}
	char szBuf[MAXBYTE];
	memset(szBuf, 0, MAXBYTE);
	getElfMagic(szBuf);
	printf("Magic: %s\r\n", szBuf);

	memset(szBuf, 0, MAXBYTE);
	getElfClass(szBuf);
	printf("Class: %s\r\n", szBuf);

	memset(szBuf, 0, MAXBYTE);
	getElfEncode(szBuf);
	printf("BigOrSmall: %s\r\n", szBuf);

	memset(szBuf, 0, MAXBYTE);
	getElfVersion(szBuf);
	printf("ElfVersion: %s\r\n", szBuf);

	memset(szBuf, 0, MAXBYTE);
	getElfABI(szBuf);
	printf("ElfABI: %s\r\n", szBuf);

	printE_type();
	printE_Machine();
	printE_Version();
	printRemain();
}



//魔法数（0x7f “ELF”）
BOOL  ElfFile32::getElfMagic(char szBuf[MAXBYTE]) {
	unsigned char* pszIdent = pEhdr->e_ident;
	memmove(szBuf, pszIdent, 4);
	memset(szBuf + 4, 0, 1);
	return TRUE;
}
//Elf Class 32 64
BOOL  ElfFile32::getElfClass(char szBuf[MAXBYTE]) {
	int nFlagCls = (int)pEhdr->e_ident[EI_CLASS];
	char* pszTmp = NULL;
	switch (nFlagCls)
	{
	case ELFCLASSNONE:
		pszTmp = "invalid";
		break;
	case ELFCLASS32:
		pszTmp = "32-bit objs";
		break;
	case ELFCLASS64:
		pszTmp = "64-bit objs";
		break;
	case ELFCLASSNUM:
		pszTmp = "number of classes";
		break;
	}
	if (pszTmp != NULL) {
		memmove(szBuf, pszTmp, strlen(pszTmp));
		memset(szBuf + strlen(szBuf), 0, 1);
		return TRUE;
	}
	return FALSE;
}

//Elf 编码方式
BOOL  ElfFile32::getElfEncode(char szBuf[MAXBYTE]) {
	int nData = pEhdr->e_ident[EI_DATA];
	char* psz = "invalid";
	if (nData == ELFDATA2LSB) {
		psz = "Little-Endian";
	}else if (nData == ELFDATA2MSB){
		psz = "Big-Endian";
	}
	memmove(szBuf, psz, strlen(psz));
	memset(szBuf + strlen(szBuf), 0, 1);
	return TRUE;
}

/* Invalid */
/* Current */
/* number of versions */
//获取Elf 的版本
BOOL  ElfFile32::getElfVersion(char szBuf[MAXBYTE]) {
	int nData = pEhdr->e_ident[EI_VERSION];
	char* psz = "invalid";
	if (nData == EV_CURRENT) {
		psz = "Current";
	}
	memmove(szBuf, psz, strlen(psz));
	memset(szBuf + strlen(szBuf), 0, 1);
	return TRUE;
}
//获取对齐值，标记未使用字节的开始
BOOL  ElfFile32::getElfABI(char szBuf[MAXBYTE]) {
	int nABI = pEhdr->e_ident[EI_OSABI];
	char* psz = "invalid";
	switch (nABI)
	{
	case ELFOSABI_SYSV: { psz = "UNIX System V ABI"; break; }
	case ELFOSABI_HPUX: { psz = "HP-UX operating system"; break; }
	case ELFOSABI_NETBSD: { psz = "NetBSD"; break; }
	case ELFOSABI_LINUX: { psz = "GNU/Linux"; break; }
	case ELFOSABI_HURD: { psz = "GNU/Hurd"; break; }
	case ELFOSABI_86OPEN: { psz = "86Open common IA32 ABI"; break; }
	case ELFOSABI_SOLARIS: { psz = "Solaris"; break; }
	case ELFOSABI_MONTEREY: { psz = "Monterey"; break; }
	case ELFOSABI_IRIX: { psz = "IRIX"; break; }
	case ELFOSABI_FREEBSD: { psz = "FreeBSD"; break; }
	case ELFOSABI_TRU64: { psz = "TRU64 UNIX"; break; }
	case ELFOSABI_MODESTO: { psz = "Novell Modesto"; break; }
	case ELFOSABI_OPENBSD: { psz = "OpenBSD"; break; }
	case ELFOSABI_ARM: { psz = "ARM"; break; }
	case ELFOSABI_STANDALONE: { psz = "Standalone (embedded) application"; break; }
	}
	memmove(szBuf, psz, strlen(psz));
	memset(szBuf + strlen(szBuf), 0, 1);
	return TRUE;
}

void ElfFile32::printE_type() {
	//pEhdr->e_type == 
	char* psz = "No file type";
	switch (pEhdr->e_type) {
	case ET_NONE: { psz = "No file type"; break; }
	case ET_REL: { psz = "relocatable file"; break; }
	case ET_EXEC: { psz = "executable file"; break; }
	case ET_DYN: { psz = "shared object file"; break; }
	case ET_CORE: { psz = "core file"; break; }
	case ET_NUM: { psz = "number of types"; break; }
	case ET_LOPROC: { psz = "reserved range for processor"; break; }
	case ET_HIPROC: { psz = "specific e_type"; break; }
	}
	printf("file_type: %s\r\n" ,psz);
}

void ElfFile32::printE_Machine() {
	//pEhdr->e_type == 
	char* psz = "No file type";
	switch (pEhdr->e_machine) {
	case EM_NONE: { psz = "No Machine"; break; }
	case EM_M32: { psz = "AT&T WE 32100"; break; }
	case EM_SPARC: { psz = "SPARC"; break; }
	case EM_386: { psz = "Intel 80386"; break; }
	case EM_68K: { psz = "Motorola 68000"; break; }
	case EM_88K: { psz = "Motorola 88000"; break; }
	case EM_486: { psz = "Intel 80486 - unused?"; break; }
	case EM_860: { psz = "Intel 80860"; break; }
	case EM_MIPS: { psz = "MIPS R3000 Big-Endian only"; break; }
	case EM_MIPS_RS4_BE: { psz = "MIPS R4000 Big-Endian"; break; }
	case EM_SPARC64: { psz = "SPARC v9 64-bit unoffical"; break; }
	case EM_PARISC: { psz = "HPPA"; break; }
	case EM_SPARC32PLUS: { psz = "Enhanced instruction set SPARC"; break; }
	case EM_PPC: { psz = "PowerPC"; break; }
	case EM_ARM: { psz = "Advanced RISC Machines ARM"; break; }
	case EM_ALPHA: { psz = "DEC ALPHA"; break; }
	case EM_SPARCV9: { psz = "SPARC version 9"; break; }
	case EM_ALPHA_EXP: { psz = "DEC ALPHA"; break; }
	case EM_AMD64: { psz = "AMD64 architecture"; break; }
	case EM_VAX: { psz = "DEC VAX"; break; }
	}
	printf("e_machine: %s\r\n", psz);
}

void ElfFile32::printE_Version() {
	//pEhdr->e_type == 
	char* psz = "No file type";
	switch (pEhdr->e_version) {
	case EV_NONE: { psz = "Invalid"; break; }
	case EV_CURRENT: { psz = "Current"; break; }
	case EV_NUM: { psz = "number of versions"; break; }
	}
	printf("e_version: %s\r\n", psz);
}

void ElfFile32::printRemain() {
	printf("虚拟入口地址：   e_entry: 0x%x\r\n"
		"程序表偏移：     e_phoff: 0x%x\r\n"
		"节表偏移：       e_shoff: 0x%x\r\n"
		"处理器特殊标志： e_flags: 0x%x\r\n"
		"ELF头部大小：    e_ehsize: 0x%x\r\n"
		"程序头表单个大小:e_phentsize: 0x%x\r\n"
		"程序头表数量：   e_phnum: 0x%x\r\n"
		"节表单个大小：   e_shentsize: 0x%x\r\n"
		"节表数量：       e_shnum: 0x%x\r\n"
		"字符串表所在节Id:e_shstrndx: 0x%x\r\n"
		, pEhdr->e_entry,
		pEhdr->e_phoff,
		pEhdr->e_shoff,
		pEhdr->e_flags,
		pEhdr->e_ehsize,
		pEhdr->e_phentsize,
		pEhdr->e_phnum,
		pEhdr->e_shentsize,
		pEhdr->e_shnum,
		pEhdr->e_shstrndx);
}

void ElfFile32::printPhdTable() {
	for (unsigned int i = 0; i < m_dwPhNum; i ++)
	{
		printf("%d :\r\n", i);
		printPhdType(pProgmHdr[i].p_type);
		printPhdAttri(pProgmHdr[i].p_flags);
		printf("segment offset       :p_offset:%x\r\n"
			"segment va           :p_vaddr:%x\r\n"
			"physical address     :p_paddr:%x\r\n"
			"seg bytes num in file:p_filesz:%x\r\n"
			"seg bytes num in mem :p_memsz:%x\r\n"
			"flags                :p_flags:%x\r\n"
			"memory alignment     :p_align:%x\r\n\r\n",
			pProgmHdr[i].p_offset,
			pProgmHdr[i].p_vaddr,
			pProgmHdr[i].p_paddr,
			pProgmHdr[i].p_filesz,
			pProgmHdr[i].p_memsz,
			pProgmHdr[i].p_flags,
			pProgmHdr[i].p_align);
	}
}


void ElfFile32::printPhdType(int p_Type) {
	char* psz = "unused";
	switch (p_Type) {
	case PT_NULL: { psz = "unused"; break; }
	case PT_LOAD: { psz = "loadable segment"; break; }
	case PT_DYNAMIC: { psz = "dynamic linking section"; break; }
	case PT_INTERP: { psz = "the RTLD"; break; }
	case PT_NOTE: { psz = "auxiliary information"; break; }
	case PT_SHLIB: { psz = "reserved - purpose undefined"; break; }
	case PT_PHDR: { psz = "program header"; break; }
	case PT_NUM: { psz = "Number of segment types"; break; }
	case PT_LOOS: { psz = "reserved range for OS"; break; }
	case PT_HIOS: { psz = " specific segment types"; break; }
	case PT_LOPROC: { psz = "reserved range for processor"; break; }
	case PT_HIPROC: { psz = " specific segment types"; break; }
	}
	printf("segment type:%s\r\n", psz);
}


void ElfFile32::printPhdAttri(int p_Flags) {
	int AryFlags[4] = { PF_X, PF_W, PF_R, PF_MASKPROC};
	char* AryDesc[4] = {"Executable", "Writable", "Readable", "reserved bits for processo"};
	for (int i = 0; i < 4; i ++)
	{
		if (p_Flags & AryFlags[i])
		{
			printf("%s ",AryDesc[i]);
		}
	}
	printf("\r\n");
}

void ElfFile32::printShdTable() {
	for (unsigned int i = 0; i < m_dwShNum; i++)
	{
		printf("%d\r\n", i);
		printShdType(pSectionHdr[i].sh_type);
		printf(
			"sh_name      :%x\r\n"
			"sh_type      :%x\r\n"
			"sh_flags     :%x\r\n"
			"sh_addr      :%x\r\n"
			"sh_offset    :%x\r\n"
			"sh_size      :%x\r\n"
			"sh_link      :%x\r\n"
			"sh_info      :%x\r\n"
			"sh_addralign :%x\r\n"
			"Single Size:sh_entsize   :%x\r\n",
			pSectionHdr[i].sh_name,
			pSectionHdr[i].sh_type,
			pSectionHdr[i].sh_flags,
			pSectionHdr[i].sh_addr,
			pSectionHdr[i].sh_offset,
			pSectionHdr[i].sh_size,
			pSectionHdr[i].sh_link,
			pSectionHdr[i].sh_info,
			pSectionHdr[i].sh_addralign,
			pSectionHdr[i].sh_entsize
		);
	}
}

void ElfFile32::printShdType(int p_Type) {
	char* psz = " inactive ";
	switch (p_Type) {
	case SHT_NULL: { psz = " inactive "; break; }
	case SHT_PROGBITS: { psz = " program defined information "; break; }
	case SHT_SYMTAB: { psz = " symbol table section "; break; }
	case SHT_STRTAB: { psz = " string table section "; break; }
	case SHT_RELA: { psz = " relocation section with addends"; break; }
	case SHT_HASH: { psz = " symbol hash table section "; break; }
	case SHT_DYNAMIC: { psz = " dynamic section "; break; }
	case SHT_NOTE: { psz = " note section "; break; }
	case SHT_NOBITS: { psz = " no space section "; break; }
	case SHT_REL: { psz = " relation section without addends "; break; }
	case SHT_SHLIB: { psz = " reserved - purpose unknown "; break; }
	case SHT_DYNSYM: { psz = " dynamic symbol table section "; break; }
	case SHT_NUM: { psz = " number of section types "; break; }
	case SHT_LOPROC: { psz = " reserved range for processor "; break; }
	case SHT_HIPROC: { psz = "  specific section header types "; break; }
	case SHT_LOUSER: { psz = " reserved range for application "; break; }
	case SHT_HIUSER: { psz = "  specific indexes "; break; }
	}
	printf("section type:%s\r\n",psz);
}

int ElfFile32::getTargetFuncInfo(const char *funcName, funcInfo32 *info) {
	char flag = -1, *dynstr;
	int i;
	Elf32_Off dyn_vaddr;
	Elf32_Word dyn_size, dyn_strsz;
	Elf32_Dyn *dyn;
	Elf32_Addr dyn_symtab, dyn_strtab, dyn_hash;
	Elf32_Sym *funSym;
	unsigned funHash, nbucket;
	unsigned *bucket, *chain;
	int mod;
	Elf32_Phdr* phdr = pProgmHdr;
	//    __android_log_print(ANDROID_LOG_INFO, "JNITag", "phdr =  0x%p, size = 0x%x\n", phdr, ehdr->e_phnum);
	for (i = 0; i < m_dwPhNum; ++i) {
		//		__android_log_print(ANDROID_LOG_INFO, "JNITag", "phdr =  0x%p\n", phdr);
		if (phdr->p_type == PT_DYNAMIC) {
			flag = 0;
			printf("Find .dynamic segment");
			break;
		}
		phdr++;
	}
	if (flag)
		return -1;
	int nOffset = phdr->p_offset;
	nOffset = Rva2Fa(phdr->p_vaddr);
	dyn_vaddr = (Elf32_Addr)(nOffset + baseAddr);
	dyn_size = phdr->p_filesz;
	flag = 0;
	for (dyn = (Elf32_Dyn*)dyn_vaddr; (Elf32_Addr)dyn < dyn_vaddr + dyn_size; dyn++){
		if (dyn->d_tag == DT_HASH){
			flag += 1;
			dyn_hash = dyn->d_un.d_ptr;
		}
		else if (dyn->d_tag == DT_STRTAB){
			flag += 2;
			dyn_strtab = dyn->d_un.d_ptr;
		}
		else if (dyn->d_tag == DT_SYMTAB){
			flag += 4;
			dyn_symtab = dyn->d_un.d_ptr;
		}
		else if (dyn->d_tag == DT_STRSZ) {
			flag += 8;
			dyn_strsz = dyn->d_un.d_val;
		}
	}
	if (flag & 0x0f != 0x0f){
		printf("Find needed .section failed\n");
		return -1;
	}
	dyn_hash = Rva2Fa(dyn_hash) + (Elf32_Addr)baseAddr;
	dyn_strtab = Rva2Fa(dyn_strtab) + (Elf32_Addr)baseAddr;
	dyn_symtab = Rva2Fa(dyn_symtab) + (Elf32_Addr)baseAddr;
	funHash = elf_hash(funcName);
	funSym = (Elf32_Sym *)dyn_symtab;
	dynstr = (char*)dyn_strtab;
	nbucket = *(unsigned*)dyn_hash;
	bucket = (unsigned*)(dyn_hash + 8);
	chain = bucket + nbucket;
	flag = -1;
	mod = (funHash % nbucket);

	for (int i = bucket[mod]; i != 0; i = chain[i]){
		if (strcmp(funSym[i].st_name + dynstr, funcName) == 0) {
			flag = 0;
			break;
		}
	}
	if (flag != 0) {
		return -1;
	}
	info->st_value = funSym[i].st_value;
	info->st_size = funSym[i].st_size;
	return 0;
}

void ElfFile32::printFuncInfo(const char *funcName) {
	funcInfo32 info;
	getTargetFuncInfo(funcName, &info);
	printf("offset:%0x, size:%0x\r\n", info.st_value, info.st_size);
}

Elf32_Addr ElfFile32::Rva2Fa(Elf32_Addr rva) {
	Elf32_Phdr* phdr = pProgmHdr;
	for (int i = 0; i < m_dwPhNum; ++i) {
		if (phdr->p_type == PT_LOAD) {
			if (phdr->p_vaddr <= rva && rva <= phdr->p_vaddr+ phdr->p_memsz) {
				return rva - phdr->p_vaddr + phdr->p_offset;
			}
		}
		phdr++;
	}
	return -1;
}

