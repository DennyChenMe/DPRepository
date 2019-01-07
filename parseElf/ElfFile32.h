#pragma once
#include "CElfInfo.h"
#include "IElfFile.h"

class ElfFile32 :public IElfFile{
public:
	ElfFile32(unsigned char* pszPathName);
	virtual ~ElfFile32();

private:
	unsigned char* baseAddr;
	Elf32_Ehdr* pEhdr;
	DWORD m_dwShNum;
	Elf32_Shdr* pSectionHdr;
	DWORD m_dwPhNum;
	Elf32_Phdr* pProgmHdr;

public:
	//魔法数（0x7f “ELF”）
	virtual BOOL  getElfMagic(char szBuf[MAXBYTE]);
	//Elf Class 32 64
	virtual BOOL  getElfClass(char szBuf[MAXBYTE]);
	//Elf 编码方式
	virtual BOOL  getElfEncode(char szBuf[MAXBYTE]);
	//获取Elf 的版本
	virtual BOOL  getElfVersion(char szBuf[MAXBYTE]);
	//获取对齐值，标记未使用字节的开始
	virtual BOOL  getElfABI(char szBuf[MAXBYTE]);
	virtual void printE_type();
	virtual void printE_Machine();
	virtual void printE_Version();
	virtual void printRemain();
	virtual void printEhd();
	virtual void initall();
	//程序头相关
	virtual void printPhdTable();
	virtual void printPhdType(int p_Type);
	virtual void printPhdAttri(int p_Flags);
	//通过程序头 获得动态符号（一些函数等）的偏移和内容大小
	virtual int getTargetFuncInfo(const char *funcName, funcInfo32 *info);
	virtual void printFuncInfo(const char *funcName);
	//通过加载段（相当于PE的节）和rva获得fa
	Elf32_Addr Rva2Fa(Elf32_Addr rva);
	//节头相关
	virtual void printShdTable();
	virtual void printShdType(int p_Type);
};