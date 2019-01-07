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
	//打印文件类型
	virtual void printE_type();
	//打印elf所对应的cpu类型，常见的是arm和x86
	virtual void printE_Machine();
	virtual void printE_Version();
	//打印elf文件头中剩余的项
	virtual void printRemain();
	//整合上面的函数将文件头信息全部打印出来
	virtual void printEhd();
	//初始化程序头表结构体变量、节头表结构体变量以及程序头个数、节头个数
	virtual void initall();
	//程序头相关
	virtual void printPhdTable();
	virtual void printPhdType(int p_Type);
	virtual void printPhdAttri(int p_Flags);
	//通过程序头 获得动态符号（一些函数等）的偏移和内容大小，结果存在info中，如果是需要链接进来的函数，则则都是0
	virtual int getTargetFuncInfo(const char *funcName, funcInfo32 *info);
	//通过elf中动态符号文件，查找对应的函数体字节所对应的文件偏移及大小
	virtual void printFuncInfo(const char *funcName);
	//通过加载段（相当于PE的节）和rva获得fa
	Elf32_Addr Rva2Fa(Elf32_Addr rva);
	//节头相关
	virtual void printShdTable();
	virtual void printShdType(int p_Type);
};
