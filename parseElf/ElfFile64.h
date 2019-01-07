#pragma once

#include "IElfFile.h"

class ElfFile64 : public IElfFile
{
public:
	ElfFile64(unsigned char* pszPathName);
	virtual ~ElfFile64();
private:
	unsigned char* baseAddr;
	Elf64_Ehdr* pEhdr;
	Elf64_Shdr* pSectionHdr;
	Elf64_Phdr* pProgmHdr;
	DWORD m_dwShNum;
	DWORD m_dwPhNum;
public:
	//ħ������0x7f ��ELF����
	virtual BOOL  getElfMagic(char szBuf[MAXBYTE]);
	//Elf Class 32 64
	virtual BOOL  getElfClass(char szBuf[MAXBYTE]);
	//Elf ���뷽ʽ
	virtual BOOL  getElfEncode(char szBuf[MAXBYTE]);
	//��ȡElf �İ汾
	virtual BOOL  getElfVersion(char szBuf[MAXBYTE]);
	//��ȡ����ֵ�����δʹ���ֽڵĿ�ʼ
	virtual BOOL  getElfABI(char szBuf[MAXBYTE]);
	virtual void printE_type();
	virtual void printE_Machine();
	virtual void printE_Version();
	virtual void printRemain();
	virtual void printEhd();
	virtual void initall();
	//����ͷ���
	virtual void printPhdTable();
	virtual void printPhdType(int p_Type);
	virtual void printPhdAttri(int p_Flags);
	//ͨ������ͷ ��ö�̬���ţ�һЩ�����ȣ���ƫ�ƺ����ݴ�С
	virtual int getTargetFuncInfo(const char *funcName, funcInfo32 *info);
	virtual void printFuncInfo(const char *funcName);
	//ͨ�����ضΣ��൱��PE�Ľڣ���rva���fa
	Elf64_Addr Rva2Fa(Elf64_Addr rva);
	//��ͷ���
	virtual void printShdTable();
	virtual void printShdType(int p_Type);
};

