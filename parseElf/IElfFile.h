#pragma once

#include "elf.h"
typedef struct _funcInfo32 {
	Elf32_Addr st_value;
	Elf32_Word st_size;
}funcInfo32;

typedef struct _funcInfo64 {
	Elf64_Addr st_value;
	Elf64_Word st_size;
}funcInfo64;

class IElfFile {
public:
	//�ļ�ͷ��ش���
	//ħ������0x7f ��ELF����
	virtual BOOL  getElfMagic(char szBuf[MAXBYTE]) = 0;
	//Elf Class 32 64
	virtual BOOL  getElfClass(char szBuf[MAXBYTE]) = 0;
	//Elf ���뷽ʽ
	virtual BOOL  getElfEncode(char szBuf[MAXBYTE]) = 0;
	//��ȡElf �İ汾
	virtual BOOL  getElfVersion(char szBuf[MAXBYTE]) = 0;
	//��ȡ����ֵ�����δʹ���ֽڵĿ�ʼ
	virtual BOOL  getElfABI(char szBuf[MAXBYTE]) = 0;
	virtual void printE_type() = 0;
	virtual void printE_Machine() = 0;
	virtual void printE_Version() = 0;
	virtual void printRemain() = 0;
	virtual void printEhd() = 0;
	virtual void initall() = 0;

	//����ͷ���
	virtual void printPhdTable() = 0;
	virtual void printPhdType(int p_Type) = 0;
	virtual void printPhdAttri(int p_Flags) = 0;
	//ͨ������ͷ ��ö�̬���ţ�һЩ�����ȣ���ƫ�ƺ����ݴ�С
	virtual int getTargetFuncInfo(const char *funcName, funcInfo32 *info) = 0;
	virtual void printFuncInfo(const char *funcName) = 0;
	//��ͷ���
	virtual void printShdTable() = 0;
	virtual void printShdType(int p_Type) = 0;
};