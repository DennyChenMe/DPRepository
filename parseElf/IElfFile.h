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
	//文件头相关处理
	//魔法数（0x7f “ELF”）
	virtual BOOL  getElfMagic(char szBuf[MAXBYTE]) = 0;
	//Elf Class 32 64
	virtual BOOL  getElfClass(char szBuf[MAXBYTE]) = 0;
	//Elf 编码方式
	virtual BOOL  getElfEncode(char szBuf[MAXBYTE]) = 0;
	//获取Elf 的版本
	virtual BOOL  getElfVersion(char szBuf[MAXBYTE]) = 0;
	//获取对齐值，标记未使用字节的开始
	virtual BOOL  getElfABI(char szBuf[MAXBYTE]) = 0;
	virtual void printE_type() = 0;
	virtual void printE_Machine() = 0;
	virtual void printE_Version() = 0;
	virtual void printRemain() = 0;
	virtual void printEhd() = 0;
	virtual void initall() = 0;

	//程序头相关
	virtual void printPhdTable() = 0;
	virtual void printPhdType(int p_Type) = 0;
	virtual void printPhdAttri(int p_Flags) = 0;
	//通过程序头 获得动态符号（一些函数等）的偏移和内容大小
	virtual int getTargetFuncInfo(const char *funcName, funcInfo32 *info) = 0;
	virtual void printFuncInfo(const char *funcName) = 0;
	//节头相关
	virtual void printShdTable() = 0;
	virtual void printShdType(int p_Type) = 0;
};