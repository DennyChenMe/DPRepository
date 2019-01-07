#pragma once
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include "IElfFile.h"

class CElfInfo
{
public:
	CElfInfo();
	CElfInfo(char * pszDexPathName);
	virtual ~CElfInfo();
private:
	char* readDexCont(char * pszDexPathName);
	void createElfObject(unsigned char* pElfBase);
public:
	unsigned int mDexSize;
	IElfFile* mElfFile;
	char* mpElfCont;

};
