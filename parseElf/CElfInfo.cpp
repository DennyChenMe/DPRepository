#include "CElfInfo.h"
#include "elf.h"
#include "ElfFile32.h"
#include "ElfFile64.h"

CElfInfo::CElfInfo()
{
}

CElfInfo::CElfInfo(char * pszElfPathName)
{
	unsigned char* pElfBase = (unsigned char*)readDexCont(pszElfPathName);
	if (pElfBase != NULL)
	{
		createElfObject(pElfBase);
	}
	else {
		mElfFile = NULL;
	}
}

void CElfInfo::createElfObject(unsigned char* pElfBase) {
	if (pElfBase[EI_CLASS] == ELFCLASS32) {
		mElfFile = new ElfFile32(pElfBase);
	}
	else if(pElfBase[EI_CLASS] == ELFCLASS64) {
		mElfFile = new ElfFile64(pElfBase);
	}
	else {
		mElfFile = NULL;
	}
}

char* CElfInfo::readDexCont(char * pszElfPathName) {
	FILE *fp;
	fopen_s(&fp, pszElfPathName, (const char*)"rb+");
	if (fp == NULL)
	{
		return NULL;
	}
	fseek(fp, 0, SEEK_END);
	int nFileSize = ftell(fp);
	//mDexSize = nFileSize;
	char* buffer = new char[nFileSize];
	if (buffer == NULL)
	{
		goto EXIT;
	}
	fseek(fp, SEEK_SET, 0);
	mDexSize = fread(buffer, 1, nFileSize, fp);
	
EXIT:
	fclose(fp);
	return buffer;
}

CElfInfo::~CElfInfo()
{
	if (mElfFile != NULL) {
		delete mElfFile;
		mElfFile = NULL;
	}
	if (mpElfCont != NULL) {
		delete mpElfCont;
		mpElfCont = NULL;
	}
}
