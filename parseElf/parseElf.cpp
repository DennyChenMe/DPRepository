// parseElf.cpp : �������̨Ӧ�ó������ڵ㡣
//
#include "CElfInfo.h"
int main()
{
	//CElfInfo elfInfo("D:\\elftest");
	CElfInfo elfInfo("D:\\_bisect.so");
	//elfInfo.mElfFile->printEhd();
	//elfInfo.mElfFile->printPhdTable();
	//elfInfo.mElfFile->printShdTable();
	elfInfo.mElfFile->printFuncInfo("PyInt_FromSsize_t");
    return 0;
}

