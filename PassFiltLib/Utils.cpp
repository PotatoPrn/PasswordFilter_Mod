#include "Utils.h"



char* PuniToChar(PUNICODE_STRING PString)
{
	size_t OrigSize = wcslen(PString->Buffer) + 1;
	size_t ConvertedChar = 0;
	size_t NewSize = OrigSize * 2;
	char* PasswordString = new char[NewSize];
	wcstombs_s(&ConvertedChar, PasswordString, NewSize, PString->Buffer, _TRUNCATE);
	return PasswordString;
}