#include <iostream>
#include <Windows.h>
#include <SubAuth.h>

using _FilterPassword = BOOLEAN(*)(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN IsSet);


PUNICODE_STRING ConvertToPuni(char* Character)
{
	int Len = MultiByteToWideChar(CP_UTF8, 0, Character, -1, NULL, 0);

	PWSTR StringAlloc = static_cast<PWSTR>(LocalAlloc(LMEM_ZEROINIT, Len * sizeof(WCHAR)));

	MultiByteToWideChar(CP_UTF8, 0, Character, -1, StringAlloc, Len);

	PUNICODE_STRING Value = static_cast<PUNICODE_STRING>(LocalAlloc(LMEM_ZEROINIT, sizeof(UNICODE_STRING)));
	Value->Buffer = StringAlloc;
	Value->Length = Len;
	Value->MaximumLength = Len;

	return Value;
}


int main()
{
	// Passfilt.dll
	// Build Project in 32bit if using 32bit Passfilt.dll & ViseVersa

	_FilterPassword FilterPassword =
			reinterpret_cast<_FilterPassword>(GetProcAddress(LoadLibrary("PassfiltLib.dll"), "PasswordFilter"));


	PUNICODE_STRING AccountName, Fullname, Password;
	AccountName = ConvertToPuni("Fuck");
	Fullname = ConvertToPuni("You");
	Password = ConvertToPuni("Cunt");

	bool Result = FilterPassword(AccountName, Fullname, Password, 0);

	printf("Password Strong > %s\n", Result ? "True" : "False");


	return 0;
}
