#include <iostream>
#include <Windows.h>
#include <SubAuth.h>
#include <lmcons.h>

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


int main(int argc, char* argv[])
{
	// Passfilt.dll
	// Build Project in 32bit if using 32bit Passfilt.dll & ViseVersa
	if (argc != 2)
	{
		printf("Input Password");
		exit(1);
	}

	// Get Username
	char Username[UNLEN+1];
	RtlZeroMemory(Username, UNLEN+1);
	DWORD UsernameLen[UNLEN+1];
	GetUserName(Username, UsernameLen);

	// Get Account/Computer Name
	char ComputerName[UNLEN+1];
	DWORD ComputerNameLen[UNLEN+1];
	RtlZeroMemory(ComputerName, UNLEN + 1);
	GetComputerName(ComputerName, ComputerNameLen);

	_FilterPassword FilterPassword =
			reinterpret_cast<_FilterPassword>(GetProcAddress(LoadLibrary("PassFiltLib.dll"), "PasswordFilter"));


	PUNICODE_STRING AccountName, Fullname, Password;
	AccountName = ConvertToPuni(ComputerName);
	Fullname = ConvertToPuni(Username);
	Password = ConvertToPuni(argv[1]);

	printf("Input Results Username > %s, Accountname > %s, Password > %s\n", Username, ComputerName, argv[1]);

	bool Result = FilterPassword(AccountName, Fullname, Password, 0);

	printf("Password Strong > %s\n", Result ? "True" : "False");


	return 0;
}
