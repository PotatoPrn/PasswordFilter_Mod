// Windows Files
#include <Windows.h>
#include <NTSecAPI.h>

#include <iostream>

// Utils
#include "Utils.h"
#include "zxcppvbn.hpp"

extern "C"
{
__declspec(dllexport) BOOLEAN _fastcall PasswordFilter(PUNICODE_STRING PuniAccountName, PUNICODE_STRING PuniFullname, PUNICODE_STRING PuniPassword, BOOLEAN SetOperation);
}


BOOLEAN _fastcall PasswordFilter(PUNICODE_STRING PuniAccountName, PUNICODE_STRING PuniFullname, PUNICODE_STRING PuniPassword, BOOLEAN SetOperation)
{
	BOOLEAN Status = TRUE;

	// Just for you f3rnos
	if (SetOperation != 0)
	{
		return Status;
	}


	// Convert to Narrow String
	char* Password = PuniToChar(PuniPassword);
	char* Fullname = PuniToChar(PuniFullname);
	char* AccountName = PuniToChar(PuniAccountName);


	// This only contains a basic check via password entropy, i want to implement the user & password strcompare etc etc
	// Perform Check
	zxcppvbn Zxcvbn;
	zxcppvbn::result Result = Zxcvbn(Password);

	printf("Strength > %d\n", Result.score);

	if (Result.score < 4)
	{
		Status = FALSE;
	}

	// Username & Account name to password comparison
	char* CompCheck = strstr(_strupr(Password), _strupr(Fullname));
	if (CompCheck != 0)
	{
		printf("Password Contains Username\n");
		Status = FALSE;;
	}

	delete[] Password;
	delete[] Fullname;
	delete[] AccountName;


	return Status;
}


// Just needed to load the CRT Libs
int main()
{
	return 1;
};
