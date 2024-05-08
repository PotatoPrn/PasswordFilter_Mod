// Windows Files
#include <Windows.h>
#include <NTSecAPI.h>

#include <stdio.h>

// Utils
#include "Utils.h"
#include <zxcvbn/zxcvbn.h>

#define LIBRARY_API __declspec(dllexport)

extern "C"
{
LIBRARY_API BOOLEAN PasswordFilter(PUNICODE_STRING PuniAccountName, PUNICODE_STRING PuniFullname, PUNICODE_STRING PuniPassword, BOOLEAN SetOperation);
}


BOOLEAN PasswordFilter(PUNICODE_STRING PuniAccountName, PUNICODE_STRING PuniFullname, PUNICODE_STRING PuniPassword, BOOLEAN SetOperation)
{
	BOOLEAN Status = FALSE;

	// Just for you, you know who .-.
	if (SetOperation != 0)
		return Status;


	// If Using Dict :/


	// Convert to Narrow String
	char* Password = PuniToChar(PuniPassword);
	char* Fullname = PuniToChar(PuniFullname);
	char* AccountName = PuniToChar(PuniAccountName);

	// Test User Dict
	// MMMM outdated non documented libraries make me want to kill my self : ^)
	int bruh = 0;
	const char* UserInput[] = {Fullname, AccountName, 0};
	zxcvbn_guesses_t yep = 0.0;
	bruh = zxcvbn_password_strength(Password, UserInput, &yep, 0);
	printf("%d\n", bruh);


	// Perform Check

	// Cleanup


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
