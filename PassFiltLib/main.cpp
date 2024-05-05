// Windows Files
#include <Windows.h>
#include <NTSecAPI.h>

#include <stdio.h>

// zxcvbn-c
#include "zxcvbn.h"

// Utils
#include "Utils.h"


#define LIBRARY_API __declspec(dllexport)

extern "C"
{
LIBRARY_API BOOLEAN PasswordFilter(PUNICODE_STRING PuniAccountName, PUNICODE_STRING PuniFullname, PUNICODE_STRING PuniPassword, BOOLEAN SetOperation);
}


BOOLEAN PasswordFilter(PUNICODE_STRING PuniAccountName, PUNICODE_STRING PuniFullname, PUNICODE_STRING PuniPassword, BOOLEAN SetOperation)
{
	// If Using Dict :/
	if (!ZxcvbnInit("zxcvbn.dict"))
	{
		printf("Error Loading Dict File");
		return FALSE;
	}


	// Convert to Narrow String
	char* Password = PuniToChar(PuniPassword);
	char* Fullname = PuniToChar(PuniFullname);
	char* AccountName = PuniToChar(PuniAccountName);


	// Perform Check
	auto CarryCheck = [&]() -> BOOLEAN
	{
		// Variables
		ZxcMatch_t *Info;
		double Entropy;

	};

	CarryCheck();

	// Cleanup

	ZxcvbnUnInit();


	return 1;
}


// Just needed to load the CRT Libs
void main()
{
};
