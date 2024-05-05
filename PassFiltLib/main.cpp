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
	BOOLEAN Status = FALSE;

	if (SetOperation != 0)
	{
		Status = FALSE;
	}
	else
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

		const char* UserDict[] =
		{
			Fullname, AccountName,
			0
		};

		// Test User Dict

		// Perform Check
		auto CarryCheck = [&]() -> BOOLEAN
		{
			// Using zxcvbn test for testing, unsure of capabilities
			// Variables
			ZxcMatch_t *Info, *p;
			double Entropy;
			double m = 0.0;
			int PasswordLen, CheckLen;

			Entropy = ZxcvbnMatch(Password, UserDict, &Info);


			for (p = Info; p; p = p->Next)
				m += p->Entrpy;

			PasswordLen = strlen(Password);

			m = Entropy - m;

			printf("Password %s \nLength %d\nEntropy bits=%.3f log10=%.3f\nMulti-word extra bits=%.1f\n",
				Password, PasswordLen, Entropy, Entropy * 0.301029996, m);

			p = Info;
			CheckLen = 0;

			while (p)
			{
				switch ((int)p->Type)
				{
				case BRUTE_MATCH: printf("  Type: Bruteforce     ");
					break;
				case DICTIONARY_MATCH: printf("  Type: Dictionary     ");
					break;
				case DICT_LEET_MATCH: printf("  Type: Dict+Leet      ");
					break;
				case USER_MATCH: printf("  Type: User Words     ");
					break;
				case USER_LEET_MATCH: printf("  Type: User+Leet      ");
					break;
				case REPEATS_MATCH: printf("  Type: Repeated       ");
					break;
				case SEQUENCE_MATCH: printf("  Type: Sequence       ");
					break;
				case SPATIAL_MATCH: printf("  Type: Spatial        ");
					break;
				case DATE_MATCH: printf("  Type: Date           ");
					break;
				case YEAR_MATCH: printf("  Type: Year           ");
					break;
				case LONG_PWD_MATCH: printf("  Type: Extra-long     ");
					break;
				case BRUTE_MATCH + MULTIPLE_MATCH: printf("  Type: Bruteforce(Rep)");
					break;
				case DICTIONARY_MATCH + MULTIPLE_MATCH: printf("  Type: Dictionary(Rep)");
					break;
				case DICT_LEET_MATCH + MULTIPLE_MATCH: printf("  Type: Dict+Leet(Rep) ");
					break;
				case USER_MATCH + MULTIPLE_MATCH: printf("  Type: User Words(Rep)");
					break;
				case USER_LEET_MATCH + MULTIPLE_MATCH: printf("  Type: User+Leet(Rep) ");
					break;
				case REPEATS_MATCH + MULTIPLE_MATCH: printf("  Type: Repeated(Rep)  ");
					break;
				case SEQUENCE_MATCH + MULTIPLE_MATCH: printf("  Type: Sequence(Rep)  ");
					break;
				case SPATIAL_MATCH + MULTIPLE_MATCH: printf("  Type: Spatial(Rep)   ");
					break;
				case DATE_MATCH + MULTIPLE_MATCH: printf("  Type: Date(Rep)      ");
					break;
				case YEAR_MATCH + MULTIPLE_MATCH: printf("  Type: Year(Rep)      ");
					break;
				case LONG_PWD_MATCH + MULTIPLE_MATCH: printf("  Type: Extra-long(Rep)");
					break;

				default: printf("  Type: Unknown%d ", p->Type);
					break;
				}

				CheckLen += p->Length;
				// Carry out next check
				p = p->Next;
			}
			printf("Entropy > %f\n", m);
			ZxcvbnFreeInfo(Info);

			return FALSE;
		};

		Status = CarryCheck();

		// Cleanup

		ZxcvbnUnInit();
	}

	return Status;
}


// Just needed to load the CRT Libs
void main()
{
};
