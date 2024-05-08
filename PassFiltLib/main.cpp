// Windows Files
#include <Windows.h>
#include <NTSecAPI.h>

#include <iostream>

// Utils
#include "Utils.h"
#include "zxcppvbn.hpp"

#define LIBRARY_API __declspec(dllexport)

extern "C"
{
LIBRARY_API BOOLEAN PasswordFilter(PUNICODE_STRING PuniAccountName, PUNICODE_STRING PuniFullname, PUNICODE_STRING PuniPassword, BOOLEAN SetOperation);
}


void render_match(const zxcppvbn::match& match)
{
	std::cout << "  token: " << match.token << std::endl;;
	std::cout << "   pattern: ";
	switch (match.pattern)
	{
	case zxcppvbn::pattern::L33T:
		std::cout << "L33T";
		break;
	case zxcppvbn::pattern::DICTIONARY:
		std::cout << "DICTIONARY";
		break;
	case zxcppvbn::pattern::SPATIAL:
		std::cout << "SPATIAL";
		break;
	case zxcppvbn::pattern::REPEAT:
		std::cout << "REPEAT";
		break;
	case zxcppvbn::pattern::SEQUENCE:
		std::cout << "SEQUENCE";
		break;
	case zxcppvbn::pattern::DATE:
		std::cout << "DATE";
		break;
	case zxcppvbn::pattern::BRUTEFORCE:
		std::cout << "BRUTEFORCE";
		break;
	}
	std::cout << ", i: " << match.i << ", j: " << match.j;
	std::cout << ", entropy: " << match.entropy << std::endl;
	switch (match.pattern)
	{
	case zxcppvbn::pattern::L33T:
		std::cout << "   subs: " << match.sub_display;
		std::cout << ", l33t entropy: " << match.l33t_entropy << std::endl;
	case zxcppvbn::pattern::DICTIONARY:
		std::cout << "   dictionary: " << match.dictionary_name;
		std::cout << ", word: " << match.matched_word;
		std::cout << ", rank: " << match.rank;
		std::cout << ", base entropy: " << match.base_entropy;
		std::cout << ", uppercase entropy: " << match.uppercase_entropy << std::endl;
		break;
	case zxcppvbn::pattern::SPATIAL:
		std::cout << "   keyboard: " << match.graph;
		std::cout << ", turns: " << match.turns;
		std::cout << ", shift count: " << match.shifted_count << std::endl;
		break;
	case zxcppvbn::pattern::REPEAT:
		std::cout << "   repeated char: " << match.repeated_char << std::endl;
		break;
	case zxcppvbn::pattern::SEQUENCE:
		std::cout << "   sequence name: " << match.sequence_name;
		std::cout << ", sequence space: " << match.sequence_space;
		std::cout << ", ascending: " << match.ascending << std::endl;
		break;
	case zxcppvbn::pattern::DATE:
		std::cout << "   year: " << match.year;
		std::cout << ", month: " << match.month;
		std::cout << ", day: " << match.day;
		std::cout << ", separator: " << match.separator << std::endl;
		break;
	case zxcppvbn::pattern::BRUTEFORCE:
		std::cout << "   cardinality: " << match.cardinality << std::endl;
		break;
	}
}

void render_result(const zxcppvbn::result& result)
{
	std::cout << "password: " << result.password << std::endl;
	std::cout << " entropy: " << result.entropy;
	std::cout << ", crack time: " << result.crack_time_display << " (" << result.crack_time.count() << " s)";
	std::cout << ", score: " << result.score;
	std::cout << ", calculation time: " << result.calc_time.count() << " ms" << std::endl;
	std::cout << " matches: " << std::endl;
	for (auto& match: result.matches)
	{
		render_match(*match);
	}
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
	zxcppvbn Zxcvbn;
	zxcppvbn::result result = Zxcvbn(Password);
	render_result(result);


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
