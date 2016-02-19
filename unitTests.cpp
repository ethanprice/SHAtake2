#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"
#include "SHA256computation.h"
#include "SHA256functions.h"
#include <vector>

TEST_CASE( "test vector \"abc\"") {
	//message "abc"
	std::vector<char> message = {0x61,0x62,0x63,0x80,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0x18};
	
	//SHA256
	std::array<uint32_t, 8> testHash = SHA256functions::generateSHA256_H0(); 
	std::array<uint32_t, 8> verifiedHash = {0xba7816bf,0x8f01cfea,0x414140de,0x5dae2223,0xb00361a3,0x96177a9c,0xb410ff61,0xf20015ad, };
	
    REQUIRE( SHA256computation::computeSHA256(message, testHash, false) == verifiedHash);
}
