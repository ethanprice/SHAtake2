#ifndef SHA256functions
#define SHA256functions

std::array<uint32_t, 64> generateSHA256_K();

std::array<uint32_t, 64> generateSHA224_H0()
std::array<uint32_t, 8> generateSHA256_H0(); 

uint32_t rotateLeft(uint32_t x, uint32_t i);

uint32_t rotateRight(uint32_t x, uint32_t i);

//SHA functions
uint32_t ch(uint32_t x, uint32_t y, uint32_t z);

uint32_t maj(uint32_t x, uint32_t y, uint32_t z);

uint32_t upperSigmaZero(uint32_t x);

uint32_t upperSigmaOne(uint32_t x);

uint32_t lowerSigmaZero(uint32_t x);

uint32_t lowerSigmaOne(uint32_t x);

#endif