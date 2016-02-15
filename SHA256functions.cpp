#include <cstdint>

uint32_t rotateLeft(uint32_t x, uint32_t i) {
    return (x<<i) | (x>>(-i&31));;
}

uint32_t rotateRight(uint32_t x, uint32_t i) {
    return (x>>i) | (x<<(-i&31));
}

//SHA256 functions
uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x&y)^(~x&z);
}

uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x&y)^(x&z)^(y&z);
}

uint32_t upperSigmaZero(uint32_t x) {
    return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
}

uint32_t upperSigmaOne(uint32_t x) {
    return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
}

uint32_t lowerSigmaZero(uint32_t x) {
    return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
}

uint32_t lowerSigmaOne(uint32_t x) {
    return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
}