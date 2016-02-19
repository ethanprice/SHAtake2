#ifndef SHA256computation
#define SHA256computation

std::array<uint32_t, 8>& computeSHA256(std::vector<char>& messageBuffer, std::array<uint32_t, 8>& hashValue, bool SHA224);

#endif