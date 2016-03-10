#ifndef SHA256computation
#define SHA256computation

std::vector<unsigned char> createSHA256MessageTail(std::istream& ifile);
std::array<uint32_t, 8>& computeSHA256(std::vector<char>& messageBuffer, std::array<uint32_t, 8>& hashValue);

#endif