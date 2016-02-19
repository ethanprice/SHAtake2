/*
SHAtake2 is an implementation of the SHA256 hashing standard. 
At least -O1 and -flto optimization are recommended.
C++11 features are used, and using the -std=c++11 flag is likely required to compile.	
*/

#include <iostream>
#include <vector>
#include <array>
#include <fstream>
#include <string>
#include <chrono>
#include "SHA256functions.h"
#include "SHA256computation.h"


std::array<unsigned char, 8> uint64ToBigEndianBytes(uint64_t x) {
    std::array<unsigned char, 8> bytes;
	bytes[0] = (x >> 56) & 0xFF;
	bytes[1] = (x >> 48) & 0xFF;
	bytes[2] = (x >> 40) & 0xFF;
	bytes[3] = (x >> 32) & 0xFF;
	bytes[4] = (x >> 24) & 0xFF;
    bytes[5] = (x >> 16) & 0xFF;
    bytes[6] = (x >> 8) & 0xFF;
    bytes[7] = x & 0xFF;
    return bytes;
}

int main(int argc, char* argv[]) {
	const uint32_t CHUNK_SIZE = 1024;
	
    if(argc<2) {
        std::cout << "Please enter the file name as an argument.\n";
        return 1;
    }

    //start timer
    auto timer1 = std::chrono::high_resolution_clock::now();

    //initialize hash with SHA constants
    std::array<uint32_t, 8> hashValue = SHA256functions::generateSHA256_H0();  

    //open file
    std::ifstream ifile (argv[1], std::ifstream::binary);
    if(!ifile) {
        std::cout << "File not found.\n";
        return 1;
    }

    // preprocess (create tail to append):
    std::vector<unsigned char> messageTail;

    //append '1' bit
    messageTail.push_back(0x80);

    //append length diff
    ifile.seekg (0, ifile.end);
    uint64_t ifileSize = ifile.tellg();
    ifile.seekg (0, ifile.beg);
    uint32_t numPaddingBytes = (56 - ifileSize%64)%64-1;
    if (numPaddingBytes == 0) {
        numPaddingBytes = 64;
    }
    for(uint32_t x=0; x<numPaddingBytes; x++) {
        messageTail.push_back(0x0);
    }

    //append filesize
    std::array<unsigned char, 8> ifileSizeBytes = uint64ToBigEndianBytes((ifileSize*8));
    for(uint32_t x=0; x<8; x++) {
        messageTail.push_back(ifileSizeBytes[x]);
    }


    //create buffer, and process the file in chunks (multiplied by 64 to ensure a full SHA round completes
    std::vector<char> messageBuffer(CHUNK_SIZE*64);
	while(ifile.read(messageBuffer.data(), messageBuffer.size())) {
		hashValue = SHA256computation::computeSHA256(messageBuffer, hashValue);
	}
	
	//append tail to file, process last chunk
	int bytesRead = ifile.gcount();
	messageBuffer.resize(bytesRead);
	for (unsigned char i : messageTail) {
		messageBuffer.push_back(i);
	}
	hashValue = SHA256computation::computeSHA256(messageBuffer, hashValue);
	
	
    std::cout << "Final hash value: ";
    for (int t=0; t<8; t++) {
        std::cout << std::hex << hashValue[t] << " ";
    }
    std::cout << "\n";
    ifile.close();
	
    //stop timer
    auto timer2 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> runtime = timer2 - timer1;
    float throughput = (ifileSize/1000)/runtime.count();
    std::cout << "Throughput: " << throughput << " MB/s";
    return 0;
}