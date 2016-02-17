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

uint32_t bytesToInt(unsigned char x0,unsigned char x1,unsigned char x2,unsigned char x3) {
    return (x0<<24)|(x1<<16)|(x2<<8)|(x3);
}

//SHA processing function
std::array<uint32_t, 8>& processingSHA256(std::vector<char>& messageBuffer, std::array<uint32_t, 8>& hashValue){
	//working variables
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    std::array<uint32_t, 64> w;
	
	const std::array<uint32_t, 64> k = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
	0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
	0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d,
	0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
	0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585,
	0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa,
	0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};
	
	for (uint32_t x=0; x<(messageBuffer.size()/64); x++) {
		//create a 64-entry message schedule array w[0..63] of 32-bit words
		//fill 0-15 with the message chunks
		for (int t=0; t<16; t++) {
			w[t] = bytesToInt(messageBuffer[x*64+t*4+0],messageBuffer[x*64+t*4+1],messageBuffer[x*64+t*4+2],messageBuffer[x*64+t*4+3]);
		}
		//fill the rest of w with sigma functions
		for (int t=16; t<64; t++) {
			w[t] = SHA256functions::lowerSigmaOne(w[t-2]) + w[t-7] + SHA256functions::lowerSigmaZero(w[t-15]) + w[t-16];
		}

		//initialize working variables
		a = hashValue[0];
		b = hashValue[1];
		c = hashValue[2];
		d = hashValue[3];
		e = hashValue[4];
		f = hashValue[5];
		g = hashValue[6];
		h = hashValue[7];
		for (int t=0; t<64; t++) {
			t1 = h + SHA256functions::upperSigmaOne(e) + SHA256functions::ch(e,f,g) + k[t] + w[t];
			t2 = SHA256functions::upperSigmaZero(a) + SHA256functions::maj(a,b,c);
			h=g;
			g=f;
			f=e;
			e=d+t1;
			d=c;
			c=b;
			b=a;
			a=t1+t2;
		}

		//intermediate hash value
		hashValue[0] = a + hashValue[0];
		hashValue[1] = b + hashValue[1];
		hashValue[2] = c + hashValue[2];
		hashValue[3] = d + hashValue[3];
		hashValue[4] = e + hashValue[4];
		hashValue[5] = f + hashValue[5];
		hashValue[6] = g + hashValue[6];
		hashValue[7] = h + hashValue[7];
	}
	return hashValue;
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
    std::array<uint32_t, 8> hashValue = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
                                        };   

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
		hashValue = processingSHA256(messageBuffer, hashValue);
	}
	
	//append tail to file, process last chunk
	int bytesRead = ifile.gcount();
	messageBuffer.resize(bytesRead);
	for (unsigned char i : messageTail) {
		messageBuffer.push_back(i);
	}
	hashValue = processingSHA256(messageBuffer, hashValue);
	
	
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