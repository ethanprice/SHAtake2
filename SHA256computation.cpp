//SHA processing function
#include <cstdint>
#include <array>
#include <vector>
#include "SHA256functions.h"
#include "catch.hpp"

uint32_t bytesToInt(unsigned char x0,unsigned char x1,unsigned char x2,unsigned char x3) {
    return (x0<<24)|(x1<<16)|(x2<<8)|(x3);
}

std::array<uint32_t, 8>& computeSHA256(std::vector<char>& messageBuffer, std::array<uint32_t, 8>& hashValue){
	//working variables
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    std::array<uint32_t, 64> w;
	static const std::array<uint32_t, 64> K = SHA256functions::generateSHA256_K();
	
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
			t1 = h + SHA256functions::upperSigmaOne(e) + SHA256functions::ch(e,f,g) + K[t] + w[t];
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