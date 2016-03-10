/*
SHAtake2 is an implementation of the SHA256 hashing standard. 
At least -O1 and -flto optimization are recommended.
C++11 features are used, and using the -std=c++11 flag is likely required to compile.	
*/

#include <iostream>
#include <sstream>
#include <vector>
#include <array>
#include <fstream>
#include <string>
#include <chrono>
#include <iomanip>
#include "SHA256functions.h"
#include "SHA256computation.h"

inline std::vector<uint32_t> createSHAofFile(std::istream& ifile, std::string SHAmode){
	const uint32_t CHUNK_SIZE = 1024;
	std::array<uint32_t, 8> hashValue;
	std::vector<unsigned char> messageTail;
	
	//initialize
	if (SHAmode == "SHA224"){
		hashValue = SHA256functions::generateSHA224_H0();
		messageTail = SHA256computation::createSHA256MessageTail(ifile);
	}else{
		hashValue = SHA256functions::generateSHA256_H0();
		messageTail = SHA256computation::createSHA256MessageTail(ifile);
	}
	
	//FILE MODE
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
	std::vector<uint32_t> hashVector;
	for (auto value : hashValue){
		hashVector.push_back(value);
	}
	
	return hashVector;
}

int main(int argc, char* argv[]) {
	std::ios::sync_with_stdio(false);
	std::string SHAmode = "";
	bool timed = false;
	//normally read from CIN
	std::string filename = "";
	
	//start timer
    auto timer1 = std::chrono::high_resolution_clock::now();
	
    for (int i = 1; i < argc; i++){
		std::string arg = argv[i];
		if (arg == "-SHA224"){
			SHAmode = "SHA224";
		}
		else if (arg == "-SHA256"){
			SHAmode = "SHA256";
		}
		else if (arg == "-t"){
			timed = true;
		}
		else{
			filename = arg;
		}
	}
	
	if (SHAmode == ""){
		std::cout << "No SHA version flag detected, defaulting to SHA256" << "\n";
		SHAmode = "SHA256";
	}
	
	std::vector<uint32_t> hashVector;
	
	//if file was redirected in, use that, else open file
	if (filename == ""){
		hashVector = createSHAofFile(std::cin, SHAmode);
		if (!std::cin.eof()){
			std::cout << "No input detected.";
			return 1;
		}
	} else {
		std::ifstream message(filename);
		if(!message) {
			std::cout << "File " << filename << " not found.\n";
			return 1;
		}
		hashVector = createSHAofFile(message, SHAmode);
	}
	
	for (auto x : hashVector){
		std::cout << std::hex << x;
	}
	
	if (timed){
		auto timer2 = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double> runtime = timer2 - timer1;
		std::cout << std::fixed << std::setprecision(3) << "\nThroughput: " << runtime.count() << " seconds";
	}
	
    return 0;
}