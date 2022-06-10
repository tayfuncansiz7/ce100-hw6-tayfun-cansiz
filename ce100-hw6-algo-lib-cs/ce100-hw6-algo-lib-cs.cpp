
/**
 * @file ce100-hw6-tayfun-cansiz
 * @author Tayfun CANSIZ
 * @date 10 June 2022
 *
 * @brief <b> HW-6 Functions </b>
 *
 * HW-6 Functions
 *
 * @see http://bilgisayar.mmf.erdogan.edu.tr/en/
 *
 */

#ifdef _DEBUG
#pragma comment(lib, "../cryptopp850/Win32/Output/Debug/cryptlib.lib")
#else
#pragma comment(lib, "../cryptopp850/Win32/Output/Release/cryptlib.lib") 
#endif

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "../cryptopp850/cryptlib.h"
#include "../cryptopp850/sha.h"
#include "../cryptopp850/hex.h"
#include "../cryptopp850/files.h"
#include "../cryptopp850/rijndael.h"
#include "../cryptopp850/modes.h"
#include "../cryptopp850/osrng.h"
#include "../cryptopp850/md5.h"
#include "../cryptopp850/crc.h"
#include "../cryptopp850/des.h"

#include <iostream>
#include <string>

#include "hotp.h"
#include "sha1.h"
#include <span>
#include "ce100-hw6-algo-lib-cs.h"

using namespace std;
using namespace CryptoPP;
using namespace shoc;


/**
* @name  transformFile
*
* @brief A function used by transformFile
*
* @param [in] fisourceFilePath [\b string]  function index of  in the serie
*
* @param [in] fidestFilePath [\b string]  function index of  in the serie
*
* @param [in] fioperation [\b int]  function index of  in the serie
*
**/

int transformFile(string sourceFilePath, string destFilePath, int operation) {
	HexEncoder encoder(new FileSink(std::cout));
	SecByteBlock key((byte*)"372377462341461556446419208", AES::DEFAULT_KEYLENGTH);
	SecByteBlock iv((byte*)"372377462341461556446419208", AES::BLOCKSIZE);
	if (operation == 1)
	{
		int allSize;
		ifstream ifd(sourceFilePath, ios::beg);
		int sourceFileSize = fileSize(sourceFilePath.c_str());
		ifd.seekg(0, ios::beg);
		//vector<char> buffer;
		//buffer.resize(sourceFileSize); // << resize not reserve
		std::stringstream buffer;
		buffer << ifd.rdbuf();

		string senderMessageString = buffer.str();

		SHA256 hashSender256;
		std::string senderMessageSha256Digest;
		hashSender256.Update((const byte*)senderMessageString.data(), senderMessageString.size());
		senderMessageSha256Digest.resize(hashSender256.DigestSize());
		hashSender256.Final((byte*)&senderMessageSha256Digest[0]);

		SHA1 hashSender1;
		std::string senderMessageSha1Digest;
		hashSender1.Update((const byte*)senderMessageString.data(), senderMessageString.size());
		senderMessageSha1Digest.resize(hashSender1.DigestSize());
		hashSender1.Final((byte*)&senderMessageSha1Digest[0]);
		auto x = AESenc(key, iv, senderMessageString);
		allSize = sizeof(int) + x.size + senderMessageSha1Digest.size() + senderMessageSha256Digest.size();

		byte* data = new byte[allSize];
		byte* ptr = data;
		memcpy(ptr, &sourceFileSize, sizeof(int));
		ptr += sizeof(int);
		memcpy(ptr, senderMessageSha1Digest.c_str(), senderMessageSha1Digest.length() * sizeof(char));
		ptr += senderMessageSha1Digest.length() * sizeof(char);
		memcpy(ptr, x.arr, x.size);
		ptr += x.size;
		memcpy(ptr, senderMessageSha256Digest.c_str(), senderMessageSha256Digest.length() * sizeof(char));



		std::ofstream file(destFilePath, ios::out | ios::binary);
		if (file)
		{
			file.write((char*)data, allSize);
		}
		file.close();

		return 1;
	}
	else if (operation == 0)
	{
		ifstream ifd(destFilePath, ios::beg | ios::binary);
		int sourceFileSize = fileSize(destFilePath.c_str());
		//vector<char> buffer;
		//buffer.resize(sourceFileSize); // << resize not reserve

		auto bytes = new byte[sourceFileSize];
		ifd.read((char*)bytes, sourceFileSize);

		int originalSize = *(int*)(&bytes[0]);

		byte* encryptedStart = &bytes[sizeof(int) + 20];
		int encDataLenght = sourceFileSize - (sizeof(int) + 20 + 32);

		auto encData = new byte[encDataLenght];
		memcpy(encData, encryptedStart, encDataLenght);
		string message = AESdec(key, iv, encData, encDataLenght);



		byte* sha1start = &bytes[sizeof(int)];
		byte* sha256start = &bytes[sizeof(int) + 20 + encDataLenght];

		byte* encryptedDataSha1 = new byte[20];
		memcpy(encryptedDataSha1, sha1start, 20);

		byte* encryptedDataSha256 = new byte[32];
		memcpy(encryptedDataSha256, sha256start, 32);

		SHA256 hashSender256;
		std::string senderMessageSha256Digest;
		hashSender256.Update((const byte*)message.data(), originalSize);
		senderMessageSha256Digest.resize(hashSender256.DigestSize());
		hashSender256.Final((byte*)&senderMessageSha256Digest[0]);

		SHA1 hashSender1;
		std::string senderMessageSha1Digest;
		hashSender1.Update((const byte*)message.data(), originalSize);
		senderMessageSha1Digest.resize(hashSender1.DigestSize());
		hashSender1.Final((byte*)&senderMessageSha1Digest[0]);

		bool isEqual = true;;
		byte* newsha = (byte*)&senderMessageSha1Digest[0];
		bool flag = true;
		for (size_t i = 0; i < 20; i++)
		{
			if (newsha[i] != encryptedDataSha1[i]) {
				flag = false;
				break;
			}
		}
		if (!flag) isEqual = false;
		newsha = (byte*)&senderMessageSha256Digest[0];

		flag = true;
		for (size_t i = 0; i < 32; i++)
		{
			if (newsha[i] != encryptedDataSha256[i]) {
				flag = false;
				break;
			}
		}
		if (!flag) isEqual = false;
		if (isEqual) {
			return 1;
		}
		else {
			return 0;
		}
	}
	return 99;
}

/**
* @name  hotp
*
* @brief Prints hotp from a given source
*
* @param [in] fiK [\b  unsigned char*]  function index of  in the serie
*
* @param [in] fiC [\b int]  function index of  in the serie
*
**/

int HOTP(unsigned char* K, int C)
{
	std::string s = std::to_string(C);
	return hotp<Sha1>(K, strlen((char*)K), 6, 6);

}
std::streampos fileSize(const char* filePath) {

	std::streampos fsize = 0;
	std::ifstream file(filePath, std::ios::binary);

	fsize = file.tellg();
	file.seekg(0, std::ios::end);
	fsize = file.tellg() - fsize;
	file.close();

	return fsize;
}
