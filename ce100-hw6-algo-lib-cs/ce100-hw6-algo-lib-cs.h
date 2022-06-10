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

#include "util.h"
#include <string>
#include "hotp.h"
#include "sha1.h"
#include <span>

using namespace std;
using namespace CryptoPP;

//Structs
struct result { byte* arr; int size; };

int transformFile(string sourceFilePath, string destFilePath, int operation);
result AESenc(SecByteBlock key, SecByteBlock iv, const string plain);
string AESdec(SecByteBlock key, SecByteBlock iv, byte* encryted, int encryptedSize);
std::streampos fileSize(const char* filePath);
int HOTP(unsigned char* K, int C);