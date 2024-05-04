#include "Utilities.h"
#include <iostream>
#include <sstream>
#include <map>
#include <openssl/sha.h>
#include <fstream>
#include "sys/types.h"
#include "sys/sysinfo.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include <stdint.h>     //for int8_t
#include <string.h>     //for memcmp
#include <wmmintrin.h>  //for intrinsics for AES-NI
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
//compile using gcc and following arguments: -g;-O0;-Wall;-msse2;-msse;-march=native;-maes

std::map<int, std::chrono::time_point<std::chrono::high_resolution_clock>> Utilities::m_begs;
std::map<std::string, std::ofstream*> Utilities::handlers;
std::map<int, double> timehist;
unsigned char Utilities::key[AES_KEY_SIZE];
unsigned char Utilities::tmpkey[TMP_AES_KEY_SIZE];
unsigned char Utilities::iv[AES_KEY_SIZE];
unsigned char Utilities::tmpiv[TMP_AES_KEY_SIZE];
bool Utilities::DROP_CACHE = false;
bool Utilities::DEBUG_MODE = false;
bool Utilities::PROFILE_MODE = false;
std::string Utilities::testKeyword;
int Utilities::numOfFile = 0;
int Utilities::TotalCacheSize = 1024 * 1024 / 4;
std::string Utilities::rootAddress = "/tmp/tmp/";
bool Utilities::useRandomFolder = false;
int Utilities::JUMP_SIZE = 1;
int Utilities::CACHE_PERCENTAGE = 0;
std::string Utilities::HDD_DROP_CACHE_COMMAND = "sudo hdparm -A 0 /dev/sda >/dev/null 2>&1";
std::string Utilities::SSD_DROP_CACHE_COMMAND = "sudo nvme set-feature -f 6 -v 0 /dev/nvme0n1 >/dev/null 2>&1";
std::string Utilities::KERNEL_DROP_CACHE_COMMAND = "echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1";
bool Utilities::HDD_CACHE = true;
bool Utilities::KERNEL_CACHE = true;
bool Utilities::SSD_CACHE = false;

Utilities::Utilities() {
    memset(key, 0x00, AES_KEY_SIZE);
    memset(tmpkey, 0x00, TMP_AES_KEY_SIZE);
    memset(iv, 0x00, AES_KEY_SIZE);
    memset(tmpiv, 0x00, TMP_AES_KEY_SIZE);
}

Utilities::~Utilities() {
}

void Utilities::startTimer(int id) {
    std::chrono::time_point<std::chrono::high_resolution_clock> m_beg = std::chrono::high_resolution_clock::now();
    m_begs[id] = m_beg;

}

double Utilities::stopTimer(int id) {
    double t = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - m_begs[id]).count();
    timehist.erase(id);
    timehist[id] = t;
    return t;
}

//std::string Utilities::getSHA256(std::string input) {
//    CryptoPP::SHA256 hash;
//    unsigned char digest[ CryptoPP::SHA256::DIGESTSIZE ];
//    hash.CalculateDigest(digest, (unsigned char*) input.c_str(), input.length());
//    CryptoPP::HexEncoder encoder;
//    std::string output;
//    encoder.Attach(new CryptoPP::StringSink(output));
//    encoder.Put(digest, sizeof (digest));
//    encoder.MessageEnd();
//    return output;
//}

unsigned char* Utilities::sha256(char* input, int size) {
    unsigned char* hash = new unsigned char[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, size);
    SHA256_Final(hash, &sha256);
    return hash;
}

//std::string Utilities::encryptAndEncode(std::string plaintext, unsigned char* key, unsigned char* iv) {
//    std::string ciphertext;
//    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
//    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
//    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
//    stfEncryptor.Put(reinterpret_cast<const unsigned char*> (plaintext.c_str()), plaintext.length() + 1);
//    stfEncryptor.MessageEnd();
//    std::string encodedCiphertext = base64_encode(ciphertext.c_str(), ciphertext.size());
//    return encodedCiphertext;
//    //    return ciphertext;
//}

//std::string Utilities::decodeAndDecrypt(std::string encodedCiphertext, unsigned char* key, unsigned char* iv) {
//    std::string decryptedtext;
//    //    std::string ciphertext = encodedCiphertext;
//    std::string ciphertext = base64_decode(encodedCiphertext);
//    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
//    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
//    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
//    stfDecryptor.Put(reinterpret_cast<const unsigned char*> (ciphertext.c_str()), ciphertext.size());
//    stfDecryptor.MessageEnd();
//    return decryptedtext;
//}


static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string Utilities::base64_encode(const char* bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';

    }

    return ret;

}

std::string Utilities::base64_decode(std::string const& encoded_string) {
    size_t in_len = encoded_string.size();
    size_t i = 0;
    size_t j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = static_cast<unsigned char> (base64_chars.find(char_array_4[i]));

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = static_cast<unsigned char> (base64_chars.find(char_array_4[j]));

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}

std::string Utilities::XOR(std::string value, std::string key) {
    std::string retval(value);

    short unsigned int klen = key.length();
    short unsigned int vlen = value.length();
    short unsigned int k = 0;
    if (klen < vlen) {
        for (int i = klen; i < vlen; i++) {
            key += " ";
        }
    } else {
        for (int i = vlen; i < klen; i++) {
            value += " ";
        }
    }
    klen = vlen;

    for (short unsigned int v = 0; v < vlen; v++) {
        retval[v] = value[v]^key[k];
        k = (++k < klen ? k : 0);
    }

    return retval;
}

void Utilities::logTime(std::string filename, std::string content) {
    (*handlers[filename]) << content << std::endl;
}

void Utilities::finalizeLogging(std::string filename) {
    handlers[filename]->close();
}

void Utilities::initializeLogging(std::string filename) {
    std::ofstream* outfile = new std::ofstream();
    outfile->open(filename, std::ios_base::app);
    handlers[filename] = outfile;
    //    Utilities::handlers.insert(std::pair<std::string, ofstream>(filename,outfile));
}

int Utilities::getMem() { //Note: this value is in KB!
    FILE* file = fopen("/proc/self/status", "r");
    int result = -1;
    char line[128];

    while (fgets(line, 128, file) != NULL) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            result = parseLine(line);
            break;
        }
    }
    fclose(file);
    return result;
}

int Utilities::parseLine(char* line) {
    // This assumes that a digit will be found and the line ends in " Kb".
    int i = strlen(line);
    const char* p = line;
    while (*p < '0' || *p > '9') p++;
    line[i - 3] = '\0';
    i = atoi(p);
    return i;
}

std::array<uint8_t, 16> Utilities::convertToArray(std::string addr) {
    std::array<uint8_t, 16> res;
    for (int i = 0; i < 16; i++) {
        res[i] = addr[i];
    }
    return res;
}

double Utilities::getTimeFromHist(int id) {
    if (timehist.count(id) > 0) {
        return timehist[id];
    }
    return 0;
}

int Utilities::getBid(std::string srchIndex) {
    return 0;
}

std::array<uint8_t, AES_KEY_SIZE> Utilities::encode(std::string keyword) {
    unsigned char plaintext[AES_KEY_SIZE];
    for (unsigned int i = 0; i < keyword.length(); i++) {
        plaintext[i] = keyword.at(i);
    }
    for (uint i = keyword.length(); i < AES_KEY_SIZE - 4; i++) {
        plaintext[i] = '\0';
    }

    unsigned char ciphertext[AES_KEY_SIZE];
    encrypt(plaintext, strlen((char *) plaintext), key, iv, ciphertext);
    std::array<uint8_t, AES_KEY_SIZE> result;
    for (uint i = 0; i < AES_KEY_SIZE; i++) {
        result[i] = ciphertext[i];
    }
    return result;
}

std::array<uint8_t, TMP_AES_KEY_SIZE> Utilities::tmpencode(std::string keyword) {
    unsigned char plaintext[TMP_AES_KEY_SIZE];
    for (unsigned int i = 0; i < keyword.length(); i++) {
        plaintext[i] = keyword.at(i);
    }
    for (uint i = keyword.length(); i < TMP_AES_KEY_SIZE - 4; i++) {
        plaintext[i] = '\0';
    }

    unsigned char ciphertext[TMP_AES_KEY_SIZE];
    encrypt(plaintext, strlen((char *) plaintext), tmpkey, tmpiv, ciphertext);
    std::array<uint8_t, TMP_AES_KEY_SIZE> result;
    for (uint i = 0; i < TMP_AES_KEY_SIZE; i++) {
        result[i] = ciphertext[i];
    }
    return result;
}

std::array<uint8_t, AES_KEY_SIZE> Utilities::encode(std::string keyword, unsigned char* curkey) {
    unsigned char plaintext[AES_KEY_SIZE];
    for (unsigned int i = 0; i < keyword.length(); i++) {
        plaintext[i] = keyword.at(i);
    }
    for (uint i = keyword.length(); i < AES_KEY_SIZE; i++) {
        plaintext[i] = '\0';
    }
    if (curkey == NULL) {
        curkey = key;
    }
    unsigned char ciphertext[AES_KEY_SIZE];
    encrypt(plaintext, AES_KEY_SIZE - 1, curkey, iv, ciphertext);
    std::array<uint8_t, AES_KEY_SIZE> result;
    for (uint i = 0; i < AES_KEY_SIZE; i++) {
        result[i] = ciphertext[i];
    }
    return result;
}

std::array<uint8_t, TMP_AES_KEY_SIZE> Utilities::tmpencode(std::string keyword, unsigned char* curkey) {
    unsigned char plaintext[TMP_AES_KEY_SIZE];
    for (unsigned int i = 0; i < keyword.length(); i++) {
        plaintext[i] = keyword.at(i);
    }
    for (uint i = keyword.length(); i < TMP_AES_KEY_SIZE; i++) {
        plaintext[i] = '\0';
    }
    if (curkey == NULL) {
        curkey = tmpkey;
    }
    unsigned char ciphertext[TMP_AES_KEY_SIZE];
    encrypt(plaintext, TMP_AES_KEY_SIZE - 1, curkey, tmpiv, ciphertext);
    std::array<uint8_t, TMP_AES_KEY_SIZE> result;
    for (uint i = 0; i < TMP_AES_KEY_SIZE; i++) {
        result[i] = ciphertext[i];
    }
    return result;
}

std::array<uint8_t, AES_KEY_SIZE> Utilities::encode(unsigned char* plaintext, unsigned char* curkey) {
    if (curkey == NULL) {
        curkey = key;
    }
    unsigned char ciphertext[AES_KEY_SIZE];
    encrypt(plaintext, AES_KEY_SIZE - 1, curkey, iv, ciphertext);
    std::array<uint8_t, AES_KEY_SIZE> result;
    for (uint i = 0; i < AES_KEY_SIZE; i++) {
        result[i] = ciphertext[i];
    }
    return result;
}

std::array<uint8_t, TMP_AES_KEY_SIZE> Utilities::tmpencode(unsigned char* plaintext, unsigned char* curkey) {
    if (curkey == NULL) {
        curkey = tmpkey;
    }
    unsigned char ciphertext[TMP_AES_KEY_SIZE];
    encrypt(plaintext, TMP_AES_KEY_SIZE - 1, curkey, tmpiv, ciphertext);
    std::array<uint8_t, TMP_AES_KEY_SIZE> result;
    for (uint i = 0; i < TMP_AES_KEY_SIZE; i++) {
        result[i] = ciphertext[i];
    }
    return result;
}

std::string Utilities::decode(std::array<uint8_t, AES_KEY_SIZE> ciphertext, unsigned char* curkey) {
    unsigned char plaintext[AES_KEY_SIZE];
    unsigned char cipher[AES_KEY_SIZE];
    for (uint i = 0; i < AES_KEY_SIZE; i++) {
        cipher[i] = ciphertext[i];
    }
    if (curkey == NULL) {
        curkey = key;
    }
    decrypt(cipher, AES_KEY_SIZE, curkey, iv, plaintext);
    std::string result;
    for (uint i = 0; i < AES_KEY_SIZE && plaintext[i] != '\0'; i++) {
        result += (char) plaintext[i];
    }
    return result;
}

std::string Utilities::tmpdecode(std::array<uint8_t, TMP_AES_KEY_SIZE> ciphertext, unsigned char* curkey) {
    unsigned char plaintext[TMP_AES_KEY_SIZE];
    unsigned char cipher[TMP_AES_KEY_SIZE];
    for (uint i = 0; i < TMP_AES_KEY_SIZE; i++) {
        cipher[i] = ciphertext[i];
    }
    if (curkey == NULL) {
        curkey = tmpkey;
    }
    decrypt(cipher, TMP_AES_KEY_SIZE, curkey, tmpiv, plaintext);
    std::string result;
    for (uint i = 0; i < TMP_AES_KEY_SIZE && plaintext[i] != '\0'; i++) {
        result += (char) plaintext[i];
    }
    return result;
}

void Utilities::decode(std::array<uint8_t, AES_KEY_SIZE> ciphertext, std::array<uint8_t, AES_KEY_SIZE>& plaintext, unsigned char* curkey) {
    unsigned char plain[AES_KEY_SIZE];
    unsigned char cipher[AES_KEY_SIZE];
    for (uint i = 0; i < AES_KEY_SIZE; i++) {
        cipher[i] = ciphertext[i];
    }
    if (curkey == NULL) {
        curkey = key;
    }
    decrypt(cipher, AES_KEY_SIZE, curkey, iv, plain);
    mempcpy(plaintext.data(), plain, AES_KEY_SIZE);
}

void Utilities::tmpdecode(std::array<uint8_t, TMP_AES_KEY_SIZE> ciphertext, std::array<uint8_t, TMP_AES_KEY_SIZE>& plaintext, unsigned char* curkey) {
    unsigned char plain[TMP_AES_KEY_SIZE];
    unsigned char cipher[TMP_AES_KEY_SIZE];
    for (uint i = 0; i < TMP_AES_KEY_SIZE; i++) {
        cipher[i] = ciphertext[i];
    }
    if (curkey == NULL) {
        curkey = tmpkey;
    }
    decrypt(cipher, TMP_AES_KEY_SIZE, curkey, tmpiv, plain);
    mempcpy(plaintext.data(), plain, TMP_AES_KEY_SIZE);
}

int Utilities::encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

void Utilities::handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int Utilities::decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

std::vector<std::string> Utilities::splitData(const std::string& str, const std::string& delim) {
    std::vector<std::string> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == std::string::npos) pos = str.length();
        std::string token = str.substr(prev, pos - prev);
        if (!token.empty()) tokens.push_back(token);
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());
    return tokens;
}

std::array<uint8_t, AES_KEY_SIZE> Utilities::generatePRF(unsigned char* input, unsigned char* prfkey) {
    unsigned char result[AES_KEY_SIZE];
    encrypt(input, AES_KEY_SIZE - 1, prfkey, iv, result);
    std::array<uint8_t, AES_KEY_SIZE> res;
    mempcpy(res.data(), result, AES_KEY_SIZE);
    return res;
}

std::array<uint8_t, TMP_AES_KEY_SIZE> Utilities::tmpgeneratePRF(unsigned char* input, unsigned char* prfkey) {
    unsigned char result[TMP_AES_KEY_SIZE];
    encrypt(input, TMP_AES_KEY_SIZE - 1, prfkey, tmpiv, result);
    std::array<uint8_t, TMP_AES_KEY_SIZE> res;
    mempcpy(res.data(), result, TMP_AES_KEY_SIZE);
    return res;
}




//internal stuff

//macros
#define DO_ENC_BLOCK(m,k) \
        do{\
        m = _mm_xor_si128       (m, k[ 0]); \
        m = _mm_aesenc_si128    (m, k[ 1]); \
        m = _mm_aesenc_si128    (m, k[ 2]); \
        m = _mm_aesenc_si128    (m, k[ 3]); \
        m = _mm_aesenc_si128    (m, k[ 4]); \
        m = _mm_aesenc_si128    (m, k[ 5]); \
        m = _mm_aesenc_si128    (m, k[ 6]); \
        m = _mm_aesenc_si128    (m, k[ 7]); \
        m = _mm_aesenc_si128    (m, k[ 8]); \
        m = _mm_aesenc_si128    (m, k[ 9]); \
        m = _mm_aesenclast_si128(m, k[10]);\
    }while(0)

#define DO_DEC_BLOCK(m,k) \
        do{\
        m = _mm_xor_si128       (m, k[10+0]); \
        m = _mm_aesdec_si128    (m, k[10+1]); \
        m = _mm_aesdec_si128    (m, k[10+2]); \
        m = _mm_aesdec_si128    (m, k[10+3]); \
        m = _mm_aesdec_si128    (m, k[10+4]); \
        m = _mm_aesdec_si128    (m, k[10+5]); \
        m = _mm_aesdec_si128    (m, k[10+6]); \
        m = _mm_aesdec_si128    (m, k[10+7]); \
        m = _mm_aesdec_si128    (m, k[10+8]); \
        m = _mm_aesdec_si128    (m, k[10+9]); \
        m = _mm_aesdeclast_si128(m, k[0]);\
    }while(0)


#define DO_ENC_BLOCK2(m1,m2,k) \
        do{\
        m1 = _mm_xor_si128       (m1, k[ 0]); \
        m1 = _mm_aesenc_si128    (m1, k[ 1]); \
        m1 = _mm_aesenc_si128    (m1, k[ 2]); \
        m1 = _mm_aesenc_si128    (m1, k[ 3]); \
        m1 = _mm_aesenc_si128    (m1, k[ 4]); \
        m1 = _mm_aesenc_si128    (m1, k[ 5]); \
        m1 = _mm_aesenc_si128    (m1, k[ 6]); \
        m1 = _mm_aesenc_si128    (m1, k[ 7]); \
        m1 = _mm_aesenc_si128    (m1, k[ 8]); \
        m1 = _mm_aesenc_si128    (m1, k[ 9]); \
        m1 = _mm_aesenclast_si128(m1, k[10]);\
        m2 = _mm_xor_si128       (m2, k[ 20]); \
        m2 = _mm_aesenc_si128    (m2, k[ 21]); \
        m2 = _mm_aesenc_si128    (m2, k[ 22]); \
        m2 = _mm_aesenc_si128    (m2, k[ 23]); \
        m2 = _mm_aesenc_si128    (m2, k[ 24]); \
        m2 = _mm_aesenc_si128    (m2, k[ 25]); \
        m2 = _mm_aesenc_si128    (m2, k[ 26]); \
        m2 = _mm_aesenc_si128    (m2, k[ 27]); \
        m2 = _mm_aesenc_si128    (m2, k[ 28]); \
        m2 = _mm_aesenc_si128    (m2, k[ 29]); \
        m2 = _mm_aesenclast_si128(m2, k[30]);\
    }while(0)

#define DO_DEC_BLOCK2(m1,m2,k) \
        do{\
        m2 = _mm_xor_si128       (m2, k[20+0]); \
        m2 = _mm_aesdec_si128    (m2, k[20+1]); \
        m2 = _mm_aesdec_si128    (m2, k[20+2]); \
        m2 = _mm_aesdec_si128    (m2, k[20+3]); \
        m2 = _mm_aesdec_si128    (m2, k[20+4]); \
        m2 = _mm_aesdec_si128    (m2, k[20+5]); \
        m2 = _mm_aesdec_si128    (m2, k[20+6]); \
        m2 = _mm_aesdec_si128    (m2, k[20+7]); \
        m2 = _mm_aesdec_si128    (m2, k[20+8]); \
        m2 = _mm_aesdec_si128    (m2, k[20+9]); \
        m2 = _mm_aesdeclast_si128(m2, k[20]);\
        m1 = _mm_xor_si128       (m1, k[10+0]); \
        m1 = _mm_aesdec_si128    (m1, k[10+1]); \
        m1 = _mm_aesdec_si128    (m1, k[10+2]); \
        m1 = _mm_aesdec_si128    (m1, k[10+3]); \
        m1 = _mm_aesdec_si128    (m1, k[10+4]); \
        m1 = _mm_aesdec_si128    (m1, k[10+5]); \
        m1 = _mm_aesdec_si128    (m1, k[10+6]); \
        m1 = _mm_aesdec_si128    (m1, k[10+7]); \
        m1 = _mm_aesdec_si128    (m1, k[10+8]); \
        m1 = _mm_aesdec_si128    (m1, k[10+9]); \
        m1 = _mm_aesdeclast_si128(m1, k[0]);\
    }while(0)

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i key_schedule[20]; //the expanded key
static __m128i key_schedule_256[40]; //the expanded key

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

//public API

void aes128_load_key(int8_t *enc_key) {
    key_schedule[0] = _mm_loadu_si128((const __m128i*) enc_key);
    key_schedule[1] = AES_128_key_exp(key_schedule[0], 0x01);
    key_schedule[2] = AES_128_key_exp(key_schedule[1], 0x02);
    key_schedule[3] = AES_128_key_exp(key_schedule[2], 0x04);
    key_schedule[4] = AES_128_key_exp(key_schedule[3], 0x08);
    key_schedule[5] = AES_128_key_exp(key_schedule[4], 0x10);
    key_schedule[6] = AES_128_key_exp(key_schedule[5], 0x20);
    key_schedule[7] = AES_128_key_exp(key_schedule[6], 0x40);
    key_schedule[8] = AES_128_key_exp(key_schedule[7], 0x80);
    key_schedule[9] = AES_128_key_exp(key_schedule[8], 0x1B);
    key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);

    // generate decryption keys in reverse order.
    // k[10] is shared by last encryption and first decryption rounds
    // k[0] is shared by first encryption round and last decryption round (and is the original user key)
    // For some implementation reasons, decryption key schedule is NOT the encryption key schedule in reverse order
    key_schedule[11] = _mm_aesimc_si128(key_schedule[9]);
    key_schedule[12] = _mm_aesimc_si128(key_schedule[8]);
    key_schedule[13] = _mm_aesimc_si128(key_schedule[7]);
    key_schedule[14] = _mm_aesimc_si128(key_schedule[6]);
    key_schedule[15] = _mm_aesimc_si128(key_schedule[5]);
    key_schedule[16] = _mm_aesimc_si128(key_schedule[4]);
    key_schedule[17] = _mm_aesimc_si128(key_schedule[3]);
    key_schedule[18] = _mm_aesimc_si128(key_schedule[2]);
    key_schedule[19] = _mm_aesimc_si128(key_schedule[1]);
}

void aes256_load_key(int8_t *enc_key) {
    key_schedule_256[0] = _mm_loadu_si128((const __m128i*) enc_key);
    key_schedule_256[1] = AES_128_key_exp(key_schedule_256[0], 0x01);
    key_schedule_256[2] = AES_128_key_exp(key_schedule_256[1], 0x02);
    key_schedule_256[3] = AES_128_key_exp(key_schedule_256[2], 0x04);
    key_schedule_256[4] = AES_128_key_exp(key_schedule_256[3], 0x08);
    key_schedule_256[5] = AES_128_key_exp(key_schedule_256[4], 0x10);
    key_schedule_256[6] = AES_128_key_exp(key_schedule_256[5], 0x20);
    key_schedule_256[7] = AES_128_key_exp(key_schedule_256[6], 0x40);
    key_schedule_256[8] = AES_128_key_exp(key_schedule_256[7], 0x80);
    key_schedule_256[9] = AES_128_key_exp(key_schedule_256[8], 0x1B);
    key_schedule_256[10] = AES_128_key_exp(key_schedule_256[9], 0x36);

    // generate decryption keys in reverse order.
    // k[10] is shared by last encryption and first decryption rounds
    // k[0] is shared by first encryption round and last decryption round (and is the original user key)
    // For some implementation reasons, decryption key schedule is NOT the encryption key schedule in reverse order
    key_schedule_256[11] = _mm_aesimc_si128(key_schedule_256[9]);
    key_schedule_256[12] = _mm_aesimc_si128(key_schedule_256[8]);
    key_schedule_256[13] = _mm_aesimc_si128(key_schedule_256[7]);
    key_schedule_256[14] = _mm_aesimc_si128(key_schedule_256[6]);
    key_schedule_256[15] = _mm_aesimc_si128(key_schedule_256[5]);
    key_schedule_256[16] = _mm_aesimc_si128(key_schedule_256[4]);
    key_schedule_256[17] = _mm_aesimc_si128(key_schedule_256[3]);
    key_schedule_256[18] = _mm_aesimc_si128(key_schedule_256[2]);
    key_schedule_256[19] = _mm_aesimc_si128(key_schedule_256[1]);

    key_schedule_256[20] = _mm_loadu_si128((const __m128i*) enc_key + 16);
    key_schedule_256[21] = AES_128_key_exp(key_schedule_256[20], 0x01);
    key_schedule_256[22] = AES_128_key_exp(key_schedule_256[21], 0x02);
    key_schedule_256[23] = AES_128_key_exp(key_schedule_256[22], 0x04);
    key_schedule_256[24] = AES_128_key_exp(key_schedule_256[23], 0x08);
    key_schedule_256[25] = AES_128_key_exp(key_schedule_256[24], 0x10);
    key_schedule_256[26] = AES_128_key_exp(key_schedule_256[25], 0x20);
    key_schedule_256[27] = AES_128_key_exp(key_schedule_256[26], 0x40);
    key_schedule_256[28] = AES_128_key_exp(key_schedule_256[27], 0x80);
    key_schedule_256[29] = AES_128_key_exp(key_schedule_256[28], 0x1B);
    key_schedule_256[30] = AES_128_key_exp(key_schedule_256[29], 0x36);

    // generate decryption keys in reverse order.
    // k[10] is shared by last encryption and first decryption rounds
    // k[0] is shared by first encryption round and last decryption round (and is the original user key)
    // For some implementation reasons, decryption key schedule is NOT the encryption key schedule in reverse order
    key_schedule_256[31] = _mm_aesimc_si128(key_schedule_256[29]);
    key_schedule_256[32] = _mm_aesimc_si128(key_schedule_256[28]);
    key_schedule_256[33] = _mm_aesimc_si128(key_schedule_256[27]);
    key_schedule_256[34] = _mm_aesimc_si128(key_schedule_256[26]);
    key_schedule_256[35] = _mm_aesimc_si128(key_schedule_256[25]);
    key_schedule_256[36] = _mm_aesimc_si128(key_schedule_256[24]);
    key_schedule_256[37] = _mm_aesimc_si128(key_schedule_256[23]);
    key_schedule_256[38] = _mm_aesimc_si128(key_schedule_256[22]);
    key_schedule_256[39] = _mm_aesimc_si128(key_schedule_256[21]);

}

void aes128_enc(int8_t *plainText, int8_t *cipherText) {
    __m128i m = _mm_loadu_si128((__m128i *) plainText);

    DO_ENC_BLOCK(m, key_schedule);

    _mm_storeu_si128((__m128i *) cipherText, m);
}

void aes256_enc(int8_t *plainText, int8_t *cipherText) {
    __m128i m1 = _mm_loadu_si128((__m128i *) plainText);
    __m128i m2 = _mm_loadu_si128((__m128i *) (plainText + 16));

    DO_ENC_BLOCK2(m1, m2, key_schedule_256);

    _mm_storeu_si128((__m128i *) cipherText, m1);
    _mm_storeu_si128((__m128i *) (cipherText + 16), m2);
}

void aes128_dec(int8_t *cipherText, int8_t *plainText) {
    __m128i m = _mm_loadu_si128((__m128i *) cipherText);

    DO_DEC_BLOCK(m, key_schedule);

    _mm_storeu_si128((__m128i *) plainText, m);
}

void aes256_dec(int8_t *cipherText, int8_t *plainText) {
    __m128i m1 = _mm_loadu_si128((__m128i *) cipherText);
    __m128i m2 = _mm_loadu_si128((__m128i *) (cipherText + 16));

    DO_DEC_BLOCK2(m1, m2, key_schedule);

    _mm_storeu_si128((__m128i *) plainText, m1);
    _mm_storeu_si128((__m128i *) (plainText + 16), m2);
}

//return 0 if no error
//1 if encryption failed
//2 if decryption failed
//3 if both failed

int aes128_self_test(void) {
    int8_t plain[] = {(int8_t) 0x32, (int8_t) 0x43, (int8_t) 0xf6, (int8_t) 0xa8, (int8_t) 0x88, (int8_t) 0x5a, (int8_t) 0x30, (int8_t) 0x8d, (int8_t) 0x31, (int8_t) 0x31, (int8_t) 0x98, (int8_t) 0xa2, (int8_t) 0xe0, (int8_t) 0x37, (int8_t) 0x07, (int8_t) 0x34};
    int8_t enc_key[] = {(int8_t) 0x2b, (int8_t) 0x7e, (int8_t) 0x15, (int8_t) 0x16, (int8_t) 0x28, (int8_t) 0xae, (int8_t) 0xd2, (int8_t) 0xa6, (int8_t) 0xab, (int8_t) 0xf7, (int8_t) 0x15, (int8_t) 0x88, (int8_t) 0x09, (int8_t) 0xcf, (int8_t) 0x4f, (int8_t) 0x3c};
    int8_t cipher[] = {(int8_t) 0x39, (int8_t) 0x25, (int8_t) 0x84, (int8_t) 0x1d, (int8_t) 0x02, (int8_t) 0xdc, (int8_t) 0x09, (int8_t) 0xfb, (int8_t) 0xdc, (int8_t) 0x11, (int8_t) 0x85, (int8_t) 0x97, (int8_t) 0x19, (int8_t) 0x6a, (int8_t) 0x0b, (int8_t) 0x32};
    int8_t computed_cipher[16];
    int8_t computed_plain[16];
    int out = 0;
    aes128_load_key(enc_key);
    aes128_enc(plain, computed_cipher);
    aes128_dec(cipher, computed_plain);
    if (memcmp(cipher, computed_cipher, sizeof (cipher))) out = 1;
    if (memcmp(plain, computed_plain, sizeof (plain))) out |= 2;
    return out;
}

void Utilities::decode2(std::array<uint8_t, AES_KEY_SIZE> ciphertext, std::array<uint8_t, AES_KEY_SIZE>& plaintext, unsigned char* curkey) {
    int8_t computed_plain[AES_KEY_SIZE];
    aes256_load_key((int8_t*) curkey);
    aes256_dec((int8_t*) ciphertext.data(), (int8_t*) plaintext.data());
    //    aes128_load_key((int8_t*) curkey);
    //    aes128_dec((int8_t*) ciphertext.data(), (int8_t*)plaintext.data());
}

std::array<uint8_t, AES_KEY_SIZE> Utilities::encode2(std::string keyword, unsigned char* curkey) {
    std::array<uint8_t, AES_KEY_SIZE> ciphertext;
    aes128_load_key((int8_t*) curkey);
    aes128_enc((int8_t*) keyword.data(), (int8_t*) ciphertext.data());
    //    aes128_load_key((int8_t*) curkey);
    //    aes128_enc((int8_t*) keyword.data(), (int8_t*) ciphertext.data());
    return ciphertext;
}



/**
  AES encryption/decryption demo program using OpenSSL EVP apis
  gcc -Wall openssl_aes.c -lcrypto
  this is public domain code. 
  Saju Pillai (saju.pillai@gmail.com)
 **/

/**
 * Create a 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
//int aes_init_enc(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx) {
//    int i, nrounds = 5;
//    unsigned char key[32], iv[32];
//
//    /*
//     * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
//     * nrounds is the number of times the we hash the material. More rounds are more secure but
//     * slower.
//     */
//    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
//    if (i != 32) {
//        printf("Key size is %d bits - should be 256 bits\n", i);
//        return -1;
//    }
//
//    EVP_CIPHER_CTX_init(e_ctx);
//    EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
//
//    return 0;
//}

//int aes_init_dec(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *d_ctx) {
//    int i, nrounds = 5;
//    unsigned char key[32], iv[32];
//
//    /*
//     * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
//     * nrounds is the number of times the we hash the material. More rounds are more secure but
//     * slower.
//     */
//    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
//    if (i != 32) {
//        printf("Key size is %d bits - should be 256 bits\n", i);
//        return -1;
//    }
//
//    EVP_CIPHER_CTX_init(d_ctx);
//    EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
//
//    return 0;
//}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len) {
    /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = (unsigned char *) malloc(c_len);

    /* allows reusing of 'e' for multiple encryption cycles */
    EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
     *len is the size of plaintext in bytes */
    EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

    /* update ciphertext with the final remaining bytes */
    EVP_EncryptFinal_ex(e, ciphertext + c_len, &f_len);

    *len = c_len + f_len;
    return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len) {
    /* plaintext will always be equal to or lesser than length of ciphertext*/
    int p_len = *len, f_len = 0;
    unsigned char *plaintext = (unsigned char *) malloc(p_len);

    EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
    EVP_DecryptFinal_ex(e, plaintext + p_len, &f_len);

    *len = p_len + f_len;
    return plaintext;
}

//std::array<uint8_t, AES_KEY_SIZE> Utilities::encode3(std::string keyword, unsigned char* key_data) {
//    EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();
//    unsigned int salt[] = {12345, 54321};
//
//    /* gen key and iv. init the cipher ctx object */
//    if (aes_init_enc(key_data, AES_KEY_SIZE, (unsigned char *) &salt, en)) {
//        printf("Couldn't initialize AES cipher\n");
//    }
//
//    /* encrypt and decrypt each input string and compare with the original */
//
//    int olen, len;
//
//    /* The enc/dec functions deal with binary data and not C strings. strlen() will 
//       return length of the string without counting the '\0' string marker. We always
//       pass in the marker byte to the encrypt/decrypt functions so that after decryption 
//       we end up with a legal C string */
//    olen = len = AES_KEY_SIZE + 1;
//    unsigned char* c = aes_encrypt(en, (unsigned char *) keyword.data(), &len);
//    std::array<uint8_t, AES_KEY_SIZE> ciphertext;
//    memcpy(ciphertext.data(), c, AES_KEY_SIZE);
//
//    EVP_CIPHER_CTX_free(en);
//    return ciphertext;
//}

//void Utilities::decode3(std::array<uint8_t, AES_KEY_SIZE> ciphertext, std::array<uint8_t, AES_KEY_SIZE>& plaintext, unsigned char* key_data) {
//    /* "opaque" encryption, decryption ctx structures that libcrypto uses to record
//         status of enc/dec operations */
//    EVP_CIPHER_CTX* de = EVP_CIPHER_CTX_new();
//
//    /* 8 bytes to salt the key_data during key generation. This is an example of
//       compiled in salt. We just read the bit pattern created by these two 4 byte 
//       integers on the stack as 64 bits of contigous salt material - 
//       ofcourse this only works if sizeof(int) >= 4 */
//    unsigned int salt[] = {12345, 54321};
//
//
//    /* gen key and iv. init the cipher ctx object */
//    if (aes_init_dec(key_data, AES_KEY_SIZE, (unsigned char *) &salt, de)) {
//        printf("Couldn't initialize AES cipher\n");
//    }
//
//    /* encrypt and decrypt each input string and compare with the original */
//    int olen, len;
//
//    /* The enc/dec functions deal with binary data and not C strings. strlen() will 
//       return length of the string without counting the '\0' string marker. We always
//       pass in the marker byte to the encrypt/decrypt functions so that after decryption 
//       we end up with a legal C string */
//    olen = len = AES_KEY_SIZE + 1;
//    char* p = (char *) aes_decrypt(de, ciphertext.data(), &len);
//    memcpy(plaintext.data(), p, AES_KEY_SIZE);
//
//
//    EVP_CIPHER_CTX_free(de);
//
//}

