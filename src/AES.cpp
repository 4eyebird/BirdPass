#include "AES.h"
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/aes.h>
#include <sstream>
#include <vector>
using namespace std;
typedef std::vector<unsigned char> bytes;

namespace AES
{

    // ECB 模式加密
    void ecb_encrypt(const unsigned char* input, const unsigned char* key, const int bok, unsigned char* output, size_t length)
    {
        AES_KEY aesKey;
        AES_set_encrypt_key(key, bok, &aesKey);

        for(size_t i = 0; i < length; i += AES_BLOCK_SIZE)
        {
            AES_encrypt(input + i, output + i, &aesKey);
        }
    }

    // ECB 模式解密
    void ecb_decrypt(const unsigned char* input, const unsigned char* key, const int bok, unsigned char* output, size_t length)
    {
        AES_KEY aesKey;
        AES_set_decrypt_key(key, bok, &aesKey);

        for(size_t i = 0; i < length; i += AES_BLOCK_SIZE)
        {
            AES_decrypt(input + i, output + i, &aesKey);
        }
    }

    // CBC 模式加密
    void cbc_encrypt(const unsigned char* input, const unsigned char* key, unsigned char* iv, const int bok, unsigned char* output, size_t length)
    {
        AES_KEY aesKey;
        AES_set_encrypt_key(key, bok, &aesKey);

        AES_cbc_encrypt(input, output, length, &aesKey, iv, AES_ENCRYPT);
    }

    // CBC 模式解密
    void cbc_decrypt(const unsigned char* input, const unsigned char* key, unsigned char* iv, const int bok, unsigned char* output, size_t length)
    {
        AES_KEY aesKey;
        AES_set_decrypt_key(key, bok, &aesKey);

        AES_cbc_encrypt(input, output, length, &aesKey, iv, AES_DECRYPT);
    }

}