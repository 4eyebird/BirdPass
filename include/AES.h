#pragma once
#include <string>
#include <vector>

namespace AES
{
    // ECB 模式加密
    void ecb_encrypt(const unsigned char* input, const unsigned char* key, const int bok, unsigned char* output, size_t length);

    // ECB 模式解密
    void ecb_decrypt(const unsigned char* input, const unsigned char* key, const int bok, unsigned char* output, size_t length);

    // CBC 模式加密
    void cbc_encrypt(const unsigned char* input, const unsigned char* key, unsigned char* iv, const int bok, unsigned char* output, size_t length);

    // CBC 模式解密
    void cbc_decrypt(const unsigned char* input, const unsigned char* key, unsigned char* iv, const int bok, unsigned char* output, size_t length);

}