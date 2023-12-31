#pragma once
#include <string>
#include <vector>

namespace AES
{
    // ECB ģʽ����
    void ecb_encrypt(const unsigned char* input, const unsigned char* key, const int bok, unsigned char* output, size_t length);

    // ECB ģʽ����
    void ecb_decrypt(const unsigned char* input, const unsigned char* key, const int bok, unsigned char* output, size_t length);

    // CBC ģʽ����
    void cbc_encrypt(const unsigned char* input, const unsigned char* key, unsigned char* iv, const int bok, unsigned char* output, size_t length);

    // CBC ģʽ����
    void cbc_decrypt(const unsigned char* input, const unsigned char* key, unsigned char* iv, const int bok, unsigned char* output, size_t length);

}