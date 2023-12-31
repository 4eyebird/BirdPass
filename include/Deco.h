#pragma once
#include <string>
#include <vector>

namespace Deco
{
    // byte to hex
    std::string byte_hex(std::vector<unsigned char> input);

    // byte to hex
    std::string byte_hex(const unsigned char* input, size_t length);

    // hex to bytes
    std::vector<unsigned char> hex_byte(const char* input, size_t length);

    // string to md5
    std::vector<unsigned char> md5(const std::string& message);

    // string to sha256
    std::vector<unsigned char> sha256(const std::string& message);

    // string to sha512
    std::vector<unsigned char> sha512(const std::string& message);

    // string to sha512 with work factor
    std::vector<unsigned char> sha512WF(const std::string& message, const int f1, const int f2);

    // base32 to byte
    std::vector<unsigned char> base32_byte(const char* input, size_t length);
}