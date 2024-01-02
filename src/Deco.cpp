#include "Deco.h"
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <queue>
#include <sstream>
#include <stack>
#include <vector>
using namespace std;
typedef std::vector<unsigned char> bytes;

namespace Deco
{
    // byte to hex
    string byte_hex(vector<unsigned char> input)
    {
        string output;
        ostringstream s;
        for(unsigned char c : input)
        {
            s << hex << setw(2) << setfill('0') << (int)(c);
        }
        string out = s.str();
        int len = (int)out.length();
        for(int i = 0; i < len; i++)
            output.push_back(out[i]);
        return output;
    }

    // byte to hex
    string byte_hex(const unsigned char* input, size_t length)
    {
        string output;
        ostringstream s;
        for(size_t i = 0; i < length; ++i)
        {
            s << hex << setw(2) << setfill('0') << (int)(input[i]);
        }
        string out = s.str();
        int len = (int)out.length();
        for(int i = 0; i < len; i++)
            output.push_back(out[i]);
        return output;
    }

    // hex to byte
    bytes hex_byte(const char* input, size_t length)
    {
        bytes ret;

        for(size_t i = 0; i + 1 < length; i += 2)
        {
            char Hex[3] = "";
            Hex[0] = input[i], Hex[1] = input[i + 1], Hex[2] = '\0';
            ret.push_back((int)strtol(Hex, nullptr, 16));
        }
        return ret;
    }

    // string to md5
    bytes md5(const string& message)
    {
        bytes hash(MD5_DIGEST_LENGTH);
        MD5((const unsigned char*)message.c_str(), message.length(), hash.data());
        return hash;
    }

    // string to sha256
    bytes sha256(const string& message)
    {
        bytes ret(SHA256_DIGEST_LENGTH);
        SHA256_CTX sha256Context;
        SHA256_Init(&sha256Context);
        SHA256_Update(&sha256Context, message.c_str(), message.length());
        SHA256_Final(ret.data(), &sha256Context);
        return ret;
    }

    // string to sha512
    bytes sha512(const string& message)
    {
        bytes ret(SHA512_DIGEST_LENGTH);
        SHA512_CTX sha512Context;
        SHA512_Init(&sha512Context);
        SHA512_Update(&sha512Context, message.c_str(), message.length());
        SHA512_Final(ret.data(), &sha512Context);
        return ret;
    }

    // string to sha512 with work factor
    const char WFdict[79] = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1Ll2Mm3Nn4Oo5Pp6Qq7Rr8Ss9Tt0Uu1Vv2Ww3Xx4Yy5Zz6";
    bytes sha512WF(const string& message, const int f1, const int f2)
    {
        int idx = 0;
        bytes ret = sha512(message);
        for(int i = 1; i <= f2; i++)
        {
            string si = message;
            string ci = byte_hex(ret);
            for(int j = 1; j <= f1; j++)
            {
                int rd = 0;
                bytes rdb = sha256(si);
                for(auto& r : rdb)
                    rd += r;
                string ns = ci + WFdict[idx] + WFdict[rd % 78];
                si += byte_hex(sha512(ns));
                if(++idx == 78)idx = 0;
            }
            ret = sha512(si);
        }
        return ret;
    }

    // base32 to byte
    bytes base32_byte(const char* input, size_t length)
    {
        queue<bool> de_bits;
        for(size_t i = 0; i < length; i++) // base32 to bits
        {
            int x = 0;
            char c = input[i];
            if(c >= 'a' && c <= 'z')
                x = c - 'a';
            else if(c >= 'A' && c <= 'Z')
                x = c - 'A';
            else if(c >= '2' && c <= '7')
                x = c - '2' + 26;
            else if(c == '=')
                break;
            else
                return {};

            stack<bool> bt;
            for(int i = 0; i < 5; i++)
            {
                bt.push(x & 1);
                x >>= 1;
            }
            while(!bt.empty())
            {
                de_bits.push(bt.top());
                bt.pop();
            }
        }

        bytes de_bytes;
        while(!de_bits.empty()) // bits to bytes
        {
            int thehex = 0;
            for(int i = 0; i < 8; i++)
            {
                thehex <<= 1;
                if(!de_bits.empty())
                {
                    thehex |= (int)de_bits.front();
                    de_bits.pop();
                }
                else
                {
                    thehex = 0;
                    break;
                }
            }
            de_bytes.push_back(thehex);
        }

        while(de_bytes.back() == 0)
            de_bytes.pop_back();
        return de_bytes;
    }

}