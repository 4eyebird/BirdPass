#include "TOTP.h"
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <queue>
#include <sstream>
#include <stack>
#include <string>
#include <vector>
using namespace std;
typedef std::vector<unsigned char> bytes;


void TOTP::reset_key(const string& key)
{
    h_key = base32_decode(key);
}

void TOTP::reset_key(const vector<unsigned char>& key)
{
    h_key = key;
}

string TOTP::getToken(int Ts)
{
    bytes h_msg = tim2bytes(getTimeSign(refreshSeconds) + Ts);

    unsigned int out_hmac_length;
    unsigned char out_hmac[UINT_LENGTH_SHA1]; // perform openssl function to calculate HMAC-SHA1 hash
    HMAC(EVP_sha1(), h_key.data(), (int)h_key.size(), h_msg.data(), (int)h_msg.size(), out_hmac, &out_hmac_length);

    return hash_to_TOTP(out_hmac, out_hmac_length, digit); // calculate TOTP according to RFC-6238/4226
}

vector<string> TOTP::getTokens()
{
    time_t now = getTimeSign(refreshSeconds);

    unsigned int out_hmac_length;
    unsigned char out_hmac[UINT_LENGTH_SHA1]; // perform openssl function to calculate HMAC-SHA1 hash

    vector<string> ret;

    bytes h_msg = tim2bytes(now - 1);
    HMAC(EVP_sha1(), h_key.data(), (int)h_key.size(), h_msg.data(), (int)h_msg.size(), out_hmac, &out_hmac_length);
    ret.push_back(hash_to_TOTP(out_hmac, out_hmac_length, digit));

    h_msg = tim2bytes(now);
    HMAC(EVP_sha1(), h_key.data(), (int)h_key.size(), h_msg.data(), (int)h_msg.size(), out_hmac, &out_hmac_length);
    ret.push_back(hash_to_TOTP(out_hmac, out_hmac_length, digit));

    h_msg = tim2bytes(now + 1);
    HMAC(EVP_sha1(), h_key.data(), (int)h_key.size(), h_msg.data(), (int)h_msg.size(), out_hmac, &out_hmac_length);
    ret.push_back(hash_to_TOTP(out_hmac, out_hmac_length, digit));

    return ret;
}


time_t TOTP::getTimeSign(const int refreshPeriod)
{
    auto now = chrono::system_clock::now();
    time_t currentUnixTime = chrono::system_clock::to_time_t(now);
    time_t outTime = currentUnixTime / refreshPeriod;
    return outTime;
}

bytes TOTP::tim2bytes(time_t tt)
{
    bytes bytes;
    for(int i = sizeof(tt) - 1; i >= 0; i--)
    {
        bytes.push_back((unsigned char)((tt >> (i * 8)) & 0xFF));
    }
    return bytes;
}

string TOTP::hash_to_TOTP(unsigned char* hmac, unsigned int length, int digit)
{
    ostringstream ss;
    ss << hex << setfill('0');
    for(size_t i = 0; i < length; i++)
    {
        ss << setw(2) << (int)(hmac[i]);
    }

    string raw_key = ss.str();
    unsigned overflow_key = stoul(raw_key.substr((size_t)((int)hmac[19] % 16 * 2), 8), nullptr, 16);

    int safe_key = overflow_key & 0x7fffffff;

    auto pow10 = [](int x) {
        int ret = 1;
        while(x--)
        {
            ret *= 10;
        }
        return ret;
        };
    int out_key = safe_key % pow10(digit);

    ostringstream result_ss;
    result_ss << setw(digit) << setfill('0') << out_key;

    return result_ss.str();
}

bytes TOTP::base32_decode(const string& base32)
{
    queue<bool> de_bits;
    for(char c : base32) // base32 to bits
    {
        int x = 0;
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