#pragma once
#include <string>
#include <vector>


class TOTP
{
public:

    TOTP() {}
    TOTP(const std::string& key): h_key(base32_decode(key)) {}
    TOTP(const std::vector<unsigned char>& key): h_key(key) {}

    void reset_key(const std::string& key);

    void reset_key(const std::vector<unsigned char>& key);

    std::string getToken(int Ts = 0);

    std::vector<std::string> getTokens();

private:

    std::vector<unsigned char> h_key;
    int digit = 6, refreshSeconds = 30;
    static const int UINT_LENGTH_SHA1 = 20;

protected:

    time_t getTimeSign(const int refreshPeriod);
    std::vector<unsigned char> tim2bytes(time_t tt);
    std::string hash_to_TOTP(unsigned char* hmac, unsigned int length, int digit);
    std::vector<unsigned char> base32_decode(const std::string& base32);

};