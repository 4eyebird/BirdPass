#pragma once
#ifndef LIB_SM4_H
#define LIB_SM4_H

//https://github.com/tonyonce2017/SM4

#include <string>
#include <vector>

class sm4 {
public:
    enum Type{
        ECB,
        CBC
    };
public:
    explicit sm4();
    ~sm4();
    void setKey(const std::vector<unsigned char>& k);
    void setIv(const std::vector<unsigned char>& i);
    void setType(Type t = Type::ECB);

    std::vector<unsigned char> encrypt(const std::string& data);
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data);
    std::string decrypt(const std::vector<unsigned char>& data);

private:
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
    Type type;
};

#endif //LIB_SM4_H
