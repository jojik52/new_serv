#pragma once
#include <string>
#include <string_view>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>

#define BUFLEN 1024

// #define DOUBLING_LOOP
#define READING_TAIL

namespace CPP = CryptoPP;

class Worker
{
private:
    std::string_view type;
    std::string_view hash;
    std::string_view side;
    int work_sock;
    std::string str_read();
    CryptoPP::HashTransformation* hash_ptr;
    void auth_with_salt_at_client_side(CPP::HashTransformation& hash);
    void calculate();
    template <typename T> void calc();
public:
    Worker(std::string_view t = "int32_t", std::string_view h = "SHA1", std::string_view s = "client");
    void operator()(int sock);
    ~Worker();
};
