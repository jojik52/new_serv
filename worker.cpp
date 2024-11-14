#include <iostream>
#include <memory>
#include <algorithm>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include "worker.h"
#include "server_error.h"
#include "database.h"
#include "logger.h"

Worker::Worker(std::string_view t, std::string_view h, std::string_view s)
    : type(t), hash(h), side(s), work_sock(-1)
{
    std::clog << "log: Выбранный вариант " << type << ':' << hash << ':' << side << std::endl;
    Logger::getInstance().log("Worker initialized with type:" + std::string(type) + 
                            " hash:" + std::string(hash) + 
                            " side:" + std::string(side));
    
    if (hash == "SHA1")
        hash_ptr = new CPP::SHA1;
    std::clog << "log: digest size: " << hash_ptr->DigestSize() << std::endl;
}

Worker::~Worker()
{
    delete hash_ptr;
}

void Worker::operator()(int sock)
{
    work_sock = sock;
    Logger::getInstance().log("New connection accepted on socket: " + std::to_string(sock));
    
    if (side == "client")
        auth_with_salt_at_client_side(*hash_ptr);
    calculate();
}

template <typename T>
void Worker::calc()
{
    uint32_t num_vectors, vector_len;
    int rc;
    std::clog << "log: Start calculate with type " << typeid(T).name() << std::endl;
    Logger::getInstance().log("Starting calculation with type: " + std::string(typeid(T).name()));

    rc = recv(work_sock, &num_vectors, sizeof num_vectors, 0);
    if (rc == -1) {
        Logger::getInstance().log("Error receiving number of vectors");
        throw std::system_error(errno, std::generic_category(), "Recv number of vectors error");
    }

    std::clog << "log: Numbers of vectors " << num_vectors << std::endl;
    Logger::getInstance().log("Processing " + std::to_string(num_vectors) + " vectors");

    for (uint32_t i = 0; i < num_vectors; ++i) {
        rc = recv(work_sock, &vector_len, sizeof vector_len, 0);
        if (rc == -1) {
            Logger::getInstance().log("Error receiving vector size for vector " + std::to_string(i));
            throw std::system_error(errno, std::generic_category(), "Recv vector size error");
        }

        std::clog << "log: Vector " << i << " size " << vector_len << std::endl;
        std::unique_ptr<T[]> data(new T[vector_len]);
        std::clog << "log: Memory allocated at " << data.get() << std::endl;

        rc = recv(work_sock, data.get(), sizeof(T) * vector_len, 0);
        std::clog << "log: Received " << rc << " bytes of vector\n";
        
        if (rc == -1) {
            Logger::getInstance().log("Error receiving vector data for vector " + std::to_string(i));
            throw std::system_error(errno, std::generic_category(), "Recv vector error");
        } else if (sizeof(T) * vector_len != (uint32_t)rc) {
            Logger::getInstance().log("Vector size mismatch for vector " + std::to_string(i));
            throw vector_error("Vector error: mismatch actual and expected size");
        }

        T sum = 0;
        for (uint32_t j = 0; j < vector_len; ++j) {
            sum += data[j];
            if (std::is_integral<T>::value) {
                if (std::is_signed<T>::value) {
                    if (data[j] > 0 && sum < 0 && (sum - data[j]) > 0) {
                        sum = std::numeric_limits<T>::max();
                        Logger::getInstance().log("Overflow detected in signed calculation");
                        break;
                    } else if (data[j] < 0 && sum > 0 && (sum - data[j]) < 0) {
                        sum = std::numeric_limits<T>::min();
                        Logger::getInstance().log("Underflow detected in signed calculation");
                        break;
                    }
                } else if (sum < data[j]) {
                    sum = std::numeric_limits<T>::max();
                    Logger::getInstance().log("Overflow detected in unsigned calculation");
                    break;
                }
            }
        }

        double average = static_cast<double>(sum) / vector_len;
        rc = send(work_sock, &average, sizeof(double), 0);
        if (rc == -1) {
            Logger::getInstance().log("Error sending result for vector " + std::to_string(i));
            throw std::system_error(errno, std::generic_category(), "Send result error");
        }

        std::clog << "log: Sent vector average " << average << std::endl;
        Logger::getInstance().log("Processed vector " + std::to_string(i) + 
                                " with average: " + std::to_string(average));
    }
}

void Worker::calculate()
{
    Logger::getInstance().log("Starting calculation phase");
    if (type == "int32_t")
        Worker::calc<int32_t>();
}

void Worker::auth_with_salt_at_client_side(CPP::HashTransformation& hash)
{
    int rc;
    std::string message(str_read());
    std::clog << "log: receive MESSAGE: " + message << std::endl;
    Logger::getInstance().log("Received authentication message");

    std::string hash_16(std::max(message.cbegin(), message.cend() - hash.DigestSize() * 2),
                        message.cend());
    message.erase(std::max(message.cbegin(), message.cend() - hash.DigestSize() * 2),
                  message.cend());
    if (message.empty()) {
        Logger::getInstance().log("Authentication error: empty message after hash extraction");
        throw auth_error("Auth error: wrong auth message");
    }
    std::clog << "log: detect HASH: " << hash_16 << std::endl;

    std::string salt_16(std::max(message.cbegin(), message.cend() - 16), message.cend());
    message.erase(std::max(message.cbegin(), message.cend() - 16), message.cend());
    if (message.empty()) {
        Logger::getInstance().log("Authentication error: empty message after salt extraction");
        throw auth_error("Auth error: wrong auth message");
    }
    std::clog << "log: detect SALT: " << salt_16 << std::endl;

    std::string username = message;
    std::clog << "log: detect USERNAME: " << username << std::endl;
    Logger::getInstance().log("Detected USERNAME: " + username);

    std::string expected_password;
    if (UserDatabase::getInstance().validateUser(username, expected_password)) {
        std::string hash_16_calc;
        CPP::StringSource(salt_16 + expected_password, true,
            new CPP::HashFilter(hash, new CPP::HexEncoder(new CPP::StringSink(hash_16_calc))));

        Logger::getInstance().log("Expected hash: " + hash_16_calc);
        Logger::getInstance().log("Received hash: " + hash_16);

        if (hash_16 != hash_16_calc) {
            Logger::getInstance().log("Auth error: password mismatch for user: " + username);
            throw auth_error("Auth error: password mismatch");
        }
    } else {
        Logger::getInstance().log("Auth error: unknown user: " + username);
        throw auth_error("Auth error: unknown user");
    }

    Logger::getInstance().log("Successful authentication for user: " + username);
    std::clog << "log: auth success, sending OK\n";
    
    rc = send(work_sock, "OK", 2, 0);
    if (rc == -1) {
        Logger::getInstance().log("Error sending OK response after successful authentication");
        throw std::system_error(errno, std::generic_category(), "`Send OK' error");
    }
}

#if defined DOUBLING_LOOP
std::string Worker::str_read()
{
    int rc;
    int buflen = BUFLEN;
    std::unique_ptr<char[]> buf(new char[buflen]);
    while (true) {
        rc = recv(work_sock, buf.get(), buflen, MSG_PEEK);
        if (rc == -1) {
            Logger::getInstance().log("Error reading string (DOUBLING_LOOP)");
            throw std::system_error(errno, std::generic_category(), "Recv string error");
        }
        if (rc < buflen)
            break;
        buflen *= 2;
        buf = std::unique_ptr<char[]>(new char[buflen]);
    }
    std::string res(buf.get(), rc);
    rc = recv(work_sock, nullptr, rc, MSG_TRUNC);
    if (rc == -1) {
        Logger::getInstance().log("Error clearing buffer");
        throw std::system_error(errno, std::generic_category(), "Clear buffer error");
    }
    res.resize(res.find_last_not_of("\n\r") + 1);
    return res;
}

#elif defined READING_TAIL

std::string Worker::str_read()
{
    int rc;
    int buflen = BUFLEN;
    std::unique_ptr<char[]> buf(new char[buflen]);
    rc = recv(work_sock, buf.get(), buflen, 0);
    if (rc == -1) {
        Logger::getInstance().log("Error reading string (READING_TAIL)");
        throw std::system_error(errno, std::generic_category(), "Recv string error");
    }
    std::string res(buf.get(), rc);
    if (rc == buflen) {
        int tail_size;
        rc = ioctl(work_sock, FIONREAD, &tail_size);
        if (rc == -1) {
            Logger::getInstance().log("Error in ioctl operation");
            throw std::system_error(errno, std::generic_category(), "IOCTL error");
        }
        if (tail_size > 0) {
            if (tail_size > buflen)
                buf = std::unique_ptr<char[]>(new char[tail_size]);
            rc = recv(work_sock, buf.get(), tail_size, 0);
            if (rc == -1) {
                Logger::getInstance().log("Error reading tail data");
                throw std::system_error(errno, std::generic_category(), "Recv string error");
            }
            res.append(buf.get(), rc);
        }
    }
    res.resize(res.find_last_not_of("\n\r") + 1);
    return res;
}

#else
std::string Worker::str_read()
{
    int buflen = BUFLEN;
    std::unique_ptr<char[]> buf(new char[buflen]);
    int rc = recv(work_sock, buf.get(), buflen, 0);
    if (rc == -1) {
        Logger::getInstance().log("Error reading string (default method)");
        throw std::system_error(errno, std::generic_category(), "Recv string error");
    }
    std::string res(buf.get(), rc);
    res.resize(res.find_last_not_of("\n\r") + 1);
    return res;
}
#endif
