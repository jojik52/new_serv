// database.h
#include <map>
#include <string>
#include <fstream>
#include <iostream>

class UserDatabase {
public:
    static UserDatabase& getInstance() {
        static UserDatabase instance;
        return instance;
    }

    bool validateUser(const std::string& username, const std::string& password) {
        auto it = users.find(username);
        if (it != users.end()) {
            Logger::getInstance().log("User found, checking password");
            return it->second == password;
        }
        Logger::getInstance().log("User not found in database");
        return false;
    }

    void loadFromFile(const std::string& filename) {
        std::ifstream file(filename);
        std::string username, password;
        while (file >> username >> password) {
            users[username] = password;
        }
        Logger::getInstance().log("Loaded users from database");
    }

private:
    UserDatabase() {} // Приватный конструктор для синглтона
    std::map<std::string, std::string> users;
};
