#pragma once
#include <fstream>
#include <string>
#include <ctime>

class Logger {
public:
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    void log(const std::string& message) {
        time_t now = time(0);
        std::string timestamp = ctime(&now);
        timestamp.pop_back(); // Удаляем символ новой строки
        logFile << "[" << timestamp << "] " << message << std::endl;
        logFile.flush();
    }

private:
    Logger() {
        logFile.open("server.log", std::ios::app);
    }
    ~Logger() {
        if (logFile.is_open()) {
            logFile.close();
        }
    }
    std::ofstream logFile;
};
