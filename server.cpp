#include <iostream>
#include <system_error>
#include "listener.h"
#include "worker.h"
#include "server_error.h"
#include "interface.h"
#include "database.h"
#include "logger.h"

int main(int argc, char **argv)
{
    try {
        // Загружаем базу данных пользователей
        UserDatabase::getInstance().loadFromFile("users.db");
        Logger::getInstance().log("Database loaded successfully");
        
        Variant v(argc, argv);
        Worker w(v.getType(), v.getHash(), v.getSide());
        Listener server;
        
        Logger::getInstance().log("Server started with parameters: " + 
            std::string(v.getType()) + ":" + 
            std::string(v.getHash()) + ":" + 
            std::string(v.getSide()));

        server.Run(w);
    } catch (std::system_error &e) {
        Logger::getInstance().log("System error occurred: " + std::string(e.what()));
        std::cerr << e.what() << std::endl;
        std::quick_exit(2);
    } catch (option_error &e) {
        Logger::getInstance().log("Option error occurred: " + std::string(e.what()));
        std::cerr << e.what() << std::endl;
        Variant::print_help_and_exit(1);
    } catch (std::exception &e) {
        Logger::getInstance().log("Unexpected error: " + std::string(e.what()));
        std::cerr << "Unexpected error: " << e.what() << std::endl;
        std::quick_exit(3);
    }
    return 0;
}
