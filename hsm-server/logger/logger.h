#ifndef LOGGER_H
#define LOGGER_H

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

#ifndef LOG_LEVEL
#define LOG_LEVEL logger::LogLevel::INFO
#endif

class logger {
   public:
    enum class LogLevel {
        ERROR,
        INFO,
        DEBUG,
    };
    logger() {}
    logger(std::string componentName);
    ~logger();
    void logMessage(LogLevel level, const std::string &message);
    void logMessage(LogLevel level, std::string src, std::string dst,
                    const std::string &message);
    void initializeLogFile();
    std::string getLogFileName();
    std::string sharedLogFileName = "shared_log_file_name.txt";
    void cleanUp();

   private:
    static std::string logLevelToString(LogLevel level);
    static bool shouldLog(LogLevel level);
    static std::string getElapsedTime();
    static std::string componentName;
    static std::string logFileName;
    bool isInitialized = false;
    static std::mutex logMutex;
    static std::chrono::system_clock::time_point initTime;
};

#endif  // LOGGER_H
