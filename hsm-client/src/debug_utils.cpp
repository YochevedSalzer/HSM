#include <cstdint>
#include <iomanip>

#include <iostream>
#include "../include/debug_utils.h"
#include "debug_utils.h"
using namespace std;

#define DEBUG
#define LOG_BUFFERS
void printBufferHexa(const uint8_t *buffer, size_t len, std::string message)
{
#ifdef DEBUG
    std::cout << message << std::endl;
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(buffer[i]) << " ";
        // Print a new line every 16 bytes for better readability
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    std::cout << std::endl;
    // Reset the stream format back to decimal
    std::cout << std::dec;
#endif
}

void logBufferHexa(const void *voidBuffer, size_t len,
                   const std::string &message, int id,
                   const char *callingFunction, int line)
{
#ifdef LOG_BUFFERS
    const uint8_t *buffer = static_cast<const uint8_t *>(voidBuffer);
    // Accumulate the message and buffer data in a single string
    std::ostringstream oss;
    oss << message << " id: " << std::to_string(id) << std::endl;
    oss << " (function: " << callingFunction << ", line:" << line << ")\n";

    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(buffer[i]) << " ";
        // Add a new line every 16 bytes for readability
        if ((i + 1) % 16 == 0)
            oss << std::endl;
    }

    // Append a final newline after the buffer, if needed
    if (len % 16 != 0)
        oss << std::endl;

    // Reset the stream back to decimal
    oss << std::dec;

    DebugLogger::getInstance().log(oss.str());
#endif
}

// Definition of the debugLog function
void debugLog(const std::string &message, const std::string &functionName)
{
    std::ostringstream oss;
    oss << "Function: " << functionName << " -> " << message << std::endl;
    DebugLogger::getInstance().log(oss.str());
}

DebugLogger::DebugLogger()
{
    std::string filename = "debug_" + currentDateTime() + ".log";
    logFile.open(filename, std::ios::trunc);
    if (!logFile.is_open()) {
        std::cerr << "Error: Could not open debug log file!" << std::endl;
    }
}

void DebugLogger::log(const std::string &message)
{
    if (logFile.is_open()) {
        logFile << currentDateTime() << " [DEBUG] " << message << std::endl;
    }
}

std::string DebugLogger::currentDateTime()
{
    std::time_t now = std::time(nullptr);
    char buf[20];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return buf;
}

DebugLogger &DebugLogger::getInstance()
{
    static DebugLogger instance;
    return instance;
}