#include "../include/general.h"

std::unique_ptr<logger> logInstance;
void log(logger::LogLevel level, const std::string &message)
{
    // Ensure logger instance exists
    if (!logInstance) {
        logInstance = std::make_unique<logger>("HSM");
    }
    logInstance->logMessage(level, message);
}

bool isValidAESKeyLength(AESKeyLength aesKeyLength)
{
    // Create a set of valid key lengths and check if the provided key length is in this set
    switch (aesKeyLength) {
        case AES_128:
        case AES_192:
        case AES_256:
            return true;
        default:
            return false;
    }
}

void signalHandler(int signum)
{
    std::cout << "Interrupt signal (" << signum
              << ") received. Cleaning up resources..." << std::endl;

    // Explicitly delete the logger instance
    logInstance.reset();

    // Exit the program
    exit(signum);
}
