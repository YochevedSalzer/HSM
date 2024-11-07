#include "general.h"

void log(logger::LogLevel level, const std::string &message)
{
    static logger logInstance("HSM(client)");
    logInstance.logMessage(level, message);
}
