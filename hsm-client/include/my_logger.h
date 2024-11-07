#ifndef MY_LOGGER_H
#define MY_LOGGER_H

#include <string>
#include <fstream>
#include <mutex>
#include "../../logger/logger.h"

void log(logger::LogLevel loglevel, const std::string &hsm_id,
         const std::string &user_id, const std::string &message);
std::string dataToHex(const unsigned char *data, size_t size);
int getId();

#endif  // MY_LOGGER_H
