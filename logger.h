#ifndef LOGGER_H
#define LOGGER_H

#define logger(level, fmt, ...) logger_(level , __FUNCTION__, fmt, ##__VA_ARGS__)
void logger_(int level, const char* funcname, void* format, ...);


#endif