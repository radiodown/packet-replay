#include "logger.h"
#include "syshead.h"

void logger_(int level, const char *funcname, void *format, ...)
{
    va_list va;
    va_start(va, format);
    vprintf(format, va);
    printf("\n");
    va_end(va);
}