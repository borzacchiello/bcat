#include "log.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static void print_common(const char* level, const char* fmt, va_list args)
{
    char str[2048]    = {0};
    char timestr[128] = {0};

    vsnprintf(str, sizeof(str) - 1, fmt, args);

    time_t     rawtime;
    struct tm* timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", timeinfo);

    fprintf(stderr, "%s [ %s ] %s\n", timestr, level, str);
}

void _panic(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    print_common(" PANIC ", fmt, args);
    va_end(args);

    abort();
}

void _debug(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    print_common(" DEBUG ", fmt, args);
    va_end(args);
}

void _info(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    print_common(" INFO  ", fmt, args);
    va_end(args);
}

void _warning(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    print_common("WARNING", fmt, args);
    va_end(args);
}

void _error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    print_common(" ERROR ", fmt, args);
    va_end(args);
}
