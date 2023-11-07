#ifndef LOG_H
#define LOG_H

#ifndef NO_LOGGING
#define info(...)    _info(__VA_ARGS__)
#define warning(...) _warning(__VA_ARGS__)
#define error(...)   _error(__VA_ARGS__)
#define panic(...)   _panic(__VA_ARGS__)
#else
#define info(...)    (void)0
#define warning(...) (void)0
#define error(...)   (void)0
#define panic(...)   abort()
#endif

#ifndef DEBUG_LOGGING
#define debug(...) _debug(__VA_ARGS__)
#else
#define debug(...) (void)0
#endif

void _debug(const char* fmt, ...);
void _info(const char* fmt, ...);
void _warning(const char* fmt, ...);
void _error(const char* fmt, ...);
void _panic(const char* fmt, ...);

#endif
