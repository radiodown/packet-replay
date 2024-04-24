#ifndef OPTIONS_H
#define OPTIONS_H

/* Log Output deive (sticky bits) */
#define LOG_TERMINAL    0b001
#define LOG_FILE        0b010
#define LOG_SYSLOG      0b100

/* Log Level */
#define LOG_TRACE   6
#define LOG_DEBUG   5
#define LOG_INFO    4
#define LOG_WARN    3
#define LOG_ERROR   2
#define LOG_FATAL   1

/* Max Parameter Count (include option name) */
#define MAX_PARAMS 16

/* Operation Mode */
#define MODE_CLIENT 0
#define MODE_SERVER 1

struct __options{
    int mode;       /* operation mode */

    char* file;    /* tcpdump file path */
    
    char* address;  /* dest ip */
    int port;       /* dest port */

    int output;     /* log output device */
    int log_level;  /* log level */
    char* log_file; /* log file path */
    int show;       /* Show packet dump */

} typedef options;

int parse_argv(options *o, int argc, char **argv);


#endif /* OPTIONS_H */