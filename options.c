#include "options.h"
#include "version.h"
#include "syshead.h"
#include "logger.h"
#include "basic.h"

void print_version()
{
    logger(LOG_INFO, "%s", PACKAGE_STRING);
    logger(LOG_INFO, "%s", PACKAGE_COPYRIGHT);
    logger(LOG_INFO, "Updated : %s", PACKAGE_LAST_UPDATE);
    logger(LOG_INFO, "Developed by : %s", PACKAGE_BUGREPORT);
}

void print_options(options *o)
{
    char buf[64] = {
        0,
    };
    logger(LOG_DEBUG, "     [   Options   ]");
    logger(LOG_DEBUG, "          MODE: %s", o->mode == 1 ? "Server" : "Client");
    logger(LOG_DEBUG, "   Packet dump: %s", o->file);
    logger(LOG_DEBUG, "Server address: %s", o->address);
    logger(LOG_DEBUG, "   Server port: %d", o->port);

    if (o->output & LOG_TERMINAL)
    {
        strcat(buf, "Terminal ");
    }
    if (o->output & LOG_FILE)
    {
        strcat(buf, "File ");
    }
    if (o->output & LOG_SYSLOG)
    {
        strcat(buf, "Syslog ");
    }

    logger(LOG_DEBUG, "     Log Ouput: %s", buf);
    logger(LOG_DEBUG, "     Log Level: %d", o->log_level);
    if (o->output & 2)
        logger(LOG_DEBUG, "     Log File: %s", o->log_file);

    logger(LOG_DEBUG, "");
}

void usage()
{
    printf("\n");
    printf("General Options:\n");
    //printf("-m   : choose operation Mode (server, client)\n");
    printf("-r   : Read tcpdump file\n");
    printf("-d   : specify Destination ip Address\n");
    printf("-p   : specify destination Port\n");
    //printf("-o   : Output options (1: console, 2: file, 4: syslog)\n");
    //printf("-l   : set log Level\n");
    //printf("-f   : log File path\n");
    printf("-s   : Show packet dump\n");
    printf("-v   : show copyright and Version\n");
    printf("\n");
}

void init_options(options *o)
{
    o->mode = 0;
    o->output = 1;
    o->log_level = 1;
    o->port = 0;
    o->show = 0;
    o->file = NULL;
    o->address = NULL;
    o->log_file = "/var/log/packet-replay.log";
}

int add_options(options *o, char *p[])
{
    if (strcmp("m", p[0]) == 0 && p[1] != NULL)
    {
        if (strcmp("server", p[1]) == 0)
        {
            o->mode = 1;
        }
    }
    else if (strcmp("l", p[0]) == 0 && p[1] != NULL)
    {
        o->log_level = atoi(p[1]);
    }
    else if (strcmp("r", p[0]) == 0 && p[1] != NULL)
    {
        o->file = (char *)malloc(strlen(p[1]) * sizeof(char) + 1);
        memset(o->file, 0, strlen(p[1]) * sizeof(char) + 1);
        memcpy(o->file, p[1], strlen(p[1]) * sizeof(char) + 1);
    }
    else if (strcmp("d", p[0]) == 0 && p[1] != NULL)
    {
        o->address = (char *)malloc(strlen(p[1]) * sizeof(char) + 1);
        memset(o->address, 0, strlen(p[1]) * sizeof(char) + 1);
        memcpy(o->address, p[1], strlen(p[1]) * sizeof(char) + 1);
    }
    else if (strcmp("p", p[0]) == 0 && p[1] != NULL)
    {
        o->port = atoi(p[1]);
    }
    else if (strcmp("o", p[0]) == 0 && p[1] != NULL)
    {
        int num = atoi(p[1]);
        if (0 < atoi(p[1]) < 8)
        {
            o->output = num;
        }
    }
    else if (strcmp("l", p[0]) == 0 && p[1] != NULL)
    {
        o->log_level = atoi(p[1]);
    }
    else if (strcmp("f", p[0]) == 0 && p[1] != NULL)
    {
        o->log_file = (char *)malloc(strlen(p[1]) * sizeof(char) + 1);
        memset(o->log_file, 0, strlen(p[1]) * sizeof(char) + 1);
        memcpy(o->log_file, p[1], strlen(p[1]) * sizeof(char) + 1);
    }
    else if (strcmp("v", p[0]) == 0)
    {
        print_version();
        return 1;
    }
    else if (strcmp("s", p[0]) == 0)
    {
       o->show = 1;
    }
    else
    {
        usage();
        return 1;
    }
    return 0;
}

int check_options(options *o)
{
    if (o->file == NULL)
    {
        return 1;
    }
    return 0;
}

int parse_argv(options *o, int argc, char **argv)
{
    int i, j, ret;

    init_options(o);

    if (argc <= 1)
    {
        usage();
        return 1;
    }

    for (i = 1; i < argc; i++)
    {
        char *p[MAX_PARAMS];
        CLEAR(p);
        p[0] = argv[i];
        if (strncmp(p[0], "-", 1))
        {
            logger(LOG_ERROR, "Cannot parse option : %s", p[0]);
            return 1;
        }
        else
        {
            p[0] += 1;
        }

        for (j = 1; j < MAX_PARAMS; ++j)
        {
            if (i + j < argc)
            {
                char *arg = argv[i + j];
                if (strncmp(arg, "-", 1))
                {
                    p[j] = arg;
                }
                else
                {
                    break;
                }
            }
        }
        i += j - 1;
        ret = add_options(o, p);
        if (ret)
            return 1;
    }

    if (check_options(o))
    {
        usage();
        return 1;
    }

    print_options(o);

    return 0;
}
