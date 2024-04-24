#include "syshead.h"
#include "basic.h"
#include "send.h"
#include "logger.h"
#include "options.h"

void dump_hex(const void *data, int size)
{
        char ascii[17];
        size_t i, j;
        ascii[16] = '\0';
        for (i = 0; i < size; ++i)
        {
                printf("%02X ", ((unsigned char *)data)[i]);
                if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~')
                {
                        ascii[i % 16] = ((unsigned char *)data)[i];
                }
                else
                {
                        ascii[i % 16] = '.';
                }
                if ((i + 1) % 8 == 0 || i + 1 == size)
                {
                        printf(" ");
                        if ((i + 1) % 16 == 0)
                        {
                                printf("|  %s \n", ascii);
                        }
                        else if (i + 1 == size)
                        {
                                ascii[(i + 1) % 16] = '\0';
                                if ((i + 1) % 16 <= 8)
                                {
                                        printf(" ");
                                }
                                for (j = (i + 1) % 16; j < 16; ++j)
                                {
                                        printf("   ");
                                }
                                printf("|  %s \n", ascii);
                        }
                }
        }
}

int send_tcp(int port, char *host, char *data, int data_size)
{       

        logger(LOG_INFO, "\n[   TCP Assembled DATA  ]");
        logger(LOG_INFO, "Send Payload to %s:%d (%d bytes)", host, port, data_size);

        struct hostent *server;
        struct sockaddr_in serv_addr;
        long arg;
        struct timeval tv;
        fd_set fd;
        socklen_t lon;
        int sockfd, bytes, sent, received, total, res, opt;
        char response[4096] = {
            0,
        };

        if (host == NULL)
        {
                logger(LOG_ERROR,"Error, Host Null Address");
                return 1;
        }

        /* create the socket */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
                logger(LOG_ERROR,"Error Occured opening socket");
                return 1;
        }

        /* lookup the ip address */
        server = gethostbyname(host);
        char ip_address[INET_ADDRSTRLEN] = {
            0,
        };
        for (int i = 0; server->h_addr_list[i] != NULL; i++)
        {
                inet_ntop(AF_INET, server->h_addr_list[i], ip_address, INET_ADDRSTRLEN);
        }

        /* fill in the structure */
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        serv_addr.sin_addr.s_addr = inet_addr(ip_address);

        /* Set non-blocking */
        if ((arg = fcntl(sockfd, F_GETFL, NULL)) < 0)
        {
                logger(LOG_ERROR,"Error fcntl(..., F_GETFL)");
                close(sockfd);
                return 1;
        }
        arg |= O_NONBLOCK;
        if (fcntl(sockfd, F_SETFL, arg) < 0)
        {
                logger(LOG_ERROR,"Error fcntl(..., F_SETFL)");
                close(sockfd);
                return 1;
        }

        res = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (res < 0)
        {
                if (errno == EINPROGRESS)
                {
                        do
                        {
                                // timeout
                                tv.tv_sec = 2;
                                tv.tv_usec = 0;
                                FD_ZERO(&fd);
                                FD_SET(sockfd, &fd);
                                res = select(sockfd + 1, NULL, &fd, NULL, &tv);
                                if (res < 0 && errno != EINTR)
                                {
                                        logger(LOG_ERROR,"Error connecting %d - %s", errno, strerror(errno));
                                        close(sockfd);
                                        return 1;
                                }
                                else if (res > 0)
                                {
                                        // Socket selected for write
                                        lon = sizeof(int);
                                        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void *)(&opt), &lon) < 0)
                                        {
                                                logger(LOG_ERROR,"Error in getsockopt() %d - %s", errno, strerror(errno));
                                                close(sockfd);
                                                return 1;
                                        }
                                        // Check the value returned...
                                        if (opt)
                                        {
                                                if (opt == 111)
                                                {
                                                        close(sockfd);
                                                        logger(LOG_ERROR,"There is no host, Not Sending Payload");
                                                        return 1;
                                                }
                                                logger(LOG_ERROR,"Error in delayed connection() %d - %s", opt, strerror(opt));

                                                close(sockfd);
                                                return 1;
                                        }
                                        break;
                                }
                                else
                                {
                                        logger(LOG_ERROR,"Timeout in select() - Cancelling!");
                                        close(sockfd);
                                        return 1;
                                }
                        } while (1);
                }
                else
                {
                        logger(LOG_ERROR,"Error, connecting server");
                        close(sockfd);
                        return 1;
                }
        }

        // Set to blocking mode again...
        if ((arg = fcntl(sockfd, F_GETFL, NULL)) < 0)
        {
                logger(LOG_ERROR,"Error fcntl(..., F_GETFL)");
                close(sockfd);
                return 1;
        }
        arg &= (~O_NONBLOCK);
        if (fcntl(sockfd, F_SETFL, arg) < 0)
        {
                logger(LOG_ERROR,"Error fcntl(..., F_SETFL)");
                close(sockfd);
                return 1;
        }

        total = data_size;
        sent = 0;

        /* send the request */
        do
        {
                bytes = write(sockfd, data + sent, total);
                if (bytes < 0)
                {
                        close(sockfd);
                        return 1;
                }
                if (bytes == 0)
                {
                        break;
                }
                sent += bytes;
        } while (sent < total);

        write(sockfd, "exit", strlen("exit"));

       logger(LOG_INFO,"sent : %d", sent);

        /* receive the response */
        total = 4096 - 1;
        received = 0;
        do
        {
                bytes = read(sockfd, response + received, total - received);
                if (bytes < 0)
                {
                        close(sockfd);
                        return 1;
                }
                if (bytes == 0)
                {
                        break;
                }
                received += bytes;
        } while (received < total);

        /*
         * if the number of received bytes is the total size of the
         * array then we have run out of space to store the response
         * and it hasn't all arrived yet - so that's a bad thing
         */
        if (received == total)
        {
                logger(LOG_ERROR,"Error, storing complete response from socket");
                close(sockfd);
                return 1;
        }

        /* close the socket */
        close(sockfd);

        /* process response */
        logger(LOG_INFO,"response: ( %d bytes )", received);
        dump_hex(response, received);

        return 0;
}
