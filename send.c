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
        int sockfd, bytes, sent, received=0, total = 0, res, opt;
        char response[4096] = {
            0,
        };
        char header[8] = {0};
        char ip_address[INET_ADDRSTRLEN] = {
            0,
        };

        if (host == NULL)
        {
                logger(LOG_ERROR, "Error, Host Null Address");
                return 1;
        }

        /* create the socket */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
                logger(LOG_ERROR, "Error Occured opening socket");
                return 1;
        }

        /* lookup the ip address */
        server = gethostbyname(host);
        for (int i = 0; server->h_addr_list[i] != NULL; i++)
        {
                inet_ntop(AF_INET, server->h_addr_list[i], ip_address, INET_ADDRSTRLEN);
        }

        /* fill in the structure */
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        serv_addr.sin_addr.s_addr = inet_addr(ip_address);

        res = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (res < 0)
        {
                logger(LOG_ERROR, "Error connecting %d - %s", errno, strerror(errno));
        }

        /* send data length first */
        sprintf(header, "%d", data_size);
        send(sockfd, header, 8, 0);

        /* send data */
        sent = send(sockfd, data, data_size, 0);
        logger(LOG_INFO, "sent : %d", sent);

        /* receive response  */
        while (total < data_size)
        {
                received = recv(sockfd, response+received, data_size, 0);
                if (received < 0)
                        break;
                else if (received == 0)
                        break;

                total += received;
        }

        /* close the socket */
        close(sockfd);

        /* process response */
        logger(LOG_INFO, "response: ( %d bytes )", received);
        dump_hex(response, received);

        return 0;
}