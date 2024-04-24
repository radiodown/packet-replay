#include "syshead.h"
#include "options.h"
#include "logger.h"
#include "send.h"

#define BUF_SIZE 4096

void *request(void *conn)
{
        char header[8] = {
            0,
        };
        char request[BUF_SIZE] = {
            0,
        };
        int data_size = 0, received = 0, sent = 0, total = 0;



        /* recv data size first*/
        recv(conn, header, 8, 0);

        data_size = atoi(header);
        //logger(LOG_INFO, "%d header received", data_size);

        /* recv data */
        while (total < data_size)
        {
                received = recv(conn, request+received, data_size, 0);
                if (received < 0)
                        break;
                else if (received == 0)
                        break;
                total+=received;
                logger(LOG_INFO, " + %d received", received);
        }

        /* send data */
        sent = send(conn, request, total, 0);
        logger(LOG_INFO, " - %d sent", sent);

        if(total-  sent ==0){
                logger(LOG_INFO, "completely transfered ");
        }

        close(conn);

        return NULL;
}

int server(int port)
{

        int sock = 0, conn = 0, size;
        struct sockaddr_in serv_addr;
        pthread_t pthread;

        memset(&serv_addr, '0', sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        serv_addr.sin_port = htons(port);
        size = sizeof(serv_addr);

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
                logger(LOG_ERROR, "Error, socket creation");
                return 1;
        }

        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

        if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
                logger(LOG_ERROR, "Error, calling bind()");
                return 1;
        }

        if ((listen(sock, 10)) == -1)
        {
                logger(LOG_INFO, "Error, Listening");
                return 1;
        }

        for (;;)
        {
                conn = accept(sock, (struct sockaddr *)&serv_addr, &size);
                if (conn == -1)
                        logger(LOG_WARN, "Error, accepting connection \n");

                int *arg = malloc(sizeof(*arg));
                arg = conn;

                if (pthread_create(&pthread, NULL, request, arg) != 0)
                        logger(LOG_WARN, "Error, pthread_create");
        }

        return 0;
}