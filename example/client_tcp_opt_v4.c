// ask for linux version >= 5.4.56.bsk.2
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>  /* for TCP_XXX defines */

#define TCP_TOA_RADDR		103     /* set CIP*/

#define MAXLINE 4096


int parse_args(int argc, char** argv, 
        struct sockaddr_in* server_addr,
        struct sockaddr_in* option_addr)
{
    int port_;

    if  (argc != 5)
    {   printf("usage: %s <server ip> <server port> <option ip> <option port>\n", argv[0]);
        return -1;
    }

    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    if  (inet_pton(AF_INET, argv[1], &server_addr->sin_addr) <= 0)
    {   perror("bad server ip: ");
        return -1;
    }

    if  (sscanf(argv[2], "%d", &port_) < 0)
    {   perror("bad server prot: ");
        return -1;
    }
    server_addr->sin_port = ntohs((short)port_);

    memset(option_addr, 0, sizeof(*option_addr));
    option_addr->sin_family = AF_INET;
    if  (inet_pton(AF_INET, argv[3], &option_addr->sin_addr) <= 0)
    {   perror("bad option ip: ");
        return -1;
    }

    if  (sscanf(argv[4], "%d", &port_) < 0)
    {   perror("bad option port: ");
        return -1;
    }
    option_addr->sin_port = htons((short)port_);

    return 0;
}

int main(int argc, char** argv)
{
    struct sockaddr_in server_addr, option_addr;
    int fd = -1;

    if  (parse_args(argc, argv, &server_addr, &option_addr) < 0)
        return -1;

    
    if  ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {   perror("socket error");
        return -1;
    }

    if  (setsockopt(fd, IPPROTO_TCP, TCP_TOA_RADDR, &option_addr, sizeof(option_addr)) < 0)
    {   perror("setsockopt error");
        return -1;
    }

    if  (connect(fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {   perror("connect error");
        return -1;
    }



    #define buf_size 64
    char buf[buf_size] = "hello world";

    int sent = send(fd, buf, strlen(buf), 0);
    

    // sleep(1);

    close(fd);

    return 0;
}
