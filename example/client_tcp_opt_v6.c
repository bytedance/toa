// ask for linux version >= 5.4.56.bsk.2
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  /* for TCP_XXX defines */
#include <arpa/inet.h>


#define TCP_TOA_RADDR		103     /* set CIP*/




int get_addr_v6(const char* addr_s, const char* port_s, struct sockaddr_in6* addr)
{
    memset(addr, 0, sizeof(*addr));
    addr->sin6_family = AF_INET6;

    if  (inet_pton(AF_INET6, addr_s, &addr->sin6_addr) <= 0)
    {   printf("bad addr: %s\n", addr_s);
        return -1;
    }

    char tmp_addr[100];
    inet_ntop(AF_INET6, &addr->sin6_addr, tmp_addr, 100);
    printf("addr: %s\n", tmp_addr);


    int port_ = 0;
    if  (sscanf(port_s, "%d", &port_) < 0)
    {   printf("bad port: %s\n", port_s);
        return -1;
    }
    printf("port_: %d\n", port_);
    addr->sin6_port = htons((short)port_);

    return 0;
}

int parse_args(int argc, char** argv, 
        struct sockaddr_in6* server_addr,
        struct sockaddr_in6* option_addr)
{
    if  (argc != 5)
    {   printf("usage: %s <server ip> <server port> <option ip> <option port>\n", argv[0]);
        return -1;
    }

    if  (get_addr_v6(argv[1], argv[2], server_addr) < 0)
    {   printf("bad server_addr\n");
        return -1;
    }

    if  (get_addr_v6(argv[3], argv[4], option_addr) < 0)
    {   printf("bad option_addr\n");
        return -1;
    }


    return 0;
}

int main(int argc, char** argv)
{
    struct sockaddr_in6 server_addr, option_addr;
    int fd = -1;

    if  (parse_args(argc, argv, &server_addr, &option_addr) < 0)
        return -1;


    
    if  ((fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
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
    

    // // sleep(1);

    close(fd);

    return 0;
}
