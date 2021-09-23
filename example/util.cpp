#include "util.h"
#include <cstdio>
#include <sys/socket.h>

ssize_t send_full(int fd, const char* msg, size_t len, int flags) 
{
    size_t remaining = len;
    const char* cur = msg;
    ssize_t sent;

    while (remaining > 0) {
        if  ((sent = send(fd, cur, remaining, flags)) == -1)  perror("send");
        cur += sent;
        remaining -= sent;
    }

    return (len - remaining);
}

ssize_t recv_full(int fd, char* msg, size_t len, int flags) {
    size_t remaining = len;
    char* cur = msg;
    ssize_t recvd;

    while (remaining > 0) {
        recvd = recv(fd, cur, remaining, flags);
        if ((recvd == -1) || (recvd == 0)) break;
        cur += recvd;
        remaining -= recvd;
    }

    return (len - remaining);
}








void sockaddr_display(struct sockaddr_in6* addr)
{
    const int addr_buf_size = 100;
    char addr_buf[addr_buf_size];

    if  (addr->sin6_family == AF_INET)
    {
        struct sockaddr_in* sa = (struct sockaddr_in*)addr;
        printf("ipv4: %s:%d\n", inet_ntop(AF_INET, &sa->sin_addr, addr_buf, addr_buf_size), ntohs(sa->sin_port));
    }
    else if  (addr->sin6_family == AF_INET6)
    {
        struct sockaddr_in6* sa = (struct sockaddr_in6*)addr;
        printf("ipv6: %s:%d\n", inet_ntop(AF_INET6, &sa->sin6_addr, addr_buf, addr_buf_size), ntohs(sa->sin6_port));
    }
    else
        printf("invaild sockaddr\n");
}

void checksockname(int fd)
{
    struct sockaddr_in6 addr;

    int sin_size = sizeof(addr);
    printf("getpeername: ");
    if (getpeername(fd, (struct sockaddr *)&addr, (socklen_t *)&sin_size) == 0)
        sockaddr_display(&addr);
    else
       printf("error\n");

    sin_size = sizeof(addr);
    printf("getsockname: ");
    if (getsockname(fd, (struct sockaddr *)&addr, (socklen_t *)&sin_size) == 0)
        sockaddr_display(&addr);
    else
        printf("error\n");
}
