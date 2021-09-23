#ifndef UTIL_H
#define UTIL_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef long long ll;


extern ssize_t send_full(int fd, const char* msg, size_t len, int flags);
extern ssize_t recv_full(int fd, char* msg, size_t len, int flags);

extern void sockaddr_display(struct sockaddr_in6* addr);
extern void checksockname(int fd);

#endif