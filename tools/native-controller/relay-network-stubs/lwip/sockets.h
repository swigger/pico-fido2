#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stddef.h>
#include <time.h>
typedef int socklen_t;
struct test_timeval { time_t tv_sec; long tv_usec; };
#ifdef __cplusplus
extern "C" {
#endif
int test_socket(int family,int type,int protocol);
int test_connect(int fd,const struct sockaddr *address,int length);
int test_close(int fd);
int test_send(int fd,const void *bytes,size_t length,int flags);
int test_recv(int fd,void *bytes,size_t length,int flags);
int test_getsockopt(int fd,int level,int option,void *value,int *length);
int test_setsockopt(int fd,int level,int option,const void *value,int length);
int test_select(int count,fd_set *read_set,fd_set *write_set,fd_set *error_set,const struct test_timeval *timeout);
void test_fd_set(int fd,fd_set *set);
#ifdef __cplusplus
}
#else
#define socket test_socket
#define connect test_connect
#define close test_close
#define send test_send
#define recv test_recv
#define getsockopt test_getsockopt
#define setsockopt test_setsockopt
#define select test_select
#define timeval test_timeval
#undef FD_SET
#define FD_SET(fd,set) test_fd_set(fd,set)
#endif
