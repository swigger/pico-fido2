#pragma once
#include <stdint.h>
typedef int err_t;
#define ERR_OK 0
#define ERR_INPROGRESS -5
#define LWIP_DNS_ADDRTYPE_IPV4_IPV6 0
#define LWIP_DNS_ADDRTYPE_IPV6_IPV4 1
typedef struct { uint32_t addr; } test_ipv4_t;
typedef struct { uint32_t addr[4]; } test_ipv6_t;
typedef struct { int family; test_ipv4_t v4; test_ipv6_t v6; } ip_addr_t;
#define IP_IS_V6(p) ((p)->family == 6)
#define ip_2_ip6(p) (&(p)->v6)
#define ip_2_ip4(p) (&(p)->v4)
#define ip4_addr_get_u32(p) ((p)->addr)
typedef void (*dns_found_callback)(const char *,const ip_addr_t *,void *);
#ifdef __cplusplus
extern "C" {
#endif
int ipaddr_aton(const char *host,ip_addr_t *address);
err_t dns_gethostbyname_addrtype(const char *host,ip_addr_t *address,dns_found_callback callback,void *arg,int type);
#ifdef __cplusplus
}
#endif
