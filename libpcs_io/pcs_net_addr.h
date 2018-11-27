/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_NET_ADDR_H__
#define __PCS_NET_ADDR_H__

#include "pcs_types.h"

struct sockaddr;
struct addrinfo;

enum
{
	PCS_ADDRTYPE_NONE = 0,
	PCS_ADDRTYPE_IP = 1,
	PCS_ADDRTYPE_IP6 = 2,
	PCS_ADDRTYPE_UNIX = 3,
	PCS_ADDRTYPE_RDMA = 4,
	PCS_ADDRTYPE_NETLINK = 5,
};

/* alignment makes it usable in binary protocols */
typedef struct __pre_aligned(8) _PCS_NET_ADDR_T {
	u32	type;
	union {
		struct {
			u32	port;			/* network byteorder */
			u8	address[16];
		};
		/* type == PCS_ADDRTYPE_NETLINK */
		struct {
			u32	pid;
			u32	groups;
		};
	};
} PCS_NET_ADDR_T __aligned(8);

PCS_API int pcs_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo ** new_ai);
PCS_API int pcs_co_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo ** new_ai);
PCS_API void pcs_freeaddrinfo(struct addrinfo* ai);

/**
   Parse a string in one of the following formats:
   - ipv4addr:port
   - ipv6addr:port
   - hostname:port

   If @str is hostname:port, this call resolves the DNS name 'hostname' into an address.

   \param @str a string with a host name
   \param @addr an address that @str resolves to (a randomly picked one if @str is a DNS name that resolves to multiple addresses)
   \returns the same errors that getaddrinfo() does
 */
PCS_API int pcs_parse_netaddr(const char *str, PCS_NET_ADDR_T *addr);

/* Similar to pcs_parse_netaddr(), but use @def_port as a port number if @str does not specify one. */
PCS_API int pcs_parse_netaddr_port(const char *str, const char *def_port, PCS_NET_ADDR_T *addr);
/* Similar to pcs_parse_netaddr_port(), but returns all addresses that @str resolves to. */
PCS_API int pcs_parse_netaddr_port_multi(const char *str, const char *def_port, int * nr_addrs, PCS_NET_ADDR_T ** addrs);

/* A version of pcs_parse_netaddr() that can be used from a coroutine. */
PCS_API int pcs_co_parse_netaddr(const char *str, PCS_NET_ADDR_T *addr);
/* A version of pcs_parse_netaddr_port() that can be used from a coroutine. */
PCS_API int pcs_co_parse_netaddr_port(const char *str, const char *def_port, PCS_NET_ADDR_T *addr);
/* A version of pcs_parse_netaddr_port_multi() that can be used from a coroutine. */
PCS_API int pcs_co_parse_netaddr_port_multi(const char *str, const char *def_port, int * nr_addrs, PCS_NET_ADDR_T ** addrs);

/* get human-readable string for error returned by pcs_parse_netaddr */
PCS_API const char *pcs_parse_netaddr_err(int err_code);

/* Like gethostname(), but guarantees to null-terminate @buf. */
PCS_API int pcs_gethostname(char *buf, int size);

/* allocate sockaddr from PCS_NET_ADDR_T */
PCS_API int pcs_netaddr2sockaddr(PCS_NET_ADDR_T const* addr, struct sockaddr **_sa, int *salen);
PCS_API int pcs_netaddr2afamily(PCS_NET_ADDR_T const* addr);
PCS_API int pcs_sockaddr2netaddr(PCS_NET_ADDR_T *addr, struct sockaddr *sa);
PCS_API int pcs_format_netaddr(char * str, int len, PCS_NET_ADDR_T const* addr);
PCS_API int pcs_netaddr_cmp(PCS_NET_ADDR_T const* addr1, PCS_NET_ADDR_T const* addr2);
PCS_API int pcs_netaddr_cmp_ignore_port(PCS_NET_ADDR_T const* addr1, PCS_NET_ADDR_T const* addr2);
PCS_API int pcs_netaddr2hostname(PCS_NET_ADDR_T *addr, char *buf, int size);
PCS_API int pcs_is_zero_netaddr(PCS_NET_ADDR_T *addr);
#endif /* __PCS_NET_ADDR_H__ */
