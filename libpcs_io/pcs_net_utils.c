/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#ifdef __linux__
#include <net/if.h>
#endif

#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <grp.h>

#include "pcs_net_utils.h"
#include "pcs_net_addr.h"
#include "pcs_sync_io.h"
#include "log.h"
#include "pcs_malloc.h"

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC	0
#endif

int pcs_resolve_hostname(const char *host, const char *svc, PCS_NET_ADDR_T addr[], int *nr, int passive)
{
	int rc;
	struct addrinfo hints;
	struct addrinfo *ai = 0, *rp;
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	if (passive)
		hints.ai_flags |= AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;

	rc = pcs_getaddrinfo(host, svc, &hints, &ai);
	if (rc) {
		TRACE("Can't resolve hostname '%s:%s'- %s", host, svc, gai_strerror(rc));
		return -1;
	}
	for(rc = 0, rp = ai; rp && rc < *nr; rp = rp->ai_next) {
		pcs_sockaddr2netaddr(&addr[rc], rp->ai_addr);
		rc++;
	}
	freeaddrinfo(ai);
	*nr = rc;
	return 0;
}

int pcs_get_local_addrs(PCS_NET_ADDR_T addr[], int *nr)
{
	struct ifaddrs *ifaddr, *ifa;
	int idx = 0, rc = 0;
	if (getifaddrs(&ifaddr) < 0) {
		pcs_log(LOG_ERR, "getifaddrs failed - %s", strerror(errno));
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL && idx < *nr; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL
#ifdef __linux__
				|| (ifa->ifa_flags & (IFF_LOOPBACK|IFF_POINTOPOINT))
				|| ifa->ifa_addr->sa_family == AF_PACKET
#endif
		   )
			continue;
		if ((rc = pcs_sockaddr2netaddr(&addr[idx], ifa->ifa_addr)))
			break;

		if (pcs_is_zero_netaddr(&addr[idx]))
			continue;

		idx++;
	}

	freeifaddrs(ifaddr);
	if (!rc)
		*nr = idx;
	return rc;
}

int pcs_get_addr_by_ifname(PCS_NET_ADDR_T *addr, const char *ifname)
{
	struct ifaddrs *ifaddr, *ifa;
	int rc = -1;
	if (getifaddrs(&ifaddr) < 0) {
		pcs_log(LOG_ERR, "getifaddrs failed - %s", strerror(errno));
		return rc;
	}
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || strcmp(ifname, ifa->ifa_name)
#ifdef __linux__
				|| ifa->ifa_addr->sa_family == AF_PACKET
#endif
		   )
			continue;

		rc = pcs_sockaddr2netaddr(addr, ifa->ifa_addr);
		break;
	}

	freeifaddrs(ifaddr);
	return rc;
}

int pcs_get_ifname_by_addr(PCS_NET_ADDR_T *addr,  char *buf, int buf_sz)
{
	struct ifaddrs *ifaddr, *ifa;
	int rc = -1;
	if (getifaddrs(&ifaddr) < 0) {
		pcs_log(LOG_ERR, "getifaddrs failed - %s", strerror(errno));
		return rc;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		PCS_NET_ADDR_T tmp;
		if (ifa->ifa_addr == NULL
#ifdef __linux__
				|| ifa->ifa_addr->sa_family == AF_PACKET
#endif
		   )
			continue;

		BUG_ON(pcs_sockaddr2netaddr(&tmp, ifa->ifa_addr));
		if (pcs_netaddr_cmp_ignore_port(&tmp, addr))
			continue;

		strncpy(buf, ifa->ifa_name, buf_sz);
		rc = 0;
		break;
	}

	freeifaddrs(ifaddr);
	return rc;
}

int pcs_get_default_addr(PCS_NET_ADDR_T *addr)
{
#ifdef __WINDOWS__
	BUG();
	return -1;
#else /* !__WINDOWS__ */
	int rc = -1;
	char buf[128];
	FILE *fi;
	/* Note that this function works only for IPv4 addresses */
	const char *route_file = "/proc/net/route";
	fi = fopen(route_file, "re");
	if (!fi) {
		pcs_log(LOG_ERR, "Unable open %s - %s", route_file, strerror(errno));
		return -1;
	}

	while(fgets(buf, sizeof(buf), fi)) {
		char *tmp = NULL;
		int i = 0;
		char *tok = strtok_r(buf, " \t", &tmp);
		char *items[3];
		while(tok && i < 3) {
			items[i++] = tok;
			tok = strtok_r(NULL, " \t", &tmp);
		}

		if (i < 3 || strcmp("00000000", items[1]))
			continue;

		pcs_log(LOG_DEBUG4, "iface=%s, dest=%s, gw=%s", items[0], items[1], items[2]);
		rc = pcs_get_addr_by_ifname(addr, items[0]);
		break;
	}
	if (rc) {
		if (ferror(fi))
			pcs_log(LOG_ERR, "Unable read %s", route_file);
		else if (feof(fi))
			pcs_log(LOG_ERR, "Default destination not found in %s", route_file);
	}
	fclose(fi);
	return rc;
#endif /* !__WINDOWS__ */
}

int pcs_is_net_addr_avail(PCS_NET_ADDR_T *addr)
{
	int sock = socket(PF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		pcs_log(LOG_ERR, "Failed to create socket: %s", strerror(errno));
		return -1;
	}

	struct sockaddr *sa;
	int salen;
	int ret, err, val = 1;

	(void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	pcs_netaddr2sockaddr(addr, &sa, &salen);
	ret = bind(sock, sa, salen);
	err = errno;
	close(sock);
	pcs_free(sa);
	if (ret < 0) {
		if (err != EADDRNOTAVAIL) {
			pcs_log(LOG_ERR, "Failed to bind to specified address: %s", strerror(errno));
			return -1;
		} else {
			char buf[128];
			/* address should be valid here */
			ret = pcs_format_netaddr(buf, sizeof(buf), addr);
			BUG_ON(ret < 0);
			pcs_log(LOG_WARN, "Warning: address '%s' is not available on the host!", buf);
		}
	}

	return 0;
}
