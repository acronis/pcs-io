/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"

#ifndef __WINDOWS__
  #include <netinet/in.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  #include <errno.h>
  #include <sys/socket.h>
  #include <ifaddrs.h>
  #include <stdio.h>
  #include <unistd.h>
#endif
#ifndef EAI_ADDRFAMILY
#define EAI_ADDRFAMILY EAI_FAMILY
#endif

#ifndef __WINDOWS__
#define PCS_SYSERR_NOMEM ENOMEM
#define PCS_SYSERR_INVAL EINVAL
#else
#define PCS_SYSERR_NOMEM ERROR_NOT_ENOUGH_MEMORY
#define PCS_SYSERR_INVAL ERROR_INVALID_PARAMETER
#endif

#ifdef __LINUX__
#include <linux/types.h>
#include <linux/netlink.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcs_sock.h"
#include "pcs_errno.h"
#include "pcs_net_addr.h"
#include "pcs_coroutine.h"
#include "pcs_process.h"
#include "log.h"
#include "pcs_malloc.h"


#ifdef __WINDOWS__
/* adjust size value to be multiple of pointer size. Use to keep pointer aligned */
#define ALIGNED_SIZE(X) PCS_ALIGN_TO(X, sizeof(void*))

static const int addrinfo_struct_len = ALIGNED_SIZE(sizeof(struct addrinfo));

static int utf8_to_utf16(const char * str, WCHAR * wstr, int wstr_len)
{
	return MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, wstr_len);
}

static int utf16_to_utf8(const WCHAR * wstr, char * str, int str_len)
{
	return WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, str_len, NULL, NULL);
}

static void addrinfoa_to_w(const struct addrinfo * ai, ADDRINFOW * aiw)
{
	aiw->ai_family = ai->ai_family;
	aiw->ai_socktype = ai->ai_socktype;
	aiw->ai_protocol = ai->ai_protocol;
	aiw->ai_flags = ai->ai_flags;
	aiw->ai_addrlen = 0;
	aiw->ai_canonname = NULL;
	aiw->ai_addr = NULL;
	aiw->ai_next = NULL;
}

static int get_addrinfo_alloc_size(const ADDRINFOW * aiw)
{
	int size = 0;
	while (aiw) {
		size += addrinfo_struct_len;
		size += (int)ALIGNED_SIZE(aiw->ai_addrlen);
		if (aiw->ai_canonname) {
			int name_len = utf16_to_utf8(aiw->ai_canonname, NULL, 0);
			BUG_ON(name_len <= 0);
			size += ALIGNED_SIZE(name_len);
		}
		aiw = aiw->ai_next;
	}
	return size;
}

static void addrinfow_to_a(const ADDRINFOW * aiw, size_t ai_len, char * ai_ptr)
{
	char* cur_ptr = ai_ptr;
	while (aiw) {
		struct addrinfo *ai = (struct addrinfo*)cur_ptr;
		ai->ai_family = aiw->ai_family;
		ai->ai_socktype = aiw->ai_socktype;
		ai->ai_protocol = aiw->ai_protocol;
		ai->ai_flags = aiw->ai_flags;
		ai->ai_addrlen = aiw->ai_addrlen;
		ai->ai_canonname = NULL;
		ai->ai_addr = NULL;
		ai->ai_next = NULL;

		cur_ptr += addrinfo_struct_len;

		/* copy sockaddr */
		if (ai->ai_addrlen > 0) {
			BUG_ON(cur_ptr + ai->ai_addrlen > ai_ptr + ai_len);
			memcpy(cur_ptr, aiw->ai_addr, ai->ai_addrlen);
			ai->ai_addr = (struct sockaddr*)cur_ptr;
			cur_ptr += ALIGNED_SIZE(ai->ai_addrlen);
		}

		/* convert canonical name to UTF-8 */
		if (aiw->ai_canonname != NULL) {
			int name_len = utf16_to_utf8(aiw->ai_canonname, NULL, 0);
			BUG_ON(name_len <= 0);
			BUG_ON(cur_ptr + name_len > ai_ptr + ai_len);
			name_len = utf16_to_utf8(aiw->ai_canonname, cur_ptr, name_len);
			BUG_ON(name_len <= 0);
			ai->ai_canonname = cur_ptr;
			cur_ptr += ALIGNED_SIZE(name_len);
		}
		BUG_ON(cur_ptr > ai_ptr + ai_len);

		/* set next ptr */
		aiw = aiw->ai_next;
		if (aiw != NULL)
			ai->ai_next = (struct addrinfo*)cur_ptr;
	}
}

int pcs_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo ** new_ai)
{
	WCHAR * nodew = NULL, *servicew = NULL;
	ADDRINFOW * hintsw = NULL, *aiw = NULL;
	int node_len = 0, service_len = 0, hints_size = 0;
	int ptr_len, ai_len;
	int err;
	char * ptr;

	if (node) {
		node_len = utf8_to_utf16(node, NULL, 0);
		if (node_len == 0)
			return GetLastError();
	}
	if (service) {
		service_len = utf8_to_utf16(service, NULL, 0);
		if (service_len == 0)
			return GetLastError();
	}
	if (hints)
		hints_size = sizeof(ADDRINFOW);

	ptr_len = sizeof(WCHAR) * (node_len + service_len) + hints_size;
	ptr = pcs_malloc(ptr_len);
	if (ptr == NULL)
		return WSA_NOT_ENOUGH_MEMORY;

	if (node) {
		nodew = (WCHAR*)ptr;
		if (utf8_to_utf16(node, nodew, node_len) == 0) {
			err = GetLastError();
			goto free_ptr_and_fail;
		}
	}
	if (service) {
		servicew = (WCHAR*)(ptr + sizeof(WCHAR) * node_len);
		if (utf8_to_utf16(service, servicew, node_len) == 0) {
			err = GetLastError();
			goto free_ptr_and_fail;
		}
	}
	if (hints) {
		hintsw = (ADDRINFOW*)(ptr + sizeof(WCHAR) * (node_len + service_len));
		addrinfoa_to_w(hints, hintsw);
	}

	err = GetAddrInfoW(nodew, servicew, hintsw, &aiw);
	if (err)
		goto free_ptr_and_fail;

	BUG_ON(!aiw);
	ai_len = get_addrinfo_alloc_size(aiw);
	BUG_ON(ai_len == 0);

	/* Prefer reuse allocated memory */
	if (ai_len > ptr_len) {
		char * new_ptr = pcs_realloc(ptr, ai_len);
		if (!new_ptr) {
			err = WSA_NOT_ENOUGH_MEMORY;
			goto free_aiw_and_fail;
		}
		ptr = new_ptr;
	}

	addrinfow_to_a(aiw, ai_len, ptr);
	FreeAddrInfoW(aiw);
	*new_ai = (struct addrinfo*)ptr;
	return 0;

free_aiw_and_fail:
	FreeAddrInfoW(aiw);

free_ptr_and_fail:
	pcs_free(ptr);
	return err;
}

void pcs_freeaddrinfo(struct addrinfo* ai)
{
	pcs_free(ai);
}

static int pcs_getnameinfo(const struct sockaddr *sa, socklen_t salen,
	char *host, size_t hostlen,
	char *serv, size_t servlen, int flags)
{
	WCHAR hostw[NI_MAXHOST];
	WCHAR servw[NI_MAXSERV], *pservw = NULL;
	DWORD servwlen = 0;
	if (serv) {
		pservw = servw;
		servwlen = NI_MAXSERV;
	}

	if (GetNameInfoW(sa, salen, hostw, NI_MAXHOST, pservw, servwlen, flags))
		return WSAGetLastError();

	if (utf16_to_utf8(hostw, host, (int)hostlen) < 0)
		return GetLastError();

	if (utf16_to_utf8(servw, serv, (int)servlen) < 0)
		return GetLastError();

	return 0;
}
#else /* !__WINDOWS__ */

int pcs_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo ** new_ai)
{
	return getaddrinfo(node, service, hints, new_ai);
}

void pcs_freeaddrinfo(struct addrinfo* ai)
{
	freeaddrinfo(ai);
}

static int pcs_getnameinfo(const struct sockaddr *sa, socklen_t salen,
	char *host, size_t hostlen,
	char *serv, size_t servlen, int flags)
{
	return getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
#endif /* !__WINDOWS__ */

struct _co_gai_args
{
	const char* node;
	const char* service;
	const struct addrinfo* hints;
	struct addrinfo ** new_ai;
};

static int _co_getaddrinfo(void * data)
{
	struct _co_gai_args * args = (struct _co_gai_args*)data;
	return pcs_getaddrinfo(args->node, args->service, args->hints, args->new_ai);
}

int pcs_co_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo ** new_ai)
{
	struct _co_gai_args args;
	args.node = node;
	args.service = service;
	args.hints = hints;
	args.new_ai = new_ai;
	return pcs_co_filejob(pcs_current_proc->co_io, _co_getaddrinfo, &args);
}

static int resolve_netaddr(const char *str, const char *port, int *nr_addrs_out, PCS_NET_ADDR_T **addrs_out)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_V4MAPPED | AI_ADDRCONFIG;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *ai0, *ai;
	int res;

	res = pcs_getaddrinfo(str, port, &hints, &ai0);
	if (res) {
		hints.ai_flags &= ~AI_NUMERICHOST;
		res = pcs_getaddrinfo(str, port, &hints, &ai0);
	}
	if (res)
		return res;

	int nr_addrs = 0;
	for (ai = ai0; ai; ai = ai->ai_next)
		if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6)
			++nr_addrs;

	if (nr_addrs == 0) {
		pcs_freeaddrinfo(ai0);
		return EAI_ADDRFAMILY;
	}

	PCS_NET_ADDR_T *addrs = pcs_xzmalloc(nr_addrs * sizeof(PCS_NET_ADDR_T));
	PCS_NET_ADDR_T *a = &addrs[0];
	for (ai = ai0; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			struct sockaddr_in *sa = (struct sockaddr_in *)ai->ai_addr;
			a->type = PCS_ADDRTYPE_IP;
			memcpy(a->address, &sa->sin_addr, sizeof(sa->sin_addr));
			a->port = sa->sin_port;
			++a;
		} else if (ai->ai_family == AF_INET6) {
			struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ai->ai_addr;
			a->type = PCS_ADDRTYPE_IP6;
			memcpy(a->address, &sa->sin6_addr, sizeof(sa->sin6_addr));
			a->port = sa->sin6_port;
			++a;
		}
	}

	pcs_freeaddrinfo(ai0);

	(*nr_addrs_out) = nr_addrs;
	(*addrs_out) = addrs;
	return 0;
}

int pcs_parse_netaddr_port_multi(const char *str, const char *def_port, int *nr_addrs, PCS_NET_ADDR_T **addrs)
{
	char *s, *a, *p;
	int res;

	s = pcs_xstrdup(str);

	a = s;
	if (a[0] == '[') { /* IPv6 address */
		a++;
		p = strchr(a, ']');
		if (!p) {
			res = EAI_NONAME;
			goto out;
		}
		*(p++) = 0;
		if (*p == 0)
			p = NULL;
		else if (*p != ':') {
			res = EAI_NONAME;
			goto out;
		}
	} else {
		p = strrchr(a, ':');
		if (p && p != strchr(a, ':')) {
			/* only one ':' is allowed here */
			res = EAI_NONAME;
			goto out;
		}
	}

	if (!p) {
		if (!def_port) {
			res = EAI_NONAME;
			goto out;
		}
		p = (char*)def_port;
	} else
		*(p++) = 0;

	res = resolve_netaddr(a, p, nr_addrs, addrs);

out:
	pcs_free(s);
	return res;
}

int pcs_parse_netaddr_port(const char *str, const char *def_port, PCS_NET_ADDR_T *addr)
{
	PCS_NET_ADDR_T *addrs;
	int nr_addrs;
	int res;

	if ((res = pcs_parse_netaddr_port_multi(str, def_port, &nr_addrs, &addrs)))
		return res;

	*addr = addrs[0];
	pcs_free(addrs);
	return 0;
}

int pcs_parse_netaddr(const char *str, PCS_NET_ADDR_T *addr)
{
	return pcs_parse_netaddr_port(str, NULL, addr);
}

struct _co_parse_netaddr_port_multi_args
{
	const char *str;
	const char *def_port;
	int *nr_addrs;
	PCS_NET_ADDR_T **addrs;
};

int _co_parse_netaddr_port_multi(void *_args)
{
	struct _co_parse_netaddr_port_multi_args *args = _args;
	return pcs_parse_netaddr_port_multi(args->str, args->def_port, args->nr_addrs, args->addrs);
}

int pcs_co_parse_netaddr_port_multi(const char *str, const char *def_port, int *nr_addrs, PCS_NET_ADDR_T **addrs)
{
	/* FIXME: implement context cancelation support */
	struct _co_parse_netaddr_port_multi_args args = {
		.str = str,
		.def_port = def_port,
		.nr_addrs = nr_addrs,
		.addrs = addrs
	};
	return pcs_co_filejob(pcs_current_proc->co_io, &_co_parse_netaddr_port_multi, &args);
}

int pcs_co_parse_netaddr_port(const char *str, const char *def_port, PCS_NET_ADDR_T *addr)
{
	PCS_NET_ADDR_T *addrs;
	int nr_addrs;
	int res;

	if ((res = pcs_co_parse_netaddr_port_multi(str, def_port, &nr_addrs, &addrs)))
		return res;

	*addr = addrs[0];
	pcs_free(addrs);
	return 0;
}

int pcs_co_parse_netaddr(const char *str, PCS_NET_ADDR_T *addr)
{
	return pcs_co_parse_netaddr_port(str, NULL, addr);
}

const char *pcs_parse_netaddr_err(int err_code)
{
	return gai_strerror(err_code);
}

int pcs_gethostname(char *buf, int size)
{
	memset(buf, 0, size);

	if (gethostname(buf, size - 1) != 0)
		return -pcs_sock_errno();
	return 0;
}

int pcs_is_zero_netaddr(PCS_NET_ADDR_T *addr)
{
	if (addr->type == PCS_ADDRTYPE_IP) {
		u8 buf[4];
		memset(buf, 0, sizeof(buf));
		return (memcmp(addr->address, buf, sizeof(buf)) == 0) ? 1 : 0;
	}
	if (addr->type == PCS_ADDRTYPE_IP6) {
		u8 buf[16];
		memset(buf, 0, sizeof(buf));
		return (memcmp(addr->address, buf, sizeof(buf)) == 0) ? 1 : 0;
	}
	return -PCS_SYSERR_INVAL;
}

int pcs_netaddr2sockaddr(PCS_NET_ADDR_T const* addr, struct sockaddr **_sa, int *salen)
{
	*_sa = NULL;
	if (addr->type == PCS_ADDRTYPE_IP || addr->type == PCS_ADDRTYPE_RDMA) {
		struct sockaddr_in *sa = pcs_malloc(sizeof(*sa));
		if (!sa)
			return -PCS_SYSERR_NOMEM;
		memset(sa, 0, sizeof(*sa));
		sa->sin_family = AF_INET;
		sa->sin_port = (u16)addr->port;
		memcpy(&sa->sin_addr, addr->address, sizeof(sa->sin_addr));
		*_sa = (struct sockaddr *)sa;
		*salen = sizeof(*sa);
	} else if (addr->type == PCS_ADDRTYPE_IP6) {
		struct sockaddr_in6 *sa = pcs_malloc(sizeof(*sa));
		if (!sa)
			return -PCS_SYSERR_NOMEM;
		memset(sa, 0, sizeof(*sa));
		sa->sin6_family = AF_INET6;
		sa->sin6_port = (u16)addr->port;
		memcpy(&sa->sin6_addr, addr->address, sizeof(sa->sin6_addr));
		*_sa = (struct sockaddr *)sa;
		*salen = sizeof(*sa);
	} else
#ifdef __LINUX__
	if (addr->type == PCS_ADDRTYPE_NETLINK) {
		struct sockaddr_nl *sa = pcs_malloc(sizeof(*sa));
		if (!sa)
			return -PCS_SYSERR_NOMEM;
		memset(sa, 0, sizeof(*sa));
		sa->nl_family = AF_NETLINK;
		sa->nl_pid = addr->pid;
		sa->nl_groups = addr->groups;
		*_sa = (struct sockaddr *)sa;
		*salen = sizeof(*sa);
	} else
#endif
		return -PCS_SYSERR_INVAL;

	return 0;
}

int pcs_netaddr2afamily(PCS_NET_ADDR_T const* addr)
{
	switch(addr->type) {
		case PCS_ADDRTYPE_IP: return AF_INET;
		case PCS_ADDRTYPE_RDMA: return AF_INET;
		case PCS_ADDRTYPE_IP6: return AF_INET6;
		case PCS_ADDRTYPE_UNIX: return AF_UNIX;
#ifdef __LINUX__
		case PCS_ADDRTYPE_NETLINK: return AF_NETLINK;
#endif
		default:
			return -1;
	}
}


int pcs_sockaddr2netaddr(PCS_NET_ADDR_T *addr, struct sockaddr *sa)
{
	memset(addr, 0, sizeof(*addr));

	switch(sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in * sin = (struct sockaddr_in *)sa;
			addr->type = PCS_ADDRTYPE_IP;
			addr->port = sin->sin_port;
			memcpy(addr->address, &sin->sin_addr, sizeof(sin->sin_addr));
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *)sa;
			addr->type = PCS_ADDRTYPE_IP6;
			addr->port = sin6->sin6_port;
			memcpy(addr->address, &sin6->sin6_addr, sizeof(sin6->sin6_addr));
			break;
		}
		case AF_UNIX:
			addr->type = PCS_ADDRTYPE_UNIX;
			break;
#ifdef __LINUX__
		case AF_NETLINK: {
			struct sockaddr_nl *snl = (struct sockaddr_nl *)sa;
			addr->type = PCS_ADDRTYPE_NETLINK;
			addr->pid = snl->nl_pid;
			addr->groups = snl->nl_groups;
			break;
		}
#endif
		default:
			return -PCS_SYSERR_INVAL;
	}

	return 0;
}

int pcs_format_netaddr_port(char *str, int len, unsigned *port, PCS_NET_ADDR_T const *addr)
{
	int fam;
	char tmpbuf[128];

	/* make sure we have a valid NULL terminated string for error paths */
	str[0] = 0;

	fam = pcs_netaddr2afamily(addr);
	if (fam < 0)
		return fam;

#ifndef __WINDOWS__
	if (inet_ntop(fam, addr->address, tmpbuf, sizeof(tmpbuf)) == NULL)
		return -1;
#else
	struct sockaddr *sa = NULL;
	int salen = 0;

	if (pcs_netaddr2sockaddr(addr, &sa, &salen))
		return -1;

	int res = pcs_getnameinfo(sa, salen, tmpbuf, sizeof(tmpbuf), 0, 0, NI_NUMERICHOST);

	pcs_free(sa);
	if (res != 0)
		return -1;
#endif

	const char *prefix = (addr->type == PCS_ADDRTYPE_RDMA) ? "rdma://" : "";
	if (port)
		*port = ntohs((u16)addr->port);
	return snprintf(str, len, "%s%s%s%s", prefix,
			fam == AF_INET6 ? "[" : "",
			tmpbuf,
			fam == AF_INET6 ? "]" : "");
}

int pcs_format_netaddr(char * str, int len, PCS_NET_ADDR_T const* addr)
{
	int ret, ret2 = 0;
	unsigned port;

	ret = pcs_format_netaddr_port(str, len, &port, addr);
	if (ret < 0 || ret >= len || !port)
		return ret;
	ret2 = snprintf(str + ret, len - ret, ":%u", port);
	if (ret2 < 0)
		return ret2;
	return ret + ret2;
}

static inline int netaddr_cmp(PCS_NET_ADDR_T const* addr1, PCS_NET_ADDR_T const* addr2, int ignore_port)
{
	unsigned int d;
	size_t sz = 0;

	if ((d = addr1->type - addr2->type))
		return d;

	if (!ignore_port && (d = addr1->port - addr2->port))
		return d;

	switch (addr1->type) {
		case PCS_ADDRTYPE_IP:
		case PCS_ADDRTYPE_RDMA:
			sz = sizeof(struct in_addr);
			break;
		case PCS_ADDRTYPE_IP6:
			sz = sizeof(struct in6_addr);
			break;
		default:
			BUG();
	}

	return memcmp(addr1->address, addr2->address, sz);
}

int pcs_netaddr_cmp(PCS_NET_ADDR_T const* addr1, PCS_NET_ADDR_T const* addr2)
{
	return netaddr_cmp(addr1, addr2, 0);
}

int pcs_netaddr_cmp_ignore_port(PCS_NET_ADDR_T const* addr1, PCS_NET_ADDR_T const* addr2)
{
	return netaddr_cmp(addr1, addr2, 1);
}

int pcs_netaddr2hostname(PCS_NET_ADDR_T *addr, char *buf, int size)
{
	struct sockaddr *sa;
	int salen;
	int ret = 0;

	pcs_might_block();
	if (pcs_netaddr2sockaddr(addr, &sa, &salen) < 0)
		return -1;
	ret = pcs_getnameinfo(sa, salen, buf, size, NULL, 0, NI_NAMEREQD);
	pcs_free(sa);

	return ret;
}
