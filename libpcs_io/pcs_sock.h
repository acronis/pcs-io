/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_SOCK_H__
#define __PCS_SOCK_H__

#include "pcs_types.h"

#ifndef __WINDOWS__

#include <sys/socket.h>
typedef int pcs_sock_t;

#else	/* __WINDOWS__ */

/* on windows one can adjust max number of fds to be put into fdset for select()... default value is 64... too small... */
#undef  FD_SETSIZE
#define FD_SETSIZE 1024

/* It's important to have exactly this order of includes (pcs_types.h -> windows.h, then winsock2.h) */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
 
typedef SOCKET pcs_sock_t;
extern LPFN_ACCEPTEX  pcs_acceptex;
extern LPFN_CONNECTEX pcs_connectex;
extern u8 can_skip_sync_notifications;

#endif	/* __WINDOWS__ */

#include "pcs_net_addr.h"

PCS_API int pcs_network_init(void);
PCS_API int pcs_sock_bind(pcs_sock_t fd, const PCS_NET_ADDR_T * addr);
PCS_API int pcs_sock_connect(pcs_sock_t fd, const PCS_NET_ADDR_T * addr);
PCS_API void pcs_sock_close(pcs_sock_t fd);
PCS_API void pcs_sock_shutdown(pcs_sock_t fd);
PCS_API void pcs_sock_nonblock(pcs_sock_t fd);
PCS_API void pcs_sock_keepalive(pcs_sock_t fd);
PCS_API int pcs_sock_cork(pcs_sock_t fd);
PCS_API void pcs_sock_push(pcs_sock_t fd);
PCS_API void pcs_sock_nodelay(pcs_sock_t fd);
PCS_API int pcs_sock_errno(void);
PCS_API void pcs_sock_setup_buffers(pcs_sock_t fd, int sndbuf, int rcvbuf);
PCS_API int pcs_sock_getpeername(pcs_sock_t fd, PCS_NET_ADDR_T * addr);
PCS_API int pcs_sock_getsockname(pcs_sock_t fd, PCS_NET_ADDR_T * addr);

static inline int pcs_sock_invalid(pcs_sock_t fd)
{
#ifndef __WINDOWS__
	return fd < 0;
#else
	return fd == INVALID_SOCKET;
#endif
}

#endif	/* __PCS_SOCK_H__ */
