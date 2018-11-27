/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"
#include "pcs_sock.h"
#include "bug.h"
#include "pcs_errno.h"
#include "pcs_malloc.h"
#include "log.h"
#include "pcs_winapi.h"

#ifndef __WINDOWS__
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif

#ifdef __WINDOWS__
LPFN_ACCEPTEX  pcs_acceptex = NULL;
LPFN_CONNECTEX pcs_connectex = NULL;
#endif

#if defined(__LINUX__) && !defined(SO_SNDBUFFORCE)
#define SO_SNDBUFFORCE	32
#define SO_RCVBUFFORCE	33
#endif

void pcs_sock_setup_buffers(pcs_sock_t fd, int sndbuf, int rcvbuf)
{
	if (pcs_sock_invalid(fd))
		return;
	if (sndbuf) {
#ifdef __LINUX__
		sndbuf /= 2;
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, (char*)&sndbuf, sizeof(sndbuf)))
#endif
			setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&sndbuf, sizeof(sndbuf));
#ifdef __LINUX__
		int val;
		unsigned int len = sizeof(val);

		if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&val, &len) ||
		    val != sndbuf * 2)
			pcs_log(LOG_ERR, "sock:%d unable to set sndbuf %d, actual %d : %d", fd, sndbuf, val, errno);
#endif
	}
	if (rcvbuf) {
#ifdef __LINUX__
		rcvbuf /= 2;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, (char*)&rcvbuf, sizeof(rcvbuf)))
#endif
			setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&rcvbuf, sizeof(rcvbuf));
	}
}

int pcs_sock_getpeername(pcs_sock_t fd, PCS_NET_ADDR_T * addr)
{
	socklen_t len;
	struct sockaddr_storage sa;

	len = sizeof(sa);
	if (getpeername(fd, (struct sockaddr *)&sa, &len))
		return -pcs_sock_errno();

	return pcs_sockaddr2netaddr(addr, (struct sockaddr *)&sa);
}

int pcs_sock_getsockname(pcs_sock_t fd, PCS_NET_ADDR_T *addr)
{
	socklen_t len;
	struct sockaddr_storage sa;

	len = sizeof(sa);
	if (getsockname(fd, (struct sockaddr *)&sa, &len))
		return -pcs_sock_errno();

	return pcs_sockaddr2netaddr(addr, (struct sockaddr *)&sa);
}

int pcs_sock_bind(pcs_sock_t fd, const PCS_NET_ADDR_T * addr)
{
	struct sockaddr *sa = NULL;
	int sa_len = 0;
	int r;

	pcs_netaddr2sockaddr(addr, &sa, &sa_len);
	if (sa == NULL) {
#ifdef __WINDOWS__
		return -WSAEAFNOSUPPORT;
#else
		return -EAFNOSUPPORT;
#endif
	}

	r = bind(fd, sa, sa_len);
	pcs_free(sa);
	return (r == 0 ? 0 : -pcs_sock_errno());
}

int pcs_sock_connect(pcs_sock_t fd, const PCS_NET_ADDR_T * addr)
{
	struct sockaddr *sa = NULL;
	int sa_len = 0;
	int r;

	pcs_netaddr2sockaddr(addr, &sa, &sa_len);
	if (sa == NULL) {
#ifdef __WINDOWS__
		return -WSAEAFNOSUPPORT;
#else
		return -EAFNOSUPPORT;
#endif
	}

	r = connect(fd, sa, sa_len);
	pcs_free(sa);
	return (r == 0 ? 0 : -pcs_sock_errno());
}

void pcs_sock_close(pcs_sock_t fd)
{
	if (pcs_sock_invalid(fd))
		return;

#ifdef __WINDOWS__
	closesocket(fd);
#else
	close(fd);
#endif
}

void pcs_sock_shutdown(pcs_sock_t fd)
{
	if (pcs_sock_invalid(fd))
		return;

#ifdef __WINDOWS__
	shutdown(fd, SD_SEND);
#else
	shutdown(fd, SHUT_WR);
#endif
}

void pcs_sock_nonblock(pcs_sock_t fd)
{
	int err;
#ifndef __WINDOWS__
	err = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	BUG_ON(err == -1);
#else
	unsigned long nblock = 1;
	err = ioctlsocket(fd, FIONBIO, &nblock);
	BUG_ON(err != 0);
#endif
}

void pcs_sock_keepalive(pcs_sock_t fd)
{
	int val;

	val = 1;
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&val, sizeof(val));
#if defined(__LINUX__)
	val = 60;
	setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &val, sizeof(val));
	val = 5;
	setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &val, sizeof(val));
	val = 5;
	setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &val, sizeof(val));
#endif
}

int pcs_sock_cork(pcs_sock_t fd)
{
#if defined(__LINUX__)
	int val = 1;
	if (setsockopt(fd, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val)) == 0)
		return 0;
#endif
	return -1;

}

void pcs_sock_nodelay(pcs_sock_t fd)
{
	int val = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
}

void pcs_sock_push(pcs_sock_t fd)
{
#ifdef __LINUX__
	/* On Linux, TCP_NODELAY pushes socket which was configured in CORK mode */
	if (fd != PCS_INVALID_FD)
		pcs_sock_nodelay(fd);
#endif
}

int pcs_sock_errno(void)
{
#ifndef __WINDOWS__
	return errno;
#else
	return WSAGetLastError();
#endif
}

#ifndef __WINDOWS__
int pcs_network_init(void)
{
	return 0;
}
#else
u8 can_skip_sync_notifications = 0;

/*
 * It's not safe to use FILE_SKIP_COMPLETION_PORT_ON_SUCCESS if non IFS providers are installed:
 * http://support.microsoft.com/kb/2568167
 */
static void check_can_skip_notifications(void)
{
	if (!SetFileCompletionNotificationModesPtr)
		return;

	int protos[2] = {IPPROTO_TCP, 0};
	WSAPROTOCOL_INFO *buf;
	DWORD buf_sz = 16384;
	int n;
	for (;;) {
		buf = pcs_xmalloc(buf_sz);
		n = WSAEnumProtocols(protos, buf, &buf_sz);
		if (n != SOCKET_ERROR)
			break;

		if (WSAGetLastError() != WSAENOBUFS)
			goto done;

		pcs_free(buf);
	}

	for (int i = 0; i < n; i++)
		if ((buf[i].dwServiceFlags1 & XP1_IFS_HANDLES) /* 0x00020000 */ == 0)
			goto done;

	can_skip_sync_notifications = 1;

done:
	pcs_free(buf);
}

int pcs_network_init(void)
{
	static int initialised = 0;
	if (initialised)
		return 0;

	int res = 0;
	SOCKET s = INVALID_SOCKET;
	GUID ax_guid = WSAID_ACCEPTEX;
	GUID cx_guid = WSAID_CONNECTEX;
	DWORD numBytes;
	WSADATA data;

	if (WSAStartup(MAKEWORD(2, 2), &data))
		return WSAGetLastError();

	if (data.wVersion != MAKEWORD(2, 2)) {
		WSASetLastError(WSAVERNOTSUPPORTED);
		goto failed;
	}

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (s == INVALID_SOCKET)
		goto failed;

	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
		(void*)&ax_guid, sizeof(ax_guid), (void*)&pcs_acceptex, sizeof(pcs_acceptex),
		&numBytes, NULL, NULL) < 0)
		goto failed;

	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
		(void*)&cx_guid, sizeof(cx_guid), (void*)&pcs_connectex, sizeof(pcs_connectex),
		&numBytes, NULL, NULL) < 0)
		goto failed;

	closesocket(s);

	check_can_skip_notifications();
	initialised = 1;
	return 0;

failed:
	res = WSAGetLastError();
	closesocket(s);
	WSACleanup();
	return res;
}
#endif /* defined(__WINDOWS__) */
