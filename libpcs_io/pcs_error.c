/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "pcs_error.h"
#include "pcs_errno.h"
#include "pcs_compat.h"
#include "pcs_sock_ssl.h"
#include "log.h"

#define ARR_SZ(a)  (sizeof(a)/sizeof((a)[0]))
#define STRZ_SZ(s) (ARR_SZ(s)-1)
#define ERR_NAME(err) [err] = #err + STRZ_SZ("PCS_ERR_")

static const char *const prot_err_names[] = {
	[0] = "OK",
	ERR_NAME(PCS_ERR_NOMEM),
	ERR_NAME(PCS_ERR_PROTOCOL),
	ERR_NAME(PCS_ERR_AUTH),
	ERR_NAME(PCS_ERR_NET),
	ERR_NAME(PCS_ERR_NOSPACE),
	ERR_NAME(PCS_ERR_IO),
	ERR_NAME(PCS_ERR_LOST_LOCK),
	ERR_NAME(PCS_ERR_NOT_FOUND),
	ERR_NAME(PCS_ERR_INTERRUPTED),
	ERR_NAME(PCS_ERR_NET_ABORT),
	ERR_NAME(PCS_ERR_CONNECT_TIMEOUT),
	ERR_NAME(PCS_ERR_AUTH_TIMEOUT),
	ERR_NAME(PCS_ERR_RESPONSE_TIMEOUT),
	ERR_NAME(PCS_ERR_WRITE_TIMEOUT),
	ERR_NAME(PCS_ERR_CANCEL_REQUEST),
	ERR_NAME(PCS_ERR_CANCEL_IO),
	ERR_NAME(PCS_ERR_LEASE_REQUIRED),
	ERR_NAME(PCS_ERR_LEASE_EXPIRED),
	ERR_NAME(PCS_ERR_LEASE_CONFLICT),
	ERR_NAME(PCS_ERR_INV_PATH),
	ERR_NAME(PCS_ERR_NOT_DIR),
	ERR_NAME(PCS_ERR_IS_DIR),
	ERR_NAME(PCS_ERR_NON_EMPTY_DIR),
	ERR_NAME(PCS_ERR_ZERO_CHUNK),
	ERR_NAME(PCS_ERR_INVALID),
	ERR_NAME(PCS_ERR_INV_PARAMS),
	ERR_NAME(PCS_ERR_NO_ID),
	ERR_NAME(PCS_ERR_INVALID_ID),
	ERR_NAME(PCS_ERR_NORES),
	ERR_NAME(PCS_ERR_UNAVAIL),
	ERR_NAME(PCS_ERR_BAD_CLUSTER),
	ERR_NAME(PCS_ERR_READONLY),
	ERR_NAME(PCS_ERR_PERM),
	ERR_NAME(PCS_ERR_UNSUPPORTED),
	ERR_NAME(PCS_ERR_TEMP_UNAVAIL),
	ERR_NAME(PCS_ERR_INTEGRITY),
	ERR_NAME(PCS_ERR_INTEGRITY_FAIL),
	ERR_NAME(PCS_ERR_NO_STORAGE),
	ERR_NAME(PCS_ERR_NOT_ALLOWED),
	ERR_NAME(PCS_ERR_CFG_VERSION),
	ERR_NAME(PCS_ERR_CLNT_VERSION),
	ERR_NAME(PCS_ERR_EXISTS),
	ERR_NAME(PCS_ERR_EPOCH_MISMATCH),
	ERR_NAME(PCS_ERR_GR_EPOCH_INVALID),
	ERR_NAME(PCS_ERR_NO_DIR),
	ERR_NAME(PCS_ERR_DIR_INST_VER),
	ERR_NAME(PCS_ERR_INST_EXISTS),
	ERR_NAME(PCS_ERR_INST_OUTDATED),
	ERR_NAME(PCS_ERR_INST_MISMATCH),
	ERR_NAME(PCS_ERR_CONTEXT_LOST),
	ERR_NAME(PCS_ERR_CSD_STALE_MAP),
	ERR_NAME(PCS_ERR_CSD_RO_MAP),
	ERR_NAME(PCS_ERR_CSD_WR_IN_PROGR),
	ERR_NAME(PCS_ERR_CSD_REPLICATING),
	ERR_NAME(PCS_ERR_CSD_STALLED_REPL),
	ERR_NAME(PCS_ERR_CANCEL_KEEPWAIT),
	ERR_NAME(PCS_ERR_CSD_LACKING),
	ERR_NAME(PCS_ERR_CSD_DROPPED),
	ERR_NAME(PCS_ERR_MDS_NOT_MASTER),
	ERR_NAME(PCS_ERR_MDS_EXIST),
	ERR_NAME(PCS_ERR_MDS_RM_TOOMANY),
	ERR_NAME(PCS_ERR_MDS_KVSTORE_GEN_OUTDATED),
	ERR_NAME(PCS_ERR_LICENSE_LIMIT),
	ERR_NAME(PCS_ERR_NO_LICENSE),
	ERR_NAME(PCS_ERR_SSL_CERTIFICATE_REVOKED),
	ERR_NAME(PCS_ERR_SSL_CERTIFICATE_EXPIRED),
	ERR_NAME(PCS_ERR_SSL_UNKNOWN_CA),
	ERR_NAME(PCS_ERR_PEER_CERTIFICATE_REJECTED),
};

static const char *const prot_err_list[] = {
	[0]				= "Success",

	[PCS_ERR_NOMEM]			= "Out of memory",
	[PCS_ERR_PROTOCOL]		= "Fatal protocol error",
	[PCS_ERR_AUTH]			= "Authentication failure due to wrong credentials",
	[PCS_ERR_NET]			= "Misc network error",
	[PCS_ERR_NOSPACE]		= "No space/quota exceeded while local file io",
	[PCS_ERR_IO]			= "Misc error while local file io",
	[PCS_ERR_LOST_LOCK]		= "CN did not get response from MDS for lease update.",

	[PCS_ERR_NOT_FOUND]		= "Requested object not found",
	[PCS_ERR_INTERRUPTED]		= "The operation was interrupted, should be retried",
	[PCS_ERR_NET_ABORT]		= "Message dropped due to abort of network connection",
	[PCS_ERR_CONNECT_TIMEOUT]	= "Failed connect()",
	[PCS_ERR_AUTH_TIMEOUT]		= "Authentication failure due to timeout",
	[PCS_ERR_RESPONSE_TIMEOUT]	= "Peer did not respond or did not hold deadline",
	[PCS_ERR_WRITE_TIMEOUT]		= "Socket write() failed, peer is stuck or network is broken",

	[PCS_ERR_CANCEL_REQUEST]	= "Request was canceled by user",
	[PCS_ERR_CANCEL_IO]		= "IO request was canceled",

	[PCS_ERR_LEASE_REQUIRED]	= "Lease required",
	[PCS_ERR_LEASE_EXPIRED]		= "Lease is expired",
	[PCS_ERR_LEASE_CONFLICT]	= "Lease request conflicts with another lease",
	[PCS_ERR_INV_PATH]              = "The path is invalid",
	[PCS_ERR_NOT_DIR]		= "Attempt to read non-directory",
	[PCS_ERR_IS_DIR]		= "Attempt to access directory (resize/io)",
	[PCS_ERR_NON_EMPTY_DIR]		= "Attempt to rename/delete non empty directory",
	[PCS_ERR_ZERO_CHUNK]		= "The requested chunk was not written yet and contains zero data",
	[PCS_ERR_INVALID]		= "Object is invalid",
	[PCS_ERR_INV_PARAMS]		= "Invalid parameters",
	[PCS_ERR_NO_ID]			= "Request from the client without ID",
	[PCS_ERR_INVALID_ID]		= "The client or server ID is invalid or banned",
	[PCS_ERR_NORES]			= "Not enough resources (too many requests)",
	[PCS_ERR_UNAVAIL]		= "Service unavailable",
	[PCS_ERR_BAD_CLUSTER]		= "Bad cluster ID",
	[PCS_ERR_READONLY]		= "Invalid operation on read-only object",
	[PCS_ERR_PERM]			= "Permission denied",
	[PCS_ERR_UNSUPPORTED]		= "Operation is not supported",

	[PCS_ERR_TEMP_UNAVAIL]		= "The resource is temporarily unavailable",
	[PCS_ERR_INTEGRITY]		= "Not enough alive replicas available",
	[PCS_ERR_INTEGRITY_FAIL]	= "Fatal MDS integrity error",

	[PCS_ERR_NO_STORAGE]		= "The number of chunk servers in cluster is less than the required number of replicas",
	[PCS_ERR_NOT_ALLOWED]		= "Operation is not allowed due to licensing limitations",
	[PCS_ERR_IO_HOLE]		= "Read operation encountered a hole",
	[PCS_ERR_CFG_VERSION]		= "Configuration version mismatch",
	[PCS_ERR_CLNT_VERSION]		= "Client version is incompatible with server version (outdated)",
	[PCS_ERR_EXISTS]		= "Specified object already exists",
	[PCS_ERR_EPOCH_MISMATCH]	= "Object epoch mismatch due to concurrent update",
	[PCS_ERR_GR_EPOCH_INVALID]	= "Object geo replication epoch invalid",
	[PCS_ERR_NO_DIR]		= "Name directory does not exists",
	[PCS_ERR_DIR_INST_VER]		= "Name directory instance version mismatch",
	[PCS_ERR_INST_EXISTS]		= "The same instance of the object already exists",
	[PCS_ERR_INST_OUTDATED]		= "The newer version of the object already exists",
	[PCS_ERR_INST_MISMATCH]		= "The instance version of the object does not match the requested one",
	[PCS_ERR_CONTEXT_LOST]		= "Operation context is lost on server restart",

	[PCS_ERR_CSD_STALE_MAP]		= "Old map (or no map) at CS",
	[PCS_ERR_CSD_RO_MAP]		= "Write request with read-only map",
	[PCS_ERR_CSD_WR_IN_PROGR]	= "Read only map is rejected due to write requests being processed",
	[PCS_ERR_CSD_REPLICATING]	= "Attempt to read from unfinished replica",
	[PCS_ERR_CANCEL_KEEPWAIT]	= "IO request was canceled and redirected to another CS",
	[PCS_ERR_CSD_STALLED_REPL]	= "Replication stalled",
	[PCS_ERR_CSD_LACKING]		= "Not enough CS servers available",
	[PCS_ERR_CSD_DROPPED]		= "The CS server was dropped by administrator",
	[PCS_ERR_MDS_NOT_MASTER]	= "The target MDS is not current master",
	[PCS_ERR_MDS_EXIST]		= "The MDS with such id already exist in cluster",
	[PCS_ERR_MDS_RM_TOOMANY]	= "Removing this MDS will make the cluster unusable",
	[PCS_ERR_MDS_KVSTORE_GEN_OUTDATED]	= "Requested generation is too old",
	[PCS_ERR_LICENSE_LIMIT]		= "Operation can't be completed due to license limitations",
	[PCS_ERR_NO_LICENSE]		= "No loaded license",

	[PCS_ERR_SSL]			    = "SSL protocol error",
	[PCS_ERR_SSL_CERTIFICATE_REVOKED]   = "Certificate revoked",
	[PCS_ERR_SSL_CERTIFICATE_EXPIRED]   = "Certificate expired",
	[PCS_ERR_SSL_UNKNOWN_CA]            = "The certificate could not be matched with a known, trusted CA",
	[PCS_ERR_PEER_CERTIFICATE_REJECTED] = "The peer certificate has failed the verification",
};

/* Get long description of the error */
const char *pcs_strerror(pcs_err_t errnum)
{
	if ((int)errnum < 0 || errnum >= ARR_SZ(prot_err_list))
		return "Unknown error";

	return prot_err_list[errnum];
}

/* Get short mnemonic */
const char *pcs_errname(pcs_err_t errnum)
{
	if ((int)errnum < 0 || errnum >= ARR_SZ(prot_err_names))
		return "ERR_UNKNOWN";

	return prot_err_names[errnum];
}

pcs_err_t pcs_errno_to_err(int err)
{
	switch (err) {
	case 0:
		return PCS_ERR_OK;
#ifndef __WINDOWS__
	case ENOMEM:
		return PCS_ERR_NOMEM;
	case ECANCELED:
		return PCS_ERR_CANCEL_IO;
	case EINVAL:
		return PCS_ERR_INV_PARAMS;
	case EINTR:
		return PCS_ERR_INTERRUPTED;
	case ENOSPC:
	case EDQUOT:
		return PCS_ERR_NOSPACE;
	case ENODEV:
	case ENOENT:
		return PCS_ERR_NOT_FOUND;
	case EEXIST:
		return PCS_ERR_EXISTS;
	case ELOOP:
	case ENAMETOOLONG:
		return PCS_ERR_INV_PATH;
	case EISDIR:
		return PCS_ERR_IS_DIR;
	case ENOTDIR:
		return PCS_ERR_NOT_DIR;
	case ENOTEMPTY:
		return PCS_ERR_NON_EMPTY_DIR;
	case EMFILE:
	case ENFILE:
		return PCS_ERR_NORES;
	case EROFS:
		return PCS_ERR_READONLY;
	case EACCES:
	case EPERM:
		return PCS_ERR_PERM;
	case ENOSYS:
	case ENOTSUP:
#ifndef __LINUX__
	case EOPNOTSUPP:
#endif
		return PCS_ERR_UNSUPPORTED;
	case EADDRINUSE:
	case EADDRNOTAVAIL:
	case EAFNOSUPPORT:
	case EHOSTDOWN:
	case EHOSTUNREACH:
	case EISCONN:
	case EMSGSIZE:
	case ENETDOWN:
	case ENETUNREACH:
	case ENOLINK:
	case ENOTCONN:
	case ENOTSOCK:
	case EPROTO:
	case EPROTONOSUPPORT:
	case EPROTOTYPE:
	case EPIPE:
		return PCS_ERR_NET;
	case ECONNABORTED:
	case ECONNREFUSED:
	case ECONNRESET:
	case ENETRESET:
	case ESHUTDOWN:
		return PCS_ERR_NET_ABORT;
	case ETIMEDOUT:
		return PCS_ERR_RESPONSE_TIMEOUT;
	case EBUSY:
	case ETXTBSY:
		return PCS_ERR_LEASE_CONFLICT;
	case EBADF:
	case EFBIG:
	case EINPROGRESS:
	case EIO:
#ifdef __LINUX__
	case EREMOTEIO:
#endif
	case ENOTTY:
	case ENXIO:
	case ESPIPE:
	case ESTALE:
	case EWOULDBLOCK:
	case EXDEV:
		return PCS_ERR_IO;
#else /* __WINDOWS__ */
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_OUTOFMEMORY:
		return PCS_ERR_NOMEM;
	case ERROR_OPERATION_ABORTED:
	case ERROR_CANCELLED:
	case WSAECANCELLED:
		return PCS_ERR_CANCEL_IO;
	case ERROR_INSUFFICIENT_BUFFER:
	case ERROR_SYMLINK_NOT_SUPPORTED:
	case WSAEPFNOSUPPORT:
	case WSAESOCKTNOSUPPORT:
		return PCS_ERR_INVALID;
	case ERROR_INVALID_BLOCK_LENGTH:
	case ERROR_INVALID_DATA:
	case ERROR_INVALID_FLAGS:
	case ERROR_INVALID_HANDLE:
	case ERROR_INVALID_PARAMETER:
	case WSAEINVAL:
		return PCS_ERR_INV_PARAMS;
	case ERROR_IO_INCOMPLETE:
	case WSAEINTR:
		return PCS_ERR_INTERRUPTED;
	case ERROR_CANNOT_MAKE:
	case ERROR_DISK_FULL:
	case ERROR_EA_TABLE_FULL:
	case ERROR_END_OF_MEDIA:
	case ERROR_HANDLE_DISK_FULL:
	case ERROR_NOT_ENOUGH_QUOTA:
		return PCS_ERR_NOSPACE;
	case ERROR_FILE_NOT_FOUND:
	case ERROR_MOD_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
	case WSAHOST_NOT_FOUND:
		return PCS_ERR_NOT_FOUND;
	case ERROR_ALREADY_EXISTS:
	case ERROR_FILE_EXISTS:
		return PCS_ERR_EXISTS;
	case ERROR_BAD_PATHNAME:
	case ERROR_CANT_RESOLVE_FILENAME:
	case ERROR_DIRECTORY: /* The directory name is invalid */
	case ERROR_FILENAME_EXCED_RANGE:
	case ERROR_INVALID_NAME:
	case ERROR_INVALID_DRIVE:
	case ERROR_INVALID_REPARSE_DATA:
		return PCS_ERR_INV_PATH;
	case ERROR_CURRENT_DIRECTORY:
	case ERROR_DIR_NOT_EMPTY:
		return PCS_ERR_NON_EMPTY_DIR;
	case ERROR_TOO_MANY_OPEN_FILES:
		return PCS_ERR_NORES;
	case ERROR_WRITE_PROTECT:
		return PCS_ERR_READONLY;
	case ERROR_ACCESS_DENIED:
	case ERROR_PRIVILEGE_NOT_HELD:
	case ERROR_VIRUS_INFECTED:
		return PCS_ERR_PERM;
	case ERROR_CALL_NOT_IMPLEMENTED:
	case ERROR_NOT_SUPPORTED:
	case ERROR_INVALID_FUNCTION:
		return PCS_ERR_UNSUPPORTED;
	case ERROR_LOCK_VIOLATION:
	case ERROR_SHARING_VIOLATION:
		return PCS_ERR_LEASE_CONFLICT;
	case ERROR_BAD_PIPE:
	case ERROR_BEGINNING_OF_MEDIA:
	case ERROR_BROKEN_PIPE:
	case ERROR_BUS_RESET:
	case ERROR_CRC:
	case ERROR_DEVICE_DOOR_OPEN:
	case ERROR_DEVICE_REQUIRES_CLEANING:
	case ERROR_DISK_CORRUPT:
	case ERROR_EOM_OVERFLOW:
	case ERROR_FILEMARK_DETECTED:
	case ERROR_GEN_FAILURE:
	case ERROR_IO_DEVICE:
	case ERROR_META_EXPANSION_TOO_LONG:
	case ERROR_NOT_SAME_DEVICE:
	case ERROR_NO_DATA:
	case ERROR_NO_DATA_DETECTED:
	case ERROR_NO_SIGNAL_SENT:
	case ERROR_OPEN_FAILED:
	case ERROR_PIPE_BUSY:
	case ERROR_PIPE_NOT_CONNECTED:
	case ERROR_SETMARK_DETECTED:
	case ERROR_SIGNAL_REFUSED:
		return PCS_ERR_IO;
	case ERROR_ADAP_HDW_ERR:
	case ERROR_ADDRESS_ALREADY_ASSOCIATED:
	case ERROR_BAD_DEV_TYPE:
	case ERROR_BAD_NET_NAME:
	case ERROR_BAD_NET_RESP:
	case ERROR_BAD_NETPATH:
	case ERROR_CONNECTION_COUNT_LIMIT:
	case ERROR_DEV_NOT_EXIST:
	case ERROR_DEVICE_NOT_CONNECTED:
	case ERROR_HOST_DOWN:
	case ERROR_HOST_UNREACHABLE:
	case ERROR_NET_WRITE_FAULT:
	case ERROR_NETNAME_DELETED:
	case ERROR_NETWORK_BUSY:
	case ERROR_NETWORK_UNREACHABLE:
	case ERROR_NO_NET_OR_BAD_PATH:
	case ERROR_NOT_CONNECTED:
	case ERROR_REM_NOT_LIST:
	case ERROR_REMOTE_SESSION_LIMIT_EXCEEDED:
	case ERROR_REQ_NOT_ACCEP:
	case ERROR_RETRY:
	case ERROR_SEM_TIMEOUT:
	case ERROR_SHARING_PAUSED:
	case ERROR_TOO_MANY_CMDS:
	case ERROR_TOO_MANY_NAMES:
	case ERROR_TOO_MANY_SESS:
	case ERROR_UNEXP_NET_ERR:
	case WSAEADDRINUSE:
	case WSAEADDRNOTAVAIL:
	case WSAEAFNOSUPPORT:
	case WSAEALREADY:
	case WSAEFAULT:
	case WSAEHOSTUNREACH:
	case WSAEISCONN:
	case WSAEMSGSIZE:
	case WSAENETUNREACH:
	case WSAENOBUFS:
	case WSAENOTCONN:
	case WSAENOTSOCK:
	case WSAEPROTONOSUPPORT:
	case WSANO_DATA:
	case WSAESHUTDOWN:
		return PCS_ERR_NET;
	case ERROR_CONNECTION_ABORTED:
	case ERROR_CONNECTION_REFUSED:
	case WSAECONNABORTED:
	case WSAECONNREFUSED:
	case WSAECONNRESET:
		return PCS_ERR_NET_ABORT;
	case WSAETIMEDOUT:
	case ERROR_TIMEOUT:
		return PCS_ERR_RESPONSE_TIMEOUT;
#endif
	case PCS_ESSL:	/* special kludge for SSL socket, no good errno/GetLastError for this */
		return PCS_ERR_SSL;
	default:
		pcs_log(LOG_WARN, "pcs_errno_to_err: Failed to convert errno %d to pcs error. Return PCS_ERR_UNKNOWN value.", err);
		return PCS_ERR_UNKNOWN;
	}
}

int pcs_sys_strerror_r(int err, char *buf, int buflen)
{
	buf[0] = 0;
#if defined (__WINDOWS__)
	wchar_t wbuf[1024];
	if (!FormatMessageW(
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
		wbuf, 1024, NULL) ||
	    !WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, buflen, NULL, NULL))
	{
		snprintf(buf, buflen, "Unknown error %d", err);
		return EINVAL;
	}
	return 0;
#elif defined (__LINUX__)
	/* When _GNU_SOURCE is defined GNU-specific version of strerror_r is provided */
	char *str = strerror_r(err, buf, buflen);
	if (str != buf)
		snprintf(buf, buflen, "%s", str);

	return 0;
#else
	return strerror_r(err, buf, buflen);
#endif
}

void pcs_log_syserror(int level, int err, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	pcs_valog(level | LOG_NONL, NULL, fmt, va);
	va_end(va);

	char buf[1024];
	if (err < 0)
		err = -err;
	pcs_sys_strerror_r(err, buf, sizeof(buf));
	pcs_log(level, "; error %d (%s)", err, buf);
}
