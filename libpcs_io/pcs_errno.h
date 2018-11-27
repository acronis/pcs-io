/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_ERRNO_H__
#define __PCS_ERRNO_H__

#include "pcs_types.h"
#include "pcs_error.h"

#include <errno.h>

#ifdef __WINDOWS__
/* on windows all error codes are in different places, e.g. WSAXXX */
#include "pcs_sock.h"
#endif

__must_check static inline int errno_eagain(int err)
{
#ifndef __WINDOWS__          
	return err == EAGAIN || err == EWOULDBLOCK; 
#else
	return err == WSATRY_AGAIN || err == WSAEWOULDBLOCK;
#endif
}

__must_check static inline int errno_enospc(int err)
{
#ifndef __WINDOWS__
	return err == ENOSPC || err == EDQUOT;
#else
	return pcs_errno_to_err(err) == PCS_ERR_NOSPACE;
#endif
}

#endif	/* __PCS_ERRNO_H__ */
