/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#pragma once

#include "pcs_types.h"
#include "pcs_net_addr.h"

/* return IP addresses for specified hostname */
int pcs_resolve_hostname(const char *host, const char *svc, PCS_NET_ADDR_T addr[], int *nr, int passive);

/* return <= nr existing network addresses */
int pcs_get_local_addrs(PCS_NET_ADDR_T addrs[], int *nr);

/* return name of network interface for specified address */
int pcs_get_ifname_by_addr(PCS_NET_ADDR_T *addr,  char *buf, int buf_sz);

int pcs_get_addr_by_ifname(PCS_NET_ADDR_T *addr, const char *ifname);

/* return IPv4 address for default routing */
int pcs_get_default_addr(PCS_NET_ADDR_T *addr);

/* try to bind to the given ip address */
int pcs_is_net_addr_avail(PCS_NET_ADDR_T *addr);
