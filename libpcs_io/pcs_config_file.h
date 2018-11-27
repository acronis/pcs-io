/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_CONFIG_FILE_H
#define _PCS_CONFIG_FILE_H

#include <pcs_net_addr.h>
#include <pcs_types.h>
#include <rbtree.h>

#include <stdio.h>

struct pcs_config {
	struct rb_root root;
};

struct pcs_config_node {
	struct rb_node rb;
	char *key;
	char *value;
	char *value_expanded;
};

/* Create empty configuration */
PCS_API struct pcs_config* pcs_create_config(void);

/* Parse configuration file */
PCS_API int pcs_parse_config_file(struct pcs_config* cfg, FILE *f);

/* Parse single line */
PCS_API int pcs_parse_config_line(struct pcs_config* cfg, char* str);

/* Release config and all associated resources */
PCS_API void pcs_free_config(struct pcs_config *cfg);

/* Create config structure and read configuration from the file
 * Returns config context on success or NULL on failure.
 */
PCS_API struct pcs_config* pcs_read_config(const char *fname);

/* Read a config from a string. Returns config context on success, or NULL on failure.
   Note: this function modifies @str (but restores it before returning). */
PCS_API struct pcs_config* pcs_read_config_mem(char *str);

/* Writes existing config structure into file.
 * Does not guarantee atomicity!
 * Either writes the whole config or nothing.
 */
PCS_API int pcs_write_config(struct pcs_config *cfg, const char *fname);

/* Writes a config to a string. The caller is responsible to free the result string. */
PCS_API char* pcs_write_config_mem(struct pcs_config *cfg);

/* Various getters. */
PCS_API int pcs_config_getstr(struct pcs_config *cfg, const char *key, const char **val);
PCS_API int pcs_config_getstr_expand(struct pcs_config *cfg, const char *key, const char **val);

PCS_API int pcs_config_getint(struct pcs_config *cfg, const char *key, void *buf, size_t size);
PCS_API int pcs_config_getuint(struct pcs_config *cfg, const char *key, void *buf, size_t size);

PCS_API int pcs_config_getnetaddr(struct pcs_config *cfg, const char *key, const char *def_port, PCS_NET_ADDR_T *val);

PCS_API int pcs_config_get_view(struct pcs_config *cfg,
		void (*cb)(void *userp, const char *key, const char *val),
		void *userp);

PCS_API void pcs_config_setstr(struct pcs_config *cfg, const char *key, const char *val);
PCS_API void pcs_config_setint(struct pcs_config *cfg, const char *key, u64 val);
PCS_API void pcs_config_setint_hex(struct pcs_config *cfg, const char *key, u64 val);
PCS_API void pcs_config_setnetaddr(struct pcs_config *cfg, const char *key, const PCS_NET_ADDR_T *val);

PCS_API int pcs_config_unset(struct pcs_config *cfg, const char *key);

/* Helper routines for string to integer conversion */
int pcs_str_to_int (const char *str, void *buf, size_t size);
int pcs_str_to_uint(const char *str, void *buf, size_t size);


#endif /* _PCS_CONFIG_FILE_H */
