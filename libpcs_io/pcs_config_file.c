/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "rbtree.h"
#include "log.h"
#include "pcs_config_file.h"
#include "pcs_config.h"
#include "pcs_malloc.h"
#include "pcs_errno.h"
#include "bufqueue.h"

#ifndef __WINDOWS__
#include <unistd.h>
#endif

static inline int cmp(struct rb_node *n, ULONG_PTR k)
{
	struct pcs_config_node *node = rb_entry(n, struct pcs_config_node, rb);
	char *key = (char *)k;

	return strcmp(key, node->key);
}

/* strips whitespace from the passed string, returns its substring */
static char *strstrip(char *str)
{
	char *end;

	while ((str[0] != '\0') && isspace(str[0]))
		str++;
	end = str + strlen(str);
	while ((end > str) && isspace(end[-1]))
		end--;
	end[0] = '\0';

	return str;
}

/* Create empty configuration */
struct pcs_config* pcs_create_config(void)
{
	struct pcs_config *cfg = pcs_xmalloc(sizeof(*cfg));

	rb_init(&cfg->root);

	return cfg;
}

static void pcs_free_config_node(struct rb_node *n)
{
	struct pcs_config_node *node = rb_entry(n, struct pcs_config_node, rb);

	if (node->value_expanded != node->value)
		pcs_free(node->value_expanded);
	pcs_free(node);
}

/* Release config and all associated resources */
void pcs_free_config(struct pcs_config *cfg)
{
	if (cfg == NULL)
		return;

	rb_destroy(&cfg->root, &pcs_free_config_node);
	pcs_free(cfg);
}

static void cfg_insert_node(struct rb_root* cfg, const char *k, const char *v)
{
	size_t klen = strlen(k);
	size_t vlen = strlen(v);

	BUG_ON(klen == 0);
	BUG_ON(vlen == 0);

	struct pcs_config_node *node = pcs_xmalloc(sizeof(*node) + klen + vlen + 2);
	node->key = (char *)(node + 1);
	node->value = node->key + klen + 1;
	node->value_expanded = NULL;

	memcpy(node->key, k, klen + 1);
	memcpy(node->value, v, vlen + 1);

	struct rb_node *prev = rb_insert_node(cfg, &node->rb, cmp, (ULONG_PTR)node->key);
	if (prev != NULL) {
		rb_delete(cfg, prev);
		pcs_free_config_node(prev);
	}
}

static struct pcs_config_node* pcs_config_find(struct rb_root *root, const char *key)
{
	struct rb_node *node = rb_search_node(root, cmp, (ULONG_PTR)key);
	if (!node)
		return NULL;
	return rb_entry(node, struct pcs_config_node, rb);
}

void pcs_config_setstr(struct pcs_config *cfg, const char *key, const char *val)
{
	cfg_insert_node(&cfg->root, key, val);
}

void pcs_config_setint(struct pcs_config *cfg, const char *key, u64 val)
{
	char val_str[32];
	snprintf(val_str, sizeof(val_str), "%llu", (llu)val);

	cfg_insert_node(&cfg->root, key, val_str);
}

void pcs_config_setint_hex(struct pcs_config *cfg, const char *key, u64 val)
{
	char val_str[32];
	snprintf(val_str, sizeof(val_str), "%#llx", (llu)val);

	cfg_insert_node(&cfg->root, key, val_str);
}

void pcs_config_setnetaddr(struct pcs_config *cfg, const char *key, const PCS_NET_ADDR_T *val)
{
	char val_str[64];
	pcs_format_netaddr(val_str, sizeof(val_str), val);

	cfg_insert_node(&cfg->root, key, val_str);
}

int pcs_config_unset(struct pcs_config *cfg, const char *key)
{
	struct pcs_config_node *n = pcs_config_find(&cfg->root, key);
	if (!n)
		return 0;

	rb_delete(&cfg->root, &n->rb);
	pcs_free_config_node(&n->rb);
	return 1;
}

/* Parse single line */
int pcs_parse_config_line(struct pcs_config* cfg, char* buf)
{
	char *k, *v;

	k = strstrip(buf);
	/* skip comments and lines containing only whitespace */
	if ((k[0] == '#') || (k[0] == '\0'))
		return 0;

	v = strchr(k, '=');
	if (!v)
		return -1;
	*(v++) = '\0';

	k = strstrip(k);
	v = strstrip(v);
	if (!strcmp(k, "") || !strcmp(v, ""))
		return -1;

	cfg_insert_node(&cfg->root, k, v);
	return 0;
}

#define BUFF_SZ (1024)

/* Parse configuration file */
int pcs_parse_config_file(struct pcs_config* cfg, FILE *f)
{
	char buf[BUFF_SZ];

	while (!feof(f))
	{
		if (!fgets(buf, sizeof(buf), f))
			/* last line is empty, stop now */
			break;
		if (pcs_parse_config_line(cfg, buf)) {
			TRACE("Can't parse line '%s'", buf);
			return -1;
		}
	}
	return 0;
}

/* Create config structure and read configuration from the file
 * Returns config context on success or NULL on failure.
 */
struct pcs_config *pcs_read_config(const char *fname)
{
	FILE *f;
	int res = -1;
	struct pcs_config* cfg = pcs_create_config();
	if (!cfg)
		return 0;

	f = fopen(fname, "rte");
	if (f) {
		res = pcs_parse_config_file(cfg, f);
		fclose(f);
	}

	if (res) {
		pcs_free_config(cfg);
		return 0;
	} else
		return cfg;
}

struct pcs_config* pcs_read_config_mem(char *str)
{
	struct pcs_config *cfg = pcs_create_config();
	int ok = 1;
	int r;

	while (str != NULL) {
		char *p = strchr(str, '\n');
		if (p)
			*p = '\0';

		r = pcs_parse_config_line(cfg, str);

		if (p) {
			*p = '\n';
			str = p + 1;
		} else {
			str = NULL;
		}

		if (r != 0) {
			ok = 0;
			break;
		}
	}

	if (!ok) {
		pcs_free_config(cfg);
		cfg = NULL;
	}

	return cfg;
}

int pcs_write_config(struct pcs_config *cfg, const char *fname)
{
	struct pcs_config_node* n;
	FILE *f;
	int ret = 0;

	if (!cfg || !fname)
		return PCS_ERR_INV_PARAMS;
	f = fopen(fname, "we");
	if (!f)
		return PCS_ERR_IO;

	rb_for_each(struct pcs_config_node, n, &cfg->root, rb)
		fprintf(f, "%s=%s\n", n->key, n->value);

	if (fflush(f) || fsync(fileno(f))) {
		unlink(fname);
		ret = PCS_ERR_IO;
	}
	fclose(f);
	return ret;
}

char* pcs_write_config_mem(struct pcs_config *cfg)
{
	struct bufqueue bq;
	bufqueue_init(&bq);
	bq.prealloc_size = 1024;

	struct pcs_config_node *n;
	rb_for_each(struct pcs_config_node, n, &cfg->root, rb)
		bufqueue_printf(&bq, "%s=%s\n", n->key, n->value);

	u32 len = bufqueue_get_size(&bq);
	char *res = pcs_xmalloc(len + 1);
	bufqueue_get_copy(&bq, res, len);
	res[len] = '\0';

	return res;
}

int pcs_config_getstr(struct pcs_config *cfg, const char *key, const char **val)
{
	struct pcs_config_node *n = pcs_config_find(&cfg->root, key);
	if (!n)
		return -PCS_ERR_NOT_FOUND;

	(*val) = n->value;
	return 0;
}

int pcs_config_getstr_expand(struct pcs_config *cfg, const char *key, const char **val)
{
	struct pcs_config_node *n = pcs_config_find(&cfg->root, key);
	if (!n)
		return -PCS_ERR_NOT_FOUND;

	if (n->value_expanded) {
		(*val) = n->value_expanded;
		return 0;
	}

	char *str = n->value;
	const char *sep = "/\\.$()-+[];:<>?*\"'";
	int expanded, i, e, len = (int)strlen(str);

	do {
		expanded = 0;
		for (i = 0; i < len - 1; i++) {
			if (str[i] == '\\') {
				i++;
				continue;
			}

			if (str[i] != '$')
				continue;

			for (e = i + 1; e < strlen(str) && !strchr(sep, str[e]); e++) ;	/* find token end */
			if (e - (i + 1) < 1)
				continue;

			char *var = pcs_xstrndup(str + i + 1, e - i - 1);
			const char *var_val;
			int r = pcs_config_getstr(cfg, var, &var_val);
			pcs_free(var);

			if (r == -PCS_ERR_NOT_FOUND)
				continue;
			if (r)
				return r;

			var = pcs_xmalloc(len + strlen(var_val));
			snprintf(var, len + strlen(var_val), "%.*s%s%s", i, str, var_val, str + e);

			if (str != n->value)
				pcs_free(str);
			str = var;
			len = (int)strlen(str);

			expanded = 1;
			break;
		}
	} while (expanded);

	(*val) = n->value_expanded = str;
	return 0;
}

int pcs_str_to_int(const char *str, void *buf, size_t size)
{
	char *str_end;
	/* see NOTES in strtol(3) */
	errno = 0;
	long long int val = strtoll(str, &str_end, 0);
	if (*str_end != '\0')
		return -PCS_ERR_INVALID;
	if ((val == LLONG_MIN || val == LLONG_MAX) && errno == ERANGE)
		return -PCS_ERR_INVALID;

	if (size < sizeof(val)) {
		BUG_ON(size < 1);
		llu uval = (llu)val + ((llu)1 << (8 * size - 1));
		if (uval >> (8 * size))
			return -PCS_ERR_INVALID; /* overflow */
	}

	if (size == sizeof(s8))
		(*(s8 *)buf) = (s8)val;
	else if (size == sizeof(s16))
		(*(s16 *)buf) = (s16)val;
	else if (size == sizeof(s32))
		(*(s32 *)buf) = (s32)val;
	else if (size == sizeof(s64))
		(*(s64 *)buf) = (s64)val;
	else
		BUG();

	return 0;
}

int pcs_str_to_uint(const char *str, void *buf, size_t size)
{
	char *str_end;
	/* see NOTES in strtol(3) */
	errno = 0;
	llu val = strtoull(str, &str_end, 0);
	if (*str_end != '\0')
		return -PCS_ERR_INVALID;
	if (val == ULLONG_MAX && errno == ERANGE)
		return -PCS_ERR_INVALID;

	if (size < sizeof(val) && val >> (8 * size))
		return -PCS_ERR_INVALID; /* overflow */

	if (size == sizeof(u8))
		(*(u8 *)buf) = (u8)val;
	else if (size == sizeof(u16))
		(*(u16 *)buf) = (u16)val;
	else if (size == sizeof(u32))
		(*(u32 *)buf) = (u32)val;
	else if (size == sizeof(u64))
		(*(u64 *)buf) = (u64)val;
	else
		BUG();

	return 0;
}

int pcs_config_getint(struct pcs_config *cfg, const char *key, void *buf, size_t size)
{
	int r;
	const char *str;
	if ((r = pcs_config_getstr(cfg, key, &str)))
		return r;
	return pcs_str_to_int(str, buf, size);
}

int pcs_config_getuint(struct pcs_config *cfg, const char *key, void *buf, size_t size)
{
	int r;
	const char *str;
	if ((r = pcs_config_getstr(cfg, key, &str)))
		return r;
	return pcs_str_to_uint(str, buf, size);
}

int pcs_config_getnetaddr(struct pcs_config *cfg, const char *key, const char *def_port, PCS_NET_ADDR_T *val)
{
	int r;
	const char *str;
	if ((r = pcs_config_getstr(cfg, key, &str)))
		return r;

	return pcs_parse_netaddr_port(str, def_port, val) ? -PCS_ERR_INVALID : 0;
}

int pcs_config_get_view(struct pcs_config *cfg,
		void (*cb)(void *userp, const char *key, const char *val),
		void *userp)
{
	struct pcs_config_node* n;

	rb_for_each(struct pcs_config_node, n, &cfg->root, rb)
		cb(userp, n->key, n->value);

	return 0;
}
