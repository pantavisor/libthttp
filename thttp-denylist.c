#include "mbedtls/config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/sha256.h"

#include "thttp-denylist.h"

#define HASH_LEN 32

struct thttp_denylist {
	size_t count;
	size_t cap;
	uint8_t (*hashes)[HASH_LEN];
};

static int hash_cmp(const void *a, const void *b)
{
	return memcmp(a, b, HASH_LEN);
}

static int hex_val(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

// parse a 64 digit hex string into out, returns 0 on success
static int parse_hash(const char *s, uint8_t *out)
{
	for (int i = 0; i < HASH_LEN; i++) {
		int hi = hex_val(s[2 * i]);
		int lo = hi < 0 ? -1 : hex_val(s[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		out[i] = (uint8_t)(hi << 4 | lo);
	}
	return 0;
}

static int add_hash(thttp_denylist_t *dl, const uint8_t *h)
{
	if (dl->count == dl->cap) {
		size_t cap = dl->cap ? dl->cap * 2 : 16;
		void *p = realloc(dl->hashes, cap * HASH_LEN);
		if (!p)
			return -1;
		dl->hashes = p;
		dl->cap = cap;
	}
	memcpy(dl->hashes[dl->count++], h, HASH_LEN);
	return 0;
}

thttp_denylist_t *thttp_denylist_load(const char *path, int *count)
{
	FILE *f;
	char *line = NULL;
	size_t len = 0;
	int lineno = 0;
	thttp_denylist_t *dl;

	if (count)
		*count = 0;
	if (!path || !*path)
		return NULL;

	f = fopen(path, "r");
	if (!f)
		return NULL;

	dl = calloc(1, sizeof(*dl));
	if (!dl) {
		fclose(f);
		return NULL;
	}

	while (getline(&line, &len, f) >= 0) {
		char *s = line;
		char *e;
		uint8_t h[HASH_LEN];

		lineno++;
		while (isspace((unsigned char)*s))
			s++;
		if (!*s || *s == '#')
			continue;
		e = s;
		while (*e && !isspace((unsigned char)*e) && *e != '#')
			e++;
		if (e - s != 2 * HASH_LEN) {
			fprintf(stderr,
				"thttp: denylist %s:%d: not a SHA-256 in hex, skipped\n",
				path, lineno);
			continue;
		}
		*e = '\0';
		if (parse_hash(s, h)) {
			fprintf(stderr,
				"thttp: denylist %s:%d: not a SHA-256 in hex, skipped\n",
				path, lineno);
			continue;
		}
		if (add_hash(dl, h))
			break;
	}
	free(line);
	fclose(f);

	if (dl->count > 1) {
		// sort and drop duplicates so lookups can use a binary search
		size_t n = 1;
		qsort(dl->hashes, dl->count, HASH_LEN, hash_cmp);
		for (size_t i = 1; i < dl->count; i++) {
			if (memcmp(dl->hashes[i], dl->hashes[n - 1], HASH_LEN))
				memmove(dl->hashes[n++], dl->hashes[i], HASH_LEN);
		}
		dl->count = n;
	}

	if (count)
		*count = (int)dl->count;
	return dl;
}

void thttp_denylist_free(thttp_denylist_t *dl)
{
	if (!dl)
		return;
	free(dl->hashes);
	free(dl);
}

int thttp_denylist_contains(const thttp_denylist_t *dl, const mbedtls_x509_crt *crt)
{
	uint8_t h[HASH_LEN];

	if (!dl || !dl->count || !crt || !crt->pk_raw.p || !crt->pk_raw.len)
		return 0;
	if (mbedtls_sha256_ret(crt->pk_raw.p, crt->pk_raw.len, h, 0))
		return 0;
	return bsearch(h, dl->hashes, dl->count, HASH_LEN, hash_cmp) != NULL;
}

int thttp_denylist_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
	(void)depth;
	if (thttp_denylist_contains(data, crt))
		*flags |= MBEDTLS_X509_BADCERT_OTHER;
	return 0;
}

void thttp_denylist_install(mbedtls_ssl_config *conf, thttp_denylist_t *dl)
{
	if (dl)
		mbedtls_ssl_conf_verify(conf, thttp_denylist_verify, dl);
}
