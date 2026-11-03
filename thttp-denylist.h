#ifndef THTTP_DENYLIST_H
#define THTTP_DENYLIST_H

#include <stdint.h>

#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

/*
 * Certificate denylist that works without a clock.
 *
 * File format: one SHA-256 per line, written as 64 hex digits, of the
 * certificate's DER encoded SubjectPublicKeyInfo. Blank lines and text
 * after '#' are ignored. Lines that are not valid are reported on stderr
 * and skipped. A certificate (leaf, intermediate or root) whose public key
 * is listed fails verification, even if it is re-issued with new dates.
 */
typedef struct thttp_denylist thttp_denylist_t;

/*
 * Load the denylist at path. Returns NULL if path is NULL or the file
 * cannot be opened (no denylist). If count is not NULL it receives the
 * number of entries loaded.
 */
thttp_denylist_t *thttp_denylist_load(const char *path, int *count);

void thttp_denylist_free(thttp_denylist_t *dl);

/* Returns 1 if the certificate's public key is on the list. */
int thttp_denylist_contains(const thttp_denylist_t *dl, const mbedtls_x509_crt *crt);

/*
 * mbedtls verify callback. data must be a thttp_denylist_t *. Marks every
 * listed certificate in the chain with MBEDTLS_X509_BADCERT_OTHER.
 */
int thttp_denylist_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags);

/* Install the callback on conf. The list must outlive conf. */
void thttp_denylist_install(mbedtls_ssl_config *conf, thttp_denylist_t *dl);

#endif
