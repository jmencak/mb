#ifndef SSL_H
#define SSL_H

#include <wolfssl/options.h>	/* HAVE_SNI, HAVE_SECURE_RENEGOTIATION, ... */
#include <wolfssl/ssl.h>	/* WOLFSSL_CTX */

#include "net.h"

/* Module variables */
extern WOLFSSL_CTX *ctx;

/* Module functions */
WOLFSSL_CTX *ssl_init(int);
WOLFSSL *ssl_new(connection *);
int ssl_free(connection *c);
void ssl_shutdown();
int ssl_connect(connection *);
ssize_t ssl_read(WOLFSSL *, void *, int);
int ssl_readable(connection *);
ssize_t ssl_write(WOLFSSL *, void *, int);

#endif /* SSL_H */
