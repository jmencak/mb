#ifndef SSL_H
#define SSL_H

#include <wolfssl/options.h>	/* HAVE_SNI, HAVE_SECURE_RENEGOTIATION, ... */
#include <wolfssl/ssl.h>	/* WOLFSSL_CTX */

#include "net.h"

/* Module variables */
extern WOLFSSL_CTX *ctx;

/* Module functions */
extern WOLFSSL_CTX *ssl_init(int);
extern WOLFSSL *ssl_new(connection *);
extern int ssl_free(connection *c);
extern void ssl_shutdown();
extern int ssl_connect(connection *);
extern ssize_t ssl_read(WOLFSSL *, void *, int);
extern int ssl_readable(connection *);
extern ssize_t ssl_write(WOLFSSL *, void *, int);

#endif /* SSL_H */
