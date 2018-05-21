#ifdef HAVE_SSL

#include <string.h>		/* strlen() */
#include <sys/socket.h>		/* MSG_NOSIGNAL */

#include "merr.h"
#include "ssl.h"

/* Global variables */
WOLFSSL_CTX *ctx = NULL;

WOLFSSL_CTX *ssl_init(int ssl_version) {
  WOLFSSL_METHOD *method = NULL;

  switch (ssl_version) {
#ifndef NO_OLD_TLS
  case 0:
    method = wolfSSLv23_client_method();	/* Use highest possible version from SSLv3 - TLS 1.2 */
    break;

#ifdef WOLFSSL_ALLOW_SSLV3
  case 1:
    method = wolfSSLv3_client_method();
    break;
#endif

#ifndef NO_TLS
  case 2:
    method = wolfTLSv1_client_method();
    break;

  case 3:
    method = wolfTLSv1_1_client_method();
    break;
#endif				/* NO_TLS */

#endif				/* NO_OLD_TLS */

#ifndef NO_TLS
  case 4:
    method = wolfTLSv1_2_client_method();
    break;
#endif

#ifdef WOLFSSL_DTLS
#ifndef NO_OLD_TLS
  case -1:
    method = wolfDTLSv1_client_method();
    break;
#endif

  case -2:
    method = wolfDTLSv1_2_client_method();
    break;
#endif

  default:
    die(EXIT_FAILURE, "bad SSL version: %d\n", ssl_version);
    break;
  }

  if (method == NULL)
    die(EXIT_FAILURE, "unable to get SSL method\n");

  wolfSSL_Init();

  if ((ctx = wolfSSL_CTX_new(method)) != NULL) {
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
    wolfSSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
  }

  return ctx;
}

WOLFSSL *ssl_new(connection *c) {
  int n;

  if (ctx == NULL) return NULL;
  if (!c->ssl) c->ssl = wolfSSL_new(ctx);

  wolfSSL_set_using_nonblock(c->ssl, 1);

  /* associate the file descriptor with the session */
  wolfSSL_set_fd(c->ssl, c->fd);
  wolfSSL_SetIOReadFlags(c->ssl, MSG_NOSIGNAL);		/* no SIGPIPE */
  wolfSSL_SetIOWriteFlags(c->ssl, MSG_NOSIGNAL);	/* no SIGPIPE */

  if (c->ssl_session) {
    /* set the session ID to connect to the server */
    if ((n = wolfSSL_set_session(c->ssl, c->ssl_session)) != SSL_SUCCESS) {
      warning("failed to set SSL session: [%d]\n", c->fd);
    }
  }

  if ((n = wolfSSL_UseSNI(c->ssl, WOLFSSL_SNI_HOST_NAME, c->host, strlen(c->host))) != SSL_SUCCESS) {
    warning("failed to set using SNI: [%d]\n", c->fd);
  }
  wolfSSL_SNI_SetOptions(c->ssl, WOLFSSL_SNI_HOST_NAME, WOLFSSL_SNI_CONTINUE_ON_MISMATCH);

  /* do not call ssl_connect()/wolfSSL_connect(), leave that up to wolfSSL_write() when needed */

  return c->ssl;
}

int ssl_free(connection *c) {
  if (!c || !c->ssl) return 0;

  if (c->tls_session_reuse) {
    /* set up TLS session reuse */
    c->ssl_session = wolfSSL_get_session(c->ssl);
    /* note that it is possible for c->ssl_session == NULL */
  }

  wolfSSL_shutdown(c->ssl);
  wolfSSL_free(c->ssl); c->ssl = NULL;
  return 0;
}

void ssl_shutdown() {
  if (ctx) {
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
  }
  wolfSSL_Cleanup();
}

int ssl_connect(connection *c) {
  int err;
  int n;

  if ((n = wolfSSL_connect(c->ssl)) != SSL_SUCCESS) {
    switch (err = wolfSSL_get_error(c->ssl, n)) {
    case SSL_ERROR_WANT_READ:
      /* client would read block */
      break;

    case SSL_ERROR_WANT_WRITE:
      /* client would write blocks */
      break;

    default:
      error("ssl_connect(): unknown error: %s: [%d]\n", wolfSSL_ERR_reason_error_string(err), c->fd);
    }
  }

  return n;
}

ssize_t ssl_read(WOLFSSL *ssl, void *data, int sz) {
  int err;
  ssize_t n = (ssize_t) wolfSSL_recv(ssl, data, sz, MSG_NOSIGNAL);

  if (n < 0) {
    switch (err = wolfSSL_get_error(ssl, n)) {
    case SSL_ERROR_WANT_READ:
      /* client would read block */
      return -1;

    case SSL_ERROR_ZERO_RETURN:
      return 0;

    default:
      error("ssl_read(): %s\n", wolfSSL_ERR_reason_error_string(err));
      return n;
    }
  }

  return n;
}

int ssl_readable(connection *c) {
  return wolfSSL_pending(c->ssl);
}

ssize_t ssl_write(WOLFSSL *ssl, void *data, int sz) {
  int err;
  ssize_t n = (ssize_t) wolfSSL_send(ssl, data, sz, MSG_NOSIGNAL);

  if (n < 0) {
    switch (err = wolfSSL_get_error(ssl, n)) {
    case SSL_ERROR_WANT_READ:
      return -1;

    case SSL_ERROR_WANT_WRITE:
      return -1;

    default:
      error("ssl_write(): %s\n", wolfSSL_ERR_reason_error_string(err));
      return n;
    }
  }

  return n;
}

#endif /* HAVE_SSL */
