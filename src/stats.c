#include <inttypes.h>	/* PRIu64 */
#include <pthread.h>	/* pthread_mutex_lock() */

#ifdef HAVE_SSL
#include <wolfssl/options.h>	/* HAVE_SNI, HAVE_SECURE_RENEGOTIATION, ... */
#include <wolfssl/ssl.h>	/* wolfSSL_session_reused() */
#endif

#include "mb.h"		/* time_us() */
#include "net.h"	/* connection struct */
#include "stats.h"

pthread_mutex_t stats_file_lock = PTHREAD_MUTEX_INITIALIZER;

int write_stats_line(FILE *fd, connection *c, char *err) {
  char s[BUFSIZ];
  uint64_t now = time_us();
  uint64_t socket_writeable = c->cstats.writeable? c->cstats.writeable - c->cstats.start: 0;
  uint64_t connection_establishment = c->cstats.handshake? c->cstats.handshake - c->cstats.start: 0;
  uint64_t start_request, delay;

  if (c->cstats.reqs <= 1) {
    /* first request within an established connection or a connection error (c->cstats.reqs == 0) */
    start_request = c->cstats.start;		/* time [us] since the Epoch we *first tried* to establish this connection */
    delay = now - c->cstats.start;
  } else {
    /* keep-alive request, connection was established */
    start_request = c->cstats.established;	/* time [us] since the Epoch the socket became writeable *and* just before we successfully issued a new request */
    delay = now - c->cstats.established;
  }

  int len = snprintf(s, BUFSIZ, "%"PRIu64",%"PRIu64",%d,%"PRIu64",%"PRIu64",%s %s://%s:%d%s,%d,%d,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%d,%s\n",
    start_request,
    delay,
    c->status,					/* HTTP response status */
    c->written,					/* request length (including headers) */
    c->read,					/* response length (including headers) */
    c->method,					/* http|https */
    (c->scheme == http)? "http": "https",
    c->host,
    c->port,
    c->path,
    c->t->id,					/* thread id */
    c->fd,					/* connection id (file descriptor) */
    c->cstats.connections,			/* how many times we connected (initial connection + reconnections) */
    c->cstats.reqs,				/* number of requests sent since the last (re-)connection */
    c->cstats.start,				/* time [us] since the Epoch we *first tried* to establish this connection */
    socket_writeable,				/* time [us] it took for the socket to become writeable */
    connection_establishment,			/* time [us] it took to establish this connection (connection establishment delay) */
#ifdef HAVE_SSL
    c->ssl? wolfSSL_session_reused(c->ssl): 0,	/* TLS session: 1 -- reused, 0 -- not reused */
#else
    0,
#endif
    err? err: ""
    );

  pthread_mutex_lock(&stats_file_lock);
  fwrite(s, len, 1, fd);
  pthread_mutex_unlock(&stats_file_lock);

  return 0;
}
