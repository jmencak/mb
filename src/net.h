#ifndef NET_H
#define NET_H

#include <wolfssl/ssl.h>		/* WOLFSSL_CTX */
#include <stdbool.h>			/* bool, true, false */

#include "../version.h"
#include "../libae/ae.h"		/* aeEventLoop */
#include "../nginx/http_parser.h"	/* http_parser */

#define RECVBUF		8192
#define MAX_REQ_LEN	4096		/* maximum number of characters to send to a server */

#define HTTP_EOL	"\r\n"
#define HTTP_REQUEST	"%s %s HTTP/1.1" HTTP_EOL "Host: %s" HTTP_EOL "User-Agent: " PGNAME "/" MB_VERSION HTTP_EOL "Accept: */*" HTTP_EOL "%s" HTTP_EOL "%s"
#define HTTP_CONN_CLOSE	"Connection: close"
#define CONTENT_LENGTH	"Content-Length"

#define SOCK_READ(c, n)		((c->scheme == https)? ssl_read(c->ssl, c->t->buf, n): recv(c->fd, c->t->buf, n, MSG_NOSIGNAL))
#define SOCK_WRITE(c, buf, len)	((c->scheme == https)? ssl_write(c->ssl, c->request, len): send(c->fd, c->request, len, MSG_NOSIGNAL))
#define SOCK_READABLE(c)	((c->scheme == https)? ssl_readable(c): socket_readable(c))

typedef enum {
  http,
  https
} scheme;

typedef struct key_value {
  char* key;
  char* value;
} key_value;

typedef struct thread {
  uint64_t id;			/* thread id */
  pthread_t thread;
  aeEventLoop *loop;
  char buf[RECVBUF+1];		/* accommodate for the trailing '\0' */
} thread;

typedef struct connection {
  thread *t;			/* pointer to a thread that handles this connection */
  int fd;			/* file descriptor */
  char *host_from;		/* bind source IP address */
  scheme scheme;		/* http/https */
  char *host;			/* target host */
  int port;			/* target port */
  char *method;			/* method: (GET, HEAD, POST, PUT, DELETE, ... */
  char *path;			/* URL path */
  key_value *headers;		/* key/value header pairs */
  uint64_t delay_min;		/* minimum delay between requests on the connection [ms] */
  uint64_t delay_max;		/* maximum delay between requests on the connection [ms] */
  bool delayed;			/* whether we need to delay this connection by a time event */
  long long delayed_id;		/* ID of the delayed time event */
  uint64_t ramp_up;		/* JMeter-style ramp-up time (start slow) [ms] */
  struct {
    uint64_t start;		/* time [us] since the Epoch we *first tried* to establish this connection */
    uint64_t writeable;		/* time [us] since the Epoch the socket became *first* writeable */
    uint64_t established;	/* time [us] since the Epoch the socket became writeable *and* just before we successfully issued a new request */
    uint64_t handshake;		/* time [us] since the Epoch we first successfully written to a socket (connection establishment delay) */
    uint64_t connections;	/* how many times we connected (initial connection + reconnections) */
    uint64_t reqs;		/* number of requests sent over the current established connection (keep-alive) */
    uint64_t reqs_total;	/* total number of requests sent over this connection */
    uint64_t written_total;	/* total number of bytes written/sent over this connection */
    uint64_t read_total;	/* total number of bytes received over this connection */
  } cstats;
  uint64_t keep_alive_reqs;	/* maximum number of requests that can be sent over this connection before reconnecting */
  bool tls_session_reuse;	/* enable session resumption to reestablish the connection without a new handshake */
  char *req_body;		/* HTTP request body to send to a server */
  char *request;		/* HTTP request data (headers & body combined) to send to a server */
  bool conn_close;		/* Is the current request built as "Connection: close" request? */
  bool message_complete;	/* Do we have a complete HTTP response on this connection? */
  uint64_t written;		/* how many bytes of request was already written/sent */
  uint64_t read;		/* how many bytes of response was already read/received (including HTTP headers) */
  http_parser parser;		/* nginx parser */
  int status;			/* HTTP response status */
  WOLFSSL *ssl;			/* SSL object */
  WOLFSSL_SESSION *ssl_session;	/* SSL session cache */
  bool duplicate;		/* duplicate of a previous connection */
} connection;

/* Module functions */
#if 0
int headers_complete(http_parser *);
#endif
void connection_init(connection *);
void connections_free(connection *);
void socket_connect(aeEventLoop *, int, void *, int);
extern int message_complete(http_parser *);
extern int header_field(http_parser *, const char *, size_t);
extern int header_value(http_parser *, const char *, size_t);
extern int response_body(http_parser *, const char *, size_t);

#endif /* NET_H */
