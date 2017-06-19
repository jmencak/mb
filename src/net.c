#include <errno.h>		/* errno */
#include <fcntl.h>		/* fnctl() */
#include <linux/tcp.h>		/* TCP_NODELAY */
#include <netdb.h>		/* freeaddrinfo() */
#include <stdio.h>		/* stdout, stderr, fopen(), fclose() */
#include <stdlib.h>		/* free() */
#include <string.h>		/* strlen() */
#include <sys/ioctl.h>		/* ioctl, FIONREAD */
#include <sys/socket.h>		/* send/recv(), MSG_NOSIGNAL */
#include <unistd.h>		/* read(), close() */
#ifdef HAVE_SSL
#include <wolfssl/ssl.h>	/* WOLFSSL_CTX */
#endif

#include "mb.h"
#include "merr.h"
#include "net.h"
#ifdef HAVE_SSL
#include "ssl.h"
#endif
#include "stats.h"		/* MIN/MAX() */

/* Internal functions */
void aeCreateFileEventOrDie(aeEventLoop *, int, int, aeFileProc *, void *);
static inline char *http_headers_create(connection *, bool);
void http_request_create(connection *, const char *, char **, size_t *);
int socket_set_nonblock(int);
static int tcp_non_block_bind_connect(connection *);
int socket_readable(int);
static int socket_connect_delay_passed(aeEventLoop *, long long, void *);
static int socket_write_delay_passed(aeEventLoop *, long long, void *);
static inline bool connection_delay(connection *, aeTimeProc *);
void socket_reconnect(connection *);
void socket_read(aeEventLoop *, int, void *, int);
void socket_write(aeEventLoop *, int, void *, int);

void aeCreateFileEventOrDie(aeEventLoop *eventLoop, int fd, int mask,
                            aeFileProc *proc, void *clientData) {
  int ret = aeCreateFileEvent(eventLoop, fd, mask, proc, clientData);

  if (ret == AE_ERR) {
    error("aeCreateFileEvent() failed: %s: [%d]\n", strerror(errno), fd);
    if (errno == ERANGE) {
      if (aeResizeSetSize(eventLoop, eventLoop->setsize * 2) != AE_OK) {
        die(EXIT_FAILURE, "failed to increase eventLoop size to %d: %s: [%d]\n", eventLoop->setsize * 2, strerror(errno), fd);
      } else {
        info("increased eventLoop size to %d\n", eventLoop->setsize);
        aeCreateFileEventOrDie(eventLoop, fd, mask, proc, clientData);
      }
    }
  }
}

static inline char *http_headers_create(connection *c, bool conn_close) {
  connection *cs_ptr = c;
  size_t headers_len = 0;
  char *headers;
  char *headers_ptr;

  /* calculate headers length */
  if (cs_ptr->headers) {
    key_value *kv;
    for (kv = c->headers; kv->key; kv++) {
      headers_len += strlen(kv->key);
      if (kv->value) headers_len += strlen(kv->value);
      headers_len += 4;		/* ': ' + '\r\n' */
    }
  }
  if (conn_close) headers_len += 17 + 2;	/* HTTP_CONN_CLOSE + separators */
  if (cs_ptr->req_body) {
    headers_len += 14 + 4 + 20;			/* CONTENT_LENGTH + separators + 64-bit long content length */
  }

  if ((headers = calloc(headers_len + 1, sizeof(char))) == NULL)
    die(EXIT_FAILURE, "calloc(): cannot allocate memory for HTTP headers\n");

  /* fill in the headers string */
  headers_ptr = headers;
  if (cs_ptr->headers) {
    key_value *kv;
    for (kv = c->headers; kv->key; kv++) {
      strcpy(headers_ptr, kv->key);
      headers_ptr += strlen(kv->key);
      strcpy(headers_ptr, ": ");
      headers_ptr += 2;
      if (kv->value) {
        strcpy(headers_ptr, kv->value);
        headers_ptr += strlen(kv->value);
      }
      strcpy(headers_ptr, HTTP_EOL);
      headers_ptr += 2;
    }
  }
  if (conn_close) {
    /* Add "Connection: close" header */
    strcpy(headers_ptr, HTTP_CONN_CLOSE HTTP_EOL);
    headers_ptr += 17 + 2;	/* HTTP_CONN_CLOSE + separators */
  }
  if (cs_ptr->req_body) {
    /* Add Content-Length header */
    size_t content_len = strlen(cs_ptr->req_body);
    strcpy(headers_ptr, CONTENT_LENGTH);
    headers_ptr += strlen(CONTENT_LENGTH);
    sprintf(headers_ptr, ": %lu" HTTP_EOL, content_len);
  }

  return headers;
}

void http_request_create(connection *c, const char *headers, char **request, size_t *length)
{
  if ((*request = malloc(MAX_REQ_LEN + 1)) == NULL) {
    fprintf(stderr, "malloc(): cannot allocate memory for HTTP request\n");
    exit(EXIT_FAILURE);
  }

  snprintf(*request, MAX_REQ_LEN, HTTP_REQUEST,
	   c->method ? c->method : "GET",
	   c->path ? c->path : "/1",
	   c->host ? c->host : "localhost",
	   headers? headers: "",
	   c->req_body ? c->req_body : "");

  *length = strlen(*request);
}

void http_requests_create(connection *c)
{
  char *headers;

  if (c->request) free(c->request);
  if (c->request_cclose) free(c->request_cclose);

  headers = http_headers_create(c, 0);
  http_request_create(c, headers, &c->request, &c->request_length);
  if (headers) free(headers);
  headers = http_headers_create(c, 1);
  http_request_create(c, headers, &c->request_cclose, &c->request_cclose_length);
  if (headers) free(headers);
}

void connection_init(connection *c) {
  c->t = NULL;
  c->fd = -1;
  c->host_from = NULL;
  c->scheme = http;
  c->host = NULL;
  c->port = 80;
  c->addr_from = NULL;
  c->addr_to = NULL;
  c->method = NULL;
  c->path = NULL;
  c->headers = NULL;
  c->delay_min = 0;
  c->delay_max = 0;
  c->delayed = false;
  c->delayed_id = 0;
  c->ramp_up = 0;
  c->cstats.start = 0;
  c->cstats.writeable = 0;
  c->cstats.established = 0;
  c->cstats.handshake = 0;
  c->cstats.connections = 0;
  c->cstats.reqs = 0;
  c->cstats.reqs_total = 0;
  c->cstats.written_total = 0;
  c->cstats.read_total = 0;
  c->max_reqs = 0;
  c->keep_alive_reqs = 0;
  c->tls_session_reuse = true;
  c->req_body = NULL;
  c->request = NULL;
  c->request_cclose = NULL;
  c->conn_close = false;
  c->request_length = 0;
  c->request_cclose_length = 0;
  c->message_complete = false;
  c->written = 0;
  c->read = 0;
  c->status = 0;
#ifdef HAVE_SSL
  c->ssl = NULL;
  c->ssl_session = NULL;
#endif
  c->duplicate = false;
}

void connections_free(connection *cs) {
  connection *cs_ptr = cs;

  if (!cs_ptr) return;

  for (; cs_ptr->t != NULL; cs_ptr++) {
    if (cs_ptr->duplicate) {
      /* duplicated connection, most data structures already freed by freeing related connection */
      goto free_dups;
    }
    if (cs_ptr->host_from) free(cs_ptr->host_from);
    if (cs_ptr->host) free(cs_ptr->host);
    if (cs_ptr->addr_from) freeaddrinfo(cs_ptr->addr_from);
    if (cs_ptr->addr_to) freeaddrinfo(cs_ptr->addr_to);
    if (cs_ptr->method) free(cs_ptr->method);
    if (cs_ptr->path) free(cs_ptr->path);
    if (cs_ptr->headers) {
      key_value *kv;
      for (kv = cs_ptr->headers; kv->key; kv++) {
        if (kv->key) free(kv->key);
        if (kv->value) free(kv->value);
      }
      free(cs_ptr->headers);
    }
    if (cs_ptr->req_body) free(cs_ptr->req_body);
    if (cs_ptr->request) free(cs_ptr->request);
    if (cs_ptr->request_cclose) free(cs_ptr->request_cclose);

free_dups:
#ifdef HAVE_SSL
    if (cs_ptr->ssl) ssl_free(cs_ptr);
#endif
  }

  free(cs);
}

int socket_set_nonblock(int fd) {
  int flags;

  if ((flags = fcntl(fd, F_GETFL, 0)) == -1) {
    error("fcntl(F_GETFL): %s\n", strerror(errno));
    return -1;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    error("fcntl(F_SETFL, O_NONBLOCK): %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/* network address and service translation */
int host_resolve(char *host, int port, struct addrinfo **addr) {
  char portstr[6];		/* strlen("65535") + 1 */
  int rc;
  struct addrinfo hints = {
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM
  };

  if (addr == NULL) return -1;
  if (*addr) freeaddrinfo(*addr);

  /* we have not translated network address and service information for this host yet */
  snprintf(portstr, sizeof(portstr), "%d", port);
  if ((rc = getaddrinfo(host, portstr, &hints, addr)) != 0) {
    error("unable to resolve %s:%s: %s\n", host, portstr, gai_strerror(rc));
    return -1;
  }

  return 0;
}

pthread_mutex_t socket_lock = PTHREAD_MUTEX_INITIALIZER;
static int tcp_non_block_bind_connect(connection *c) {
  int fd, rc, flags = 1;
  struct addrinfo *a, *b;

  for (a = c->addr_to; a != NULL; a = a->ai_next) {
    pthread_mutex_lock(&socket_lock);
    /* this critical section prevents coredumps when there are too many open files (the call below returns fd < 0) */
    fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
    pthread_mutex_unlock(&socket_lock);
    if (fd == -1) continue;

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags)) == -1) {
      /* Disable the Nagle algorithm.  This means that segments are always sent
         as soon as possible, even if there is only a small amount of data. */
      error("unable to setsockopt TCP_NODELAY: %s\n", strerror(errno));
      goto error;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags)) == -1) {
      error("unable to setsockopt SO_REUSEADDR: %s\n", strerror(errno));
      goto error;
    }

    if (socket_set_nonblock(fd)) goto error;

    if (c->addr_from) {
      bool bound = false;

      for (b = c->addr_from; b != NULL; b = b->ai_next) {
        if ((rc = bind(fd, b->ai_addr, b->ai_addrlen)) != -1) {
          bound = true;
          break;
        }
      }
      if (!bound) {
        error("unable to bind source %s: %s\n", c->host_from, gai_strerror(rc));
        goto error;
      }
    }

    if (connect(fd, a->ai_addr, a->ai_addrlen) == -1) {
      if (errno == EINPROGRESS) {
        goto end;
      }
      close(fd);
      fd = -1;	/* prevent double close() */
      continue;
    }

end:
    return fd;
  }
  if (a == NULL)
    error("creating socket: %s\n", strerror(errno));

error:
  if (fd != -1) close(fd);
  return -1;
}

int socket_readable(int fd) {
  int n, rc;
  rc = ioctl(fd, FIONREAD, &n);		/* Get the number of bytes that are immediately available for reading. */
  return rc == -1 ? 0 : n;
}

static int socket_connect_delay_passed(aeEventLoop *loop, long long id, void *data) {
  connection *c = data;
  c->delayed = false;
  aeDeleteTimeEvent(loop, c->delayed_id);
  socket_connect(loop, c->fd, c, 0);
  return AE_NOMORE;
}

static int socket_write_delay_passed(aeEventLoop *loop, long long id, void *data) {
  connection *c = data;
  c->delayed = false;
  aeDeleteTimeEvent(loop, c->delayed_id);
  aeCreateFileEvent(loop, c->fd, AE_WRITABLE, socket_write, c);
  return AE_NOMORE;
}

static inline bool connection_delay(connection *c, aeTimeProc *f_cb) {
  uint64_t delay_min, delay_max, delay, ramp_up_end, ramp_up_delay;

  if (c->delayed) {
    uint64_t now = time_us();
    /* delay_min is guranteed to be <= delay_max (checks during json parsing) */
    delay_min = c->delay_min;
    delay_max = c->delay_max;
    if (c->ramp_up) {
      ramp_up_end = stats.start + (c->ramp_up * 1000);
      if (now < ramp_up_end) {
        ramp_up_delay = ((ramp_up_end - now)/1000)/2;	/* half of the remaining ramp-up interval in [ms] */
        delay_max = MAX(ramp_up_delay, c->delay_max);
      }
    }
    delay = (delay_min == delay_max)? delay_max: (rand() % (delay_max - delay_min + 1)) + delay_min;
    if (c->fd != -1) {
      /* the check above is necessary, we are not necessarily connected (have a valid fd) here */
      aeDeleteFileEvent(c->t->loop, c->fd, AE_WRITABLE);
    }
    c->delayed_id = aeCreateTimeEvent(c->t->loop, delay, f_cb, c, NULL);
    if (c->delayed_id == AE_ERR) {
      die(EXIT_FAILURE, "cannot create time event (delay): %s\n", strerror(errno));
    }
    return true;
  }

  return false;
}

void socket_connect(aeEventLoop *loop, int fd, void *data, int flags) {
  connection *c = data;

  if (connection_delay(c, socket_connect_delay_passed))
    /* delayed connection */
    return;

  c->cstats.start = time_us();
  c->fd = tcp_non_block_bind_connect(c);

  if (c->fd < 0) {
    char *msg = strerror(errno);
    error("cannot connect to %s:%d: %s\n", c->host, c->port, msg);
    if (errno == EMFILE) die(EXIT_FAILURE, "%s\n", msg);
    return;
  } else {
    /* connected to host c->host */
    c->cstats.connections++;
  }

  if (c->scheme == https) {
#ifdef HAVE_SSL
    if (!ssl_new(c)) {
      die(EXIT_FAILURE, "ssl_new() error\n");
    }
#else
    die(EXIT_FAILURE, "ssl support not compiled in\n");
#endif
  }

  http_parser_init(&c->parser, HTTP_RESPONSE);
  c->parser.data = c;

  aeCreateFileEventOrDie(loop, c->fd, AE_WRITABLE, socket_write, c);
}

void socket_reconnect(connection *c) {
#ifdef HAVE_SSL
  if (c->ssl) ssl_free(c);
#endif
  if (c->fd != -1) {
    aeDeleteFileEvent(c->t->loop, c->fd, AE_READABLE | AE_WRITABLE);
    close(c->fd);
  }
  c->delayed = c->delay_max;
  c->cstats.writeable = 0;
  c->cstats.established = 0;
  c->cstats.handshake = 0;
  c->cstats.reqs = 0;
  c->read = 0;
  c->written = 0;
  socket_connect(c->t->loop, c->fd, c, 0);
}

void socket_read(aeEventLoop *loop, int fd, void *data, int flags) {
  ssize_t n;
  connection *c = data;

  do {
    n = CONN_READ(c, RECVBUF);

    if (n < 0) {
      if (errno == EAGAIN) {
        if (c->conn_close) {
          /* Request with "Connection: close" header. */
          return;
        }
        /* HTTP keep-alive request */
        break;
      }
      if (c->message_complete) {
        /* message already complete, reconnect or send more data if keep-alive */
        break;
      }

      error("cannot read from [%d] (%s:%d): %s: reconnecting...\n", c->fd, c->host, c->port, strerror(errno));
      goto err_conn;
    }

    /* successfully read from a socket data or received EOF (n == 0) */
    c->read += n;
    c->cstats.read_total += n;
    c->t->buf[n] = '\0';

    if (c->parser.data) {
      size_t n_parsed;

      int old_state=c->parser.state;
      n_parsed = http_parser_execute(&c->parser, &parser_settings, c->t->buf, (size_t)n);
      if (n_parsed != n) {
        error("parser [%d] (%s:%d): %lu != %lu; %d->%d; reconnecting...\n", c->fd, c->host, c->port, n_parsed, n, old_state, c->parser.state);
        goto err_parser;
      }
    }
  } while (n != 0);

  if (c->conn_close || !http_should_keep_alive(&c->parser)) {
    goto reconnect;
  }
  /* we have a HTTP keep-alive connection */

  if (!c->message_complete) {
    /* HTTP response is not yet fully retrieved */
    return;
  }
  /* we have a complete response and continue with HTTP keep-alive requests on the current connection */
  c->read = 0;
  aeCreateFileEventOrDie(c->t->loop, c->fd, AE_WRITABLE, socket_write, c);
  return;

err_parser:
  c->status = 0;
  if (stats.fd) write_stats_line(stats.fd, c, "socket_read(): parser");
  stats.err_parser++;
  goto reconnect;

err_conn:
  c->status = 0;
  if (stats.fd) write_stats_line(stats.fd, c, "socket_read(): connection");
  stats.err_conn++;

reconnect:
  socket_reconnect(c);
}

void socket_write(aeEventLoop *loop, int fd, void *data, int flags) {
  ssize_t n;
  connection *c = data;
  uint64_t now_writable;
  size_t request_len, write_len;
  char *request;

  if (connection_delay(c, socket_write_delay_passed))
    /* delayed connection */
    return;

  if (c->max_reqs && c->cstats.reqs_total >= c->max_reqs) {
    /* we reached the maximum number of hits allowed */
    aeDeleteFileEvent(loop, c->fd, AE_WRITABLE);
    if (requests_max_cb) requests_max_cb();
    return;
  }
  c->conn_close = c->keep_alive_reqs && !((c->cstats.reqs_total + 1) % c->keep_alive_reqs);
  if (c->conn_close) {
    request = c->request_cclose;
    request_len = c->request_cclose_length;
  } else {
    request = c->request;
    request_len = c->request_length;
  }

  now_writable = time_us();
  if (c->cstats.writeable == 0)
    /* first request within an established connection */
    c->cstats.writeable = now_writable;

  write_len = request_len - c->written;

  n = CONN_WRITE(c, request + c->written, write_len);

  if (n < 0) {
    if (errno == EAGAIN) {
      return;
    }

    error("cannot write to [%d] (%s:%d): %s: reconnecting...\n", c->fd, c->host, c->port, strerror(errno));
    goto err_conn;
  } else {
    if (c->cstats.handshake == 0)
      /* first request within an established connection */
      c->cstats.handshake = now_writable;

    if (c->cstats.established == 0)
      /* a request within an established connection (keep-alive) */
      c->cstats.established = now_writable;

    c->written += n;
    c->cstats.written_total += n;

    if (c->written == request_len) {
      /* writing done */
      c->message_complete = false;
      c->cstats.reqs++;
      c->cstats.reqs_total++;
      aeDeleteFileEvent(loop, c->fd, AE_WRITABLE);
      aeCreateFileEventOrDie(loop, c->fd, AE_READABLE, socket_read, c);
    }
  }

  return;

err_conn:
  c->status = 0;
  if (stats.fd) write_stats_line(stats.fd, c, "socket_write()");
  stats.err_conn++;
  socket_reconnect(c);
}

#if 0
int headers_complete(http_parser *parser) {
  connection *c = parser->data;
  int status = parser->status_code;

  c->status = status;

  return 0;
}
#endif

int message_complete(http_parser *parser) {
  connection *c = parser->data;
  int status = parser->status_code;

  if (status > 399) stats.err_status++;

  c->status = status;
  if (stats.fd) write_stats_line(stats.fd, c, NULL);
  c->delayed = c->delay_max;
  c->cstats.established = 0;
  c->message_complete = true;
  c->written = 0;

  return 0;
}

int header_field(http_parser *parser, const char *at, size_t len) {
  info("header_field: `%s' (%ld)\n", at, len);
  return 0;
}

int header_value(http_parser *parser, const char *at, size_t len) {
  info("header_value: `%s' (%ld)\n", at, len);
  return 0;
}
