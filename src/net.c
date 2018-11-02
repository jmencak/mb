#include <ctype.h>		/* isspace() */
#include <errno.h>		/* errno */
#include <fcntl.h>		/* fnctl() */
#include <netdb.h>		/* freeaddrinfo() */
#include <netinet/tcp.h>	/* TCP_NODELAY, TCP_FASTOPEN, ... */
#include <stdio.h>		/* stdout, stderr, fopen(), fclose() */
#include <stdlib.h>		/* free() */
#include <string.h>		/* strlen() */
#include <sys/ioctl.h>		/* ioctl, FIONREAD */
#include <sys/socket.h>		/* send/recv(), MSG_NOSIGNAL */
#include <unistd.h>		/* read(), close() */

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
void http_request_create_cc(connection *);
void http_request_create_ka(connection *);
int socket_set_nonblock(int);
int socket_set_keep_alive(int, int, int, int);
static int tcp_non_block_bind_connect(connection *);
int socket_readable(int);
static void socket_write_enable(connection *);
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

/*
 * Create HTTP headers
 * Note: this function has a side effect of trimming request body, when content length is too large.
 */
static inline char *http_headers_create(connection *c, bool conn_close) {
  connection *cs_ptr = c;
  size_t headers_len = 0;
  char *headers;
  char *headers_ptr;

  /* calculate headers length */
  headers_len += strlen(c->method ? c->method : "GET") + 1 + strlen(c->path ? c->path : "/") + 1 + strlen(HTTP_PROTO) + 2;	/* + 2x spaces + HTTP_CRLF */
  headers_len += strlen(HTTP_HOST) + 2 + strlen(c->host ? c->host : "localhost") + 2;	/* + ': ' + HTTP_CRLF */
  headers_len += strlen(HTTP_USER_AGENT) + 2;		/* + HTTP_CRLF */
  headers_len += strlen(HTTP_ACCEPT) + 2;		/* + HTTP_CRLF */

  if (cs_ptr->headers) {
    key_value *kv;
    for (kv = c->headers; kv->key; kv++) {
      headers_len += strlen(kv->key);
      if (kv->value) headers_len += strlen(kv->value);
      headers_len += 4;		/* ': ' + '\r\n' */
    }
  }
  if (cs_ptr->cookies) {
    headers_len += 6 + strlen(cs_ptr->cookies) + 4;	/* HTTP_COOKIE + cookie length + separators */
  }
  if (conn_close) headers_len += 17 + 2;		/* HTTP_CONN_CLOSE + separators */
  if (cs_ptr->req_body) {
    headers_len += 14 + 4 + HTTP_CONT_MAX;		/* HTTP_CONT_LEN + separators + HTTP_CONT_MAX */
  }

  if ((headers = calloc(headers_len + 1, sizeof(char))) == NULL)
    die(EXIT_FAILURE, "calloc(): cannot allocate memory for HTTP headers\n");

  /* fill in the headers string */
  headers_ptr = headers;
  headers_ptr += sprintf(headers_ptr,
           "%s %s " HTTP_PROTO HTTP_CRLF
           HTTP_HOST ": %s" HTTP_CRLF
           HTTP_USER_AGENT HTTP_CRLF
           HTTP_ACCEPT HTTP_CRLF,
           c->method ? c->method : "GET",
           c->path ? c->path : "/",
           c->host ? c->host : "localhost");

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
      strcpy(headers_ptr, HTTP_CRLF);
      headers_ptr += 2;
    }
  }
  if (cs_ptr->cookies) {
    /* Add "Cookie: " header */
    strcpy(headers_ptr, HTTP_COOKIE);
    headers_ptr += 6;
    strcpy(headers_ptr, ": ");
    headers_ptr += 2;
    strcpy(headers_ptr, cs_ptr->cookies);
    headers_ptr += strlen(cs_ptr->cookies);
    strcpy(headers_ptr, HTTP_CRLF);
    headers_ptr += 2;
  }
  if (conn_close) {
    /* Add "Connection: close" header */
    strcpy(headers_ptr, HTTP_CONN_CLOSE HTTP_CRLF);
    headers_ptr += 17 + 2;	/* HTTP_CONN_CLOSE + separators */
  }

  if (cs_ptr->req_body) {
    /* Add Content-Length header */
    size_t content_len = strlen(cs_ptr->req_body);
    strcpy(headers_ptr, HTTP_CONT_LEN);
    headers_ptr += strlen(HTTP_CONT_LEN);
    if (headers_len + 2 + content_len > MAX_REQ_LEN) {
      warning("content length too large (%ld), trimming; consider increasing MAX_REQ_LEN (%ld)\n", content_len, MAX_REQ_LEN);
      content_len = MAX_REQ_LEN - headers_len - 2;
      cs_ptr->req_body[content_len] = 0;
    }
    sprintf(headers_ptr, ": %lu" HTTP_CRLF, content_len);
  }

  return headers;
}

void http_request_create(connection *c, const char *headers, char **request, size_t *length)
{
  size_t request_len = strlen(headers) + 2 + (c->req_body? strlen(c->req_body): 0) + 1;	/* + HTTP_CRLF + '\0' */
  if ((*request = malloc(request_len + 1)) == NULL) {
    fprintf(stderr, "malloc(): cannot allocate memory for HTTP request\n");
    exit(EXIT_FAILURE);
  }

  snprintf(*request, request_len, "%s" HTTP_CRLF "%s",
           headers? headers: "",
           c->req_body ? c->req_body : "");

  *length = strlen(*request);
}

void http_request_create_cc(connection *c)
{
  char *headers;

  if (c->request_cclose) free(c->request_cclose);

  headers = http_headers_create(c, 1);
  http_request_create(c, headers, &c->request_cclose, &c->request_cclose_length);
  if (headers) free(headers);
}

void http_request_create_ka(connection *c)
{
  char *headers;

  if (c->request) free(c->request);

  headers = http_headers_create(c, 0);
  http_request_create(c, headers, &c->request, &c->request_length);
  if (headers) free(headers);
}

void http_requests_create(connection *c)
{
  http_request_create_cc(c);
  http_request_create_ka(c);
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
  c->tcp.keep_alive.enable = false;
  c->tcp.keep_alive.idle = 0;
  c->tcp.keep_alive.intvl = 0;
  c->tcp.keep_alive.cnt = 0;
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
  c->reqs_max = 0;
  c->keep_alive_reqs = 0;
  c->tls_session_reuse = true;
  c->req_body = NULL;
  c->request = NULL;
  c->request_cclose = NULL;
  c->close_client = false;
  c->close_linger = false;
  c->close_linger_sec = 0;
  c->cclose = false;
  c->header_cclose = false;
  c->request_length = 0;
  c->request_cclose_length = 0;
  c->message_complete = false;
  c->written = 0;
  c->read = 0;
  c->status = 0;
  c->cookies = NULL;
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

free_dups:
    if (cs_ptr->request) free(cs_ptr->request);
    if (cs_ptr->request_cclose) free(cs_ptr->request_cclose);
    if (cs_ptr->cookies) free(cs_ptr->cookies);

#ifdef HAVE_SSL
    if (cs_ptr->ssl) ssl_free(cs_ptr);
#endif
  }

  free(cs);
}

int socket_set_nonblock(int fd) {
  int flags;

  if ((flags = fcntl(fd, F_GETFL, 0)) == -1) {
    error("fcntl(F_GETFL): %s (%d)\n", strerror(errno), errno);
    return -1;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    error("fcntl(F_SETFL, O_NONBLOCK): %s (%d)\n", strerror(errno), errno);
    return -1;
  }

  return 0;
}

int socket_set_keep_alive(int fd, int idle, int intvl, int cnt) {
  int flags = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags)) == -1) {
    error("unable to setsockopt SO_KEEPALIVE: %s\n", strerror(errno));
    return -1;
  }

  /* Send first probe after `idle' seconds.  The default is 7200 (as of Linux 4.18.16). */
  flags = idle;
  if (flags && setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, (void *)&flags, sizeof(flags)) == -1) {
    error("unable to setsockopt TCP_KEEPIDLE: %s\n", strerror(errno));
    return -1;
  }

  /* Send the next probes after the specified interval. */
  flags = intvl;
  if (flags && setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, (void *)&flags, sizeof(flags)) == -1) {
    error("unable to setsockopt TCP_KEEPINTVL: %s\n", strerror(errno));
    return -1;
  }

  /* Consider the socket in error state after we send cnt probes without getting
     a reply. */
  flags = cnt;
  if (flags && setsockopt(fd, SOL_TCP, TCP_KEEPCNT, (void *)&flags, sizeof(flags)) == -1) {
    error("unable to setsockopt TCP_KEEPCNT: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/* network address and service translation */
int host_resolve(char *host, int port, struct addrinfo **addr) {
  char portstr[6];              /* strlen("65535") + 1 */
  int retry = 2;
  int rc = -1;
  struct addrinfo hints = {
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM
  };

  if (addr == NULL) return -1;
  if (*addr) freeaddrinfo(*addr);

  /* we have not translated network address and service information for this host yet */
  snprintf(portstr, sizeof(portstr), "%d", port);

  for (; rc != 0 && retry >= 0; retry--) {
    if ((rc = getaddrinfo(host, portstr, &hints, addr)) != 0) {
      /* failed to resolve a host */
      if (retry == 0) {
        error("unable to resolve %s:%s: %s\n", host, portstr, gai_strerror(rc));
        return -1;
      } else {
        warning("unable to resolve %s:%s: %s, retrying\n", host, portstr, gai_strerror(rc));
      }
      usleep(100000);   /* sleep for a while, before re-trying */
    }
  }

  return rc;
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

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags)) == -1) {
      /* Disable the Nagle algorithm.  This means that segments are always sent
         as soon as possible, even if there is only a small amount of data. */
      error("unable to setsockopt TCP_NODELAY: %s (%d)\n", strerror(errno), errno);
      goto error;
    }

#if 0
    if (setsockopt(fd, SOL_TCP, TCP_FASTOPEN, (void *)&flags, sizeof(flags)) == -1) {
      error("unable to setsockopt TCP_FASTOPEN: %s (%d)\n", strerror(errno), errno);
      goto error;
    }

    if (setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&flags, sizeof(flags)) == -1) {
      error("unable to setsockopt TCP_QUICKACK: %s (%d)\n", strerror(errno), errno);
      goto error;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *)&flags, sizeof(flags)) == -1) {
      error("unable to setsockopt SO_RCVBUF: %s (%d)\n", strerror(errno), errno);
      goto error;
    }
#endif

    if (c->close_linger) {
      struct linger l;
      l.l_onoff = 1;
      l.l_linger = c->close_linger_sec;
      if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof(l)) == -1) {
        error("unable to setsockopt SO_LINGER: %s (%d)\n", strerror(errno), errno);
        goto error;
      }
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags)) == -1) {
      error("unable to setsockopt SO_REUSEADDR: %s (%d)\n", strerror(errno), errno);
      goto error;
    }

    if (socket_set_nonblock(fd)) goto error;
    if (c->tcp.keep_alive.enable)
      if (socket_set_keep_alive(fd, c->tcp.keep_alive.idle, c->tcp.keep_alive.intvl, c->tcp.keep_alive.cnt))
        goto error;

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
    error("creating socket: %s (%d)\n", strerror(errno), errno);

error:
  if (fd != -1) close(fd);
  return -1;
}

int socket_readable(int fd) {
  int n, rc;
  rc = ioctl(fd, FIONREAD, &n);		/* Get the number of bytes that are immediately available for reading. */
  return rc == -1 ? 0 : n;
}

static void socket_write_enable(connection *c) {
  c->written = 0;
  c->cstats.established = 0;
  aeCreateFileEventOrDie(c->t->loop, c->fd, AE_WRITABLE, socket_write, c);
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
  socket_write_enable(c);
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
    c->delayed_id = aeCreateTimeEvent(c->t->loop, delay, f_cb, c, NULL);
    if (c->delayed_id == AE_ERR) {
      die(EXIT_FAILURE, "cannot create time event (delay): %s (%d)\n", strerror(errno), errno);
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
    error("cannot connect to %s:%d: %s (%d)\n", c->host, c->port, msg, errno);
    if (errno == EMFILE) die(EXIT_FAILURE, "%s (%d)\n", msg, errno);
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

  socket_write_enable(c);
}

void socket_reconnect(connection *c) {
#ifdef HAVE_SSL
  if (c->ssl) ssl_free(c);
#endif
  if (c->fd != -1) {
    aeDeleteFileEvent(c->t->loop, c->fd, AE_READABLE | AE_WRITABLE);
    if (shutdown(c->fd, SHUT_RDWR) == -1) {
      /* Ignore errors on shutdown(), e.g. when the target is no longer connected */
    }
    if (close(c->fd) == -1) {
      error("socket_reconnect(): close() failed: [%d] %s (%d)\n", c->fd, strerror(errno), errno);
    }
    c->fd = -1;
  }
  if (c->delayed_id) {
    /* we have a delayed time event on this connection, delete it */
    aeDeleteTimeEvent(c->t->loop, c->delayed_id);
  }

  free(c->cookies); c->cookies = NULL;
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
  size_t parser_n_parsed;
  int parser_old_state=c->parser.state;

  do {
    n = CONN_READ(c, RECVBUF);

    if (n < 0) {
      if (errno == EAGAIN) {
        return;
      }

      /* ECONNRESET (104) and simillar */
      error("cannot read from [%d] (%s:%d): %s: (%d) reconnecting...\n", c->fd, c->host, c->port, strerror(errno), errno);
      goto err_conn;
    }

    if (n == 0) {
      /*
       * Stream socket peer has performed an orderly shutdown (EOF).
       * This doesn't need to be client initiated, e.g. server-side disconnect to keep
       * the number of non-active TCP open connections low.
       */
      error("host sent an empty reply [%d] (%s:%d): %s: (%d) reconnecting...\n", c->fd, c->host, c->port, strerror(errno), errno);
      goto err_conn;
    }

    /* successfully read from a socket */
    c->read += n;
    c->cstats.read_total += n;
    c->t->buf[n] = '\0';

    parser_old_state=c->parser.state;
    parser_n_parsed = http_parser_execute(&c->parser, &parser_settings, c->t->buf, (size_t)n);
    if (parser_n_parsed != n) {
      error("parser [%d] (%s:%d): %lu != %lu; %d->%d; reconnecting...\n", c->fd, c->host, c->port, parser_n_parsed, n, parser_old_state, c->parser.state);
      goto err_parser;
    }
#ifdef HAVE_SSL
    /*
     * With SSL we cannot rely on the event loop (epoll) to trigger the next socket_read().
     * The following code is necessary when we have a small RECVBUF, i.e. (n == RECVBUF)
     */
    if (c->ssl && CONN_READABLE(c)) {
      /* there is data buffered and available in the SSL object to be read */
      continue;
    }
#endif
    break;
  } while (true);

  if (c->message_complete) {
    /* HTTP response is fully retrieved */
  } else {
    /* HTTP response is not yet fully retrieved */
    return;
  }

  /* we have a fully retrieved HTTP response */
  if (c->header_cclose || !http_should_keep_alive(&c->parser)) {
    /* we asked for a connection close or host responded with "Connection: close", or both */
    goto reconnect;
  }
  /* we have a HTTP keep-alive connection */

  if (c->cclose) {
    /* we have a complete response and closing the connection from the client side */
    goto reconnect;
  }
  /* we have a complete response and continue with HTTP keep-alive requests on the current connection */
  c->read = 0;

  if (connection_delay(c, socket_write_delay_passed)) {
    /* delayed write on the current connection */
    return;
  }

  /* no delay, schedule a write event immediately */
  socket_write_enable(c);
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
  bool cclose = false;
  uint64_t now_writable;
  size_t request_len, write_len;
  char *request;

  if (c->reqs_max && c->cstats.reqs_total >= c->reqs_max) {
    /* we reached the maximum number of hits allowed */
    aeDeleteFileEvent(loop, c->fd, AE_WRITABLE);
    if (requests_max_cb) requests_max_cb();
    return;
  }
  cclose = c->keep_alive_reqs && !((c->cstats.reqs_total + 1) % c->keep_alive_reqs);
  if (c->close_client) {
    /* always keep-alive connections, close from the client side (c->header_cclose == false) */
    c->cclose = cclose;
  } else {
    /* once we have the last request, ask the server to close the connection by "Connection: close" (c->header_cclose == true) */
    c->header_cclose = cclose;
  }
  if (c->cookies && c->written == 0) {
    /* we have some cookies => need to re-create HTTP requests */
    if (c->header_cclose) {
      http_request_create_cc(c);
    } else {
      http_request_create_ka(c);
    }
  }
  if (c->header_cclose) {
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

  write_len = (request_len - c->written) > SNDBUF? SNDBUF: request_len - c->written;

  n = CONN_WRITE(c, request + c->written, write_len);

  if (n < 0) {
    if (errno == EAGAIN) {
      return;
    }

    /* ECONNRESET (104) and simillar */
    error("cannot write to [%d] (%s:%d): %s (%d) reconnecting...\n", c->fd, c->host, c->port, strerror(errno), errno);
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
      free(c->cookies); c->cookies = NULL;
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
  c->message_complete = true;

  return 0;
}

int header_field(http_parser *parser, const char *at, size_t len) {
  connection *c = parser->data;
  const char *p_at = at;	/* pointer to the current character of the new cookie */
  const char *p_end;		/* pointer right after the last character of the new cookie header line */
  const char *p_kvend;		/* pointer right after the last character of the new key=value cookie pair */
  char *cookies;

  /* a very trivial and naive implementation of session cookies */
  if (len == 10 && !strncmp(at, "Set-Cookie", 10)) {
    p_at += 11;
    p_end = p_at;

    /* find the end of the Set-Cookie header */
    while (*p_end != '\n' && *p_end != '\r' && *p_end)
      p_end++;

    while ((p_at < p_end) && isspace(*p_at))
      p_at++;

    /* find the end of the key-value pair */
    p_kvend = p_at;
    while (p_kvend < p_end  && *p_kvend != ';' && *p_kvend != ' ' && *p_kvend != '\t')
      p_kvend++;

    /* the new cookie is between p_at and p_kvend as `var=value' */
    if (c->cookies != NULL) {
      const char *p_eq, *p_old_kvend, *oldcookie = c->cookies;
      char *newcookie;
      if ((newcookie = cookies = (char *) calloc(strlen(oldcookie) + p_kvend - p_at + 3, sizeof(char))) == NULL)
        die(EXIT_FAILURE, "calloc(): cannot allocate memory for HTTP cookies\n"); /* 3: 1 ("\0") + 2 ("; ") */

      p_eq = p_at;

      /* find the equal sign of the key=value pair */
      while (p_eq < p_kvend && *p_eq != '=')
        p_eq++;

      if (p_eq == p_kvend) {
        warning("ignoring a malformed cookie (missing an equal sign): %s\n", p_at);
        return 1;
      }

      /* the new cookie name (key) is between p_at and p_eq */
      while (*oldcookie) {
        p_old_kvend = oldcookie;

        /* find the end of the old cookie key=value */
        while (*p_old_kvend != ';' && *p_old_kvend != ' ' && *p_old_kvend)
          p_old_kvend++;

        /* copy old cookie key=value pairs */
        if (strncmp(oldcookie, p_at, p_eq - p_at) != 0) {
          /* key does not match the new key=value pair => copy */
          if (oldcookie != c->cookies) {
            /* an old cookie was copied, add "; " separator */
            strcpy(newcookie, "; ");
            newcookie += 2;
          }
          memcpy(newcookie, oldcookie, p_old_kvend - oldcookie);
          newcookie += p_old_kvend - oldcookie;
        }

        /* find the next key=value pair */
        oldcookie = p_old_kvend;
        while (*oldcookie && (*oldcookie == ';' || *oldcookie == ' '))
          oldcookie++;
      }

      if (oldcookie != c->cookies) {
        /* an old cookie was copied, add "; " separator */
        strcpy(newcookie, "; ");
        newcookie += 2;
      }
      memcpy(newcookie, p_at, p_kvend - p_at);
      newcookie += (p_kvend - p_at);
      free(c->cookies);
      c->cookies = cookies;
    } else {
      /* until now we haven't had any cookies */
      if ((cookies = calloc(p_kvend - p_at + 1, sizeof(char))) == NULL)
        die(EXIT_FAILURE, "calloc(): cannot allocate memory for HTTP cookies\n");

      memcpy(cookies, p_at, p_kvend - p_at);
      c->cookies = cookies;
    }
  }

  return 0;
}

int header_value(http_parser *parser, const char *at, size_t len) {
  info("header_value: `%s' (%ld)\n", at, len);
  return 0;
}
