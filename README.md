# mb: Multiple-host HTTP(s) Benchmarking tool

The [mb](https://github.com/jmencak/mb)
client aims to be a clean, simple and scalable tool to generate
significant HTTP(s) load against multiple targets from a single host.  It
also has a per-target reporting functionality.  Similarly to Will Glozer's
[fantastic tool](https://github.com/wg/wrk)
it combines a multithreaded design with scalable event notification systems.


## Quick start

```
$ mb -h
```

mb expects specification of the requests it sends in a JSON file.
A simple (requests.json) example:

```
[
  {
    "scheme": "http",
    "host": "www.example.com",
    "port": 80,
    "method": "GET",
    "path": "/",
    "delay": {
      "min": 1000,
      "max": 2000,
    },
    "keep-alive-requests": 100,
    "clients": 2,
  },
  {
    "scheme": "https",
    "tls-session-reuse": true,
    "host": "example.com",
    "port": 443,
    "method": "POST",
    "path": "/",
    "headers": {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    "body": {
      "content": "name=user&email=user@example.com",
    },
    "delay": {
      "min": 3000,
      "max": 5000,
    },
    "keep-alive-requests": 1,
    "clients": 3,
  }
]
```

A quick run with an optional output response stats file

```
$ mb -d10 -i requests.json -o responses.csv
Time: 10.05s
Sent: 1.51kiB, 153.87B/s
Recv: 21.55kiB, 2.14kiB/s
Hits: 14, 1.39/s
```


## JSON request file

The JSON request file format is

```
[
  <request 1>,
  <request 2>,
  ...
  <request n>
]
```

where the individual `<request>`s are

```
{
  "host_from": <s>,
  "host": <s>,
  "port": <n>,
  "tcp": {
    "keep-alive": {
      "enable": <b>,
      "idle": <n>,
      "intvl": <n>,
      "cnt": <n>
    }
  },
  "scheme": <s>,
  "tls-session-reuse": <b>
  "method": <s>,
  "path": <s>,
  "headers": {
    "X-Custom-Header-1": <s>,
    "X-Custom-Header-2": <s>,
    ...
    "X-Custom-Header-n": <s>
  },
  "body": {
    "content": <s>,
    "size": <n>,
    "type": <s>,
  },
  "max-requests": <n>,
  "keep-alive-requests": <n>,
  "clients": <n>,
  "delay": {
    "min": <n>,
    "max": <n>
  },
  "close": {
    "client": <b>,
    "linger": <n>
  },
  "ramp-up": <n>
}
```

* **host_from**: a host (typically an IP address) to bind the source to.
  This was implemented to work around the port exhaustion problem.
* **host**: target host
* **port**: target port
* **tcp**: TCP-related options
  * **keep-alive**:
    * **enable**: enable/disable TCP keep-alive (default false)
    * **idle**: The number of seconds a connection needs to be idle before TCP begins sending
      out keep-alive probes.  If unset or 0, system defaults are used.
    * **intvl**: The number of seconds between TCP keep-alive probes.  If unset or 0,
      system defaults are used.
    * **cnt**: The maximum number of TCP keep-alive probes to send before giving up and
      killing the connection if no response is obtained from the other end.  If unset or 0,
      system defaults are used.
* **scheme**: URL scheme (http|https)
* **tls-session-reuse**: Use TLS session reuse? (true|false)
* **method**: HTTP method (GET/HEAD/PATCH/POST/PUT...), see RFC 7231
* **path**: URL path
* **headers**: an array of custom HTTP headers
* **body**: HTTP requests body
  * **content**: Data to send in the HTTP request body when **type** is "content".  For any
    other **type**, the content is ignored.
  * **size**: Size of the PRNG body to be sent in the body of the HTTP request.  The size is
    the real size of the transferred data excluding overhead of the chunked Transfer-Encoding
    (see RFC 2616).  This field must be set for **type** "random".  For any other **type**,
    the size is ignored.
  * **type**: (content|random).  If the type is "content", **content** will be sent in the
    HTTP request.  If the type is "random", PRNG data with the period of `MAX_REQ_LEN`
    will be sent.  If the **type** is unset, "content" is assumed.
* **max-requests**: how many HTTP requests to send to **host** in total.  If the value is 0 or
  unspecified, the requests will be sent for the entire duration of the test.  If there is no more
  HTTP requests to be sent for all hosts, the test may finish earlier than specified.
* **keep-alive-requests**: how many HTTP requests to send within a single TCP connection, including
  the last "Connection: close" request.  If the value is 0 or unspecified, the
  "Connection: close" will never be sent.
* **clients**: How many TCP connections to open against the target **host**.  This simulates
  concurrent client requests as the TCP connections do not block.
* **delay**: random delay between requests in milliseconds.  The random delay is between **min**
  and **max**.
* **close**: Options in this section are *experimental*.
  * **client**: Client/Server-side close.  If the value is "false" or unspecified, "Connection: close" header will be
    sent to the target host after reaching **keep-alive-requests** requests and the target host will be expected to close
    the TCP connection first.  If the value is "true", the mb client will close the TCP connection after reaching
    **keep-alive-requests** requests.
  * **linger**: How many seconds to linger for.  Set to 0 to to cause TCP connection abort on close(), and send a RST
    to the target host.
* **ramp-up**: time in seconds to "ramp up" to the **delay** above (per-thread slow start)

Note that all of the above are *optional*, apart from the target **host**.


## CSV response file

The optional request-response output CSV file has the following format:

```
start_request(1),delay(2),status(3),written(4),read(5),method_and_url(6),thread_id(7),conn_id(8),conns(9),reqs(10),start(11),socket_writable(12),conn_est(13),tls_reuse(14),err(15)
```

* **start_request**: start of the request since the Epoch in microseconds.  For a HTTP
  keep-alive (already established) connection this is the time the socket became
  writeable, just before the request data was written to a non-blocking socket.
  For a non-established connection, this is the time we first tried to establish
  this connection, i.e. just before a non-binding socket connect() call.
* **delay**: time in microseconds it took for a full response (e.g. a complete
  chunk-encoded message) to arrive since ``start_request''.  If there was an error
  before we received the full response, the delay is the time it took to receive
  the error.
* **status**: HTTP response status when receiving a valid response (see RFC 7231).
  On a connection or HTTP parser error, the status is 0 and **err** column is set
  appropriately.
* **written**: raw request length (including headers) in bytes.
* **read**: raw response length (including headers) in bytes.  Note that this
  also includes the overhead of encoding schemes such as the chunk encoding.
* **method_and_url**: HTTP method (GET/HEAD/POST/...) and request URL.
* **thread_id**: Id of a thread responsible for handling of this request/response
  pair.
* **conn_id**: connection id (file descriptor).
* **conns**: how many times we already connected (initial connection + reconnections).
  For HTTP keep-alive connections you should see numbers higher than 1.
* **reqs**: number of HTTP requests sent over the connection since the last
  (re-)connection.
* **start**: time in microseconds (since the Epoch) we first tried to establish
  this connection.  Note that this time is equal for all HTTP keep-alive requests
  for this connection (if any).
* **socket_writable**: time in microseconds it took for the socket to become
  writeable (since **start**).  Note that this time is the same for all HTTP
  keep-alive requests within a connection.
* **conn_est**: time in microseconds it took to establish this connection (since
  **start**).  Note that this connection establishment delay is the
  same for all HTTP keep-alive requests within a connection.  Also, for plain
  HTTP requests this delay is equal to the **socket_writable**
  value.  For TLS connections, the delay is increased by the TLS handshake.
* **tls_reuse**: TLS session reused: [0|1].
* **err**: an optional error message in case of a failure


## Creating a container image with the mb client

A minimalist container image with the `mb` client can be created by one of the
following commands.

```
$ docker build -t <container_image_tag> -f containers/Dockerfile.busybox .
$ buildah bud  -t <container_image_tag> -f containers/Dockerfile.busybox .
```


## Credits

I would like to thank the following people and organisations.
In no particular order:

* Igor Sysoev and Joyent, Inc. for their work on the HTTP parser
* James McLaughlin et al. for his
  [low footprint JSON parser](https://github.com/udp/json-parser)
* Salvatore Sanfilippo for his
  [async event-driven programming library](https://github.com/aisk/libae)
* Will Glozer for his [wrk test client](https://github.com/wg/wrk)
* wolfSSL Inc. for their [Embedded SSL Library](https://www.wolfssl.com/)
