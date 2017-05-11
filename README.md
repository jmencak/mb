# mb: Multiple-host HTTP(s) Benchmarking tool

## Usage

    $ mb -h

mb expects specification of the requests it sends in a JSON file.
A simple (requests.json) example:

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
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "body": "name=user&email=user@example.com",
        "delay": {
          "min": 3000,
          "max": 5000,
        },
        "keep-alive-requests": 1,
        "clients": 3,
      }
    ]

A quick run with an optional output response stats file

    $ mb -d10 -i requests.json -o responses.csv
    Duration [s]: 10.09
    Total hits: 15
    Req/s: 1.49


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
