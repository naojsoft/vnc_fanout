About
=====
This is a VNC fanout script that makes a connection to an "upstream" actual
VNC (RFB) server and fans that single connection out to multiple "downstream"
clients.  The goal is to reduce the load on the VNC server by making only a
single TCP connection to the actual VNC server.  An additional benefit is
that different client passwords can be used for the fanout than to the actual
server.


License
=======
BSD Zero Clause License


Features and Limitations
========================
- Fans out *one* (upstream) VNC server connection to many (downstream) clients
- Supports RAW and Tight encoding
- Supports 24 and 32 bpp
- Supports optional TLSVnc and X509Vnc encryption for both upstream and
  downstream
- Can have a different password for upstream and downstream connections
- Supports view only and control passwords
- With control connections, control is given to one of the control clients
  at a time; to gain control, press the special key sequence (default is
  Ctrl-F1, can be configured).
- Can be configured to reconnect to upstream VNC while maintaining downsteam
  connections if the upstream VNC server is shut down (only recovers if
  restarted with the same geometry/depth/encoding though)
- Supports only simple VNCAuth authentication

Encryption
----------
- Both TLSVnc (258) and X509Vnc (261) are offered.
  TLSVnc works with self-signed certs without client-side CA trust.
  X509Vnc allows clients to verify the cert.
- Generate your own self-signed cert:
  $ openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
      -days 365 -nodes -subj "/CN=vnc_fanout"

  Then add to your config:
  proxy_tls_cert = "cert.pem"
  proxy_tls_key = "key.pem"


Installation
============
$ pip install .


Usage
=====
$ vnc_fanout -f examples/example_config.toml

See the example config file for the format and options.


More Documentation
==================
See the [User Manual](USER_MANUAL.md)
