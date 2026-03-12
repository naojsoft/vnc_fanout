About
=====
This is a VNC fanout script that makes a connection to an "upstream" actual
VNC (RFB) server and fans that single connection out to multiple "downstream"
clients.  The goal is to reduce the load on the VNC server by making only a
single view-only TCP connection to the actual VNC server.  An additional
benefit is that a different VNC password can be used for the fanout.

License
=======
BSD Zero Clause License

Features and Limitations
========================
- Fans out *one* (upstream) VNC server connection to many (downstream) clients
- Supports RAW and Tight encoding
- Supports 24 and 32 bpp
- Can have a different password for upstream and downstream connections
- Supports view only and control passwords
- With control connections, control is given to one of the control clients
  at a time; to gain control, press the special key sequence (default is
  Ctrl-F1, can be configured).
- Can be configured to reconnect to upstream VNC while maintaining downsteam
  connections if the upstream VNC server is shut down (only recovers if
  restarted with the same geometry/depth/encoding though)
- Supports only simple VNCAuth authentication

Install
=======
$ pip install .

Usage
=====
$ vnc_fanout -f examples/example_config.toml

See the example config file for the format and options.

