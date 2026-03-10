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

Install
=======
$ pip install .

Usage
=====
$ vnc_fanout -f examples/example_config.toml

See the example config file for the format and options

Limitations
===========
*** MANY ***

- the program only currently supports RAW and Tight encoding
- simple VNCAuth authentication
