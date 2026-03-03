About
=====
This is a VNC fanout script that makes a connection to an "upstream" actual
VNC (RFB) server and fans that single connection out to multiple "downstream"
clients.  The goal is to reduce the load on the VNC server by making only a
single view-only TCP connection to the actual VNC server.  An additional
benefit is that a different VNC password can be used for the fanout, thus
adding a modicum of security.

License
=======
BSD Zero Clause License

Install
=======
$ pip install .

Usage
=====
$ vnc_fanout [options]

Options
=======

--vnchost : the actual hostname of the running VNC server (defaults to
  "localhost")

--vncport : the port number of the running VNC server (no default);
  e.g. 5905

--vncpass-file : a text file containing a clear text view only password

--host : the interface name that the fanout proxy should use for clients
  to connect to (defaults to "localhost"); e.g. "0.0.0.0"

--port : the port number that the fanout proxy should use for clients to
  connect to (no default); e.g. 5910

--pass-file : a text file containing a clear text view only password that
  clients should use to connect to the proxy

Limitations
===========
*** MANY ***

- the program only currently supports RAW encoding, 32 bit pixels
- simple VNCAuth authentication
