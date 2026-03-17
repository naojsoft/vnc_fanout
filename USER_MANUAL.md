# vnc_fanout User Manual

vnc_fanout is a VNC fanout proxy (repeater) that makes a single connection
to an upstream VNC server and fans it out to multiple downstream clients.
This reduces load on the VNC server and allows using different passwords
for downstream access. It supports view-only and control connections,
Tight encoding for bandwidth reduction, TLS encryption via VeNCrypt,
and automatic upstream reconnection.

## Requirements

- Python 3.11 or later
- pycryptodome >= 3.23

## Installation

```
pip install .
```

## Quick Start

1. Copy `examples/example_config.toml` and edit it for your environment.
2. Run the proxy:

```
vnc_fanout -f my_config.toml
```

## Command-Line Options

| Option | Description |
|---|---|
| `-f FILE`, `--config FILE` | Path to the TOML configuration file (required) |
| `--pidfile FILE` | Write the process PID to FILE |

## Configuration File

The configuration file is in [TOML](https://toml.io/) format. Each VNC
session to proxy is defined as a screen section. You can define as many
screens as you need -- the proxy spawns one process per screen.

Screen sections must have names starting with `screen` (e.g., `screen1`,
`screen_lobby`, `screenA`). Each screen section has top-level options and
two sub-tables: `upstream` (the VNC server to connect to) and `downstream`
(the proxy server that clients connect to).

### Minimal Example

```toml
[screen1]

[screen1.upstream]
vnc_host = "vnc-server.example.com"
vnc_port = 5900
vnc_password = "serverpassword"

[screen1.downstream]
proxy_host = "0.0.0.0"
proxy_port = 5910
proxy_viewonly_password = "viewerpass"
```

### Multiple Screens

```toml
[screen1]
upstream_reconnect_delay = 5

[screen1.upstream]
vnc_host = "server1.example.com"
vnc_port = 5900
vnc_password = "pass1"

[screen1.downstream]
proxy_host = "0.0.0.0"
proxy_port = 5910
proxy_viewonly_password = "viewer1"

[screen2]
upstream_reconnect_delay = 10

[screen2.upstream]
vnc_host = "server2.example.com"
vnc_port = 5901
vnc_password = "pass2"

[screen2.downstream]
proxy_host = "0.0.0.0"
proxy_port = 5911
proxy_viewonly_password = "viewer2"
```

### Full Configuration Reference

#### Screen-Level Options

These go directly under the `[screenX]` section.

| Option | Type | Default | Description |
|---|---|---|---|
| `logfile` | string | _(none)_ | Path to a log file. If not set, logs go to stderr. |
| `loglevel` | integer | 30 | Python logging level. Common values: 10 = DEBUG, 20 = INFO, 30 = WARNING, 40 = ERROR. |
| `log_maxsize` | integer | 20971520 | Maximum log file size in bytes before rotation (default 20 MB). |
| `log_backups` | integer | 4 | Number of rotated log files to keep. |
| `upstream_reconnect_delay` | integer | 10 | Seconds between upstream reconnect attempts. If the upstream VNC server disconnects, the proxy will keep trying to reconnect at this interval. Set to 0 to disable reconnection (the proxy will shut down and disconnect all clients instead). |

#### Upstream Options `[screenX.upstream]`

These configure the connection to the legacy VNC server.

| Option | Type | Default | Description |
|---|---|---|---|
| `vnc_host` | string | `"localhost"` | Hostname or IP of the upstream VNC server. |
| `vnc_port` | integer | _(required)_ | Port of the upstream VNC server (e.g., 5900). |
| `vnc_password` | string | _(required)_ | Password for the upstream VNC server. If you want downstream clients to have control capability, this must be the **control** password on the upstream server (not its view-only password). |
| `vnc_tls` | boolean | `false` | Enable VeNCrypt TLS encryption for the upstream connection. The upstream server must support VeNCrypt. |
| `vnc_tls_ca` | string | _(none)_ | Path to a CA certificate file (PEM) for verifying the upstream server's certificate (X509Vnc). If omitted, the server certificate is not verified. Only relevant when `vnc_tls = true`. |

#### Downstream Options `[screenX.downstream]`

These configure the proxy server that VNC clients connect to.

| Option | Type | Default | Description |
|---|---|---|---|
| `proxy_host` | string | `"localhost"` | Interface to bind the proxy server on. Use `"0.0.0.0"` to listen on all interfaces. |
| `proxy_port` | integer | _(required)_ | Port for the proxy server. |
| `proxy_viewonly_password` | string | _(required)_ | Password for view-only downstream connections. Clients authenticating with this password can only watch the screen. |
| `proxy_control_password` | string | _(none)_ | Password for control-capable downstream connections. Clients authenticating with this password can claim control of the upstream session. See [View-Only and Control Passwords](#view-only-and-control-passwords) below. If not set, all clients are view-only. |
| `grab_key` | string | `"f1"` | The key to press with Ctrl to grab control. See [Grabbing and Releasing Control](#grabbing-and-releasing-control) for valid keys. |
| `proxy_tls_cert` | string | _(none)_ | Path to a PEM certificate file for downstream TLS (VeNCrypt). When set, clients can connect with VeNCrypt (encrypted) or plain VNC auth (unencrypted). |
| `proxy_tls_key` | string | _(none)_ | Path to the PEM private key file corresponding to `proxy_tls_cert`. |
| `proxy_tls_required` | boolean | `false` | When `true`, only VeNCrypt (encrypted) connections are accepted. Clients that do not support VeNCrypt will be unable to connect. Only effective when `proxy_tls_cert` and `proxy_tls_key` are also set. |

## View-Only and Control Passwords

vnc_fanout supports two downstream passwords with different privilege levels:

- **View-only password** (`proxy_viewonly_password`): Clients that
  authenticate with this password can see the screen but cannot send any
  keyboard or mouse input to the upstream server.

- **Control password** (`proxy_control_password`): Clients that authenticate
  with this password have the *ability* to take control of the upstream
  session. They do not automatically have control -- they must explicitly
  grab it using a key sequence (see below). When not in control, they are
  view-only just like other clients.

Only **one client** can have control at a time. This prevents conflicting
input from multiple users.

If `proxy_control_password` is not configured, all clients are view-only
regardless of what password they use.

**Important**: For control to work, the upstream VNC server password
(`vnc_password`) must be set to the upstream server's **control** password,
not its view-only password. If the proxy connects to the upstream server
with a view-only password, input forwarding will be silently ignored by the
upstream server.

## Grabbing and Releasing Control

### Grabbing Control

To take control of the upstream session, press **Ctrl + grab key** in
your VNC viewer. The default grab key is **F1**, so the default sequence is
**Ctrl+F1**.

When you grab control:
- Your keyboard and mouse events are forwarded to the upstream VNC server.
- Any other client that previously held control loses it.
- A message is logged indicating which client grabbed control.

Only clients that authenticated with the control password can grab control.
If a view-only client presses Ctrl+F1, nothing happens.

### Releasing Control

To voluntarily release control, press **Ctrl+Escape**. After releasing:
- Your events are no longer forwarded upstream.
- No client has control until someone grabs it again.
- You remain connected as a view-only viewer.

If you do not currently have control, Ctrl+Escape does nothing.

### Stealing Control

If another control-capable client presses the grab sequence while you hold
control, they take it from you. There is no confirmation -- the new client
immediately becomes the controller. This allows operators to hand off
control without coordination.

### Valid Grab Keys

The grab key can be changed with the `grab_key` option. Valid values:

`delete`, `end`, `escape`, `f1`, `f2`, `f3`, `f4`, `f5`, `f6`, `f7`,
`f8`, `f9`, `f10`, `f11`, `f12`, `home`, `insert`, `pause`,
`scroll_lock`, `space`, `tab`

## Downstream TLS Encryption (VeNCrypt)

vnc_fanout can encrypt connections from downstream VNC clients using the
VeNCrypt extension. When enabled, clients that support VeNCrypt (such as
TigerVNC) will negotiate TLS encryption. By default, clients that do not
support VeNCrypt can still connect using plain (unencrypted) VNC
authentication. This can be disabled with `proxy_tls_required`.

### Generating a Self-Signed Certificate

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=vnc_fanout"
```

### Enabling Downstream TLS

```toml
[screen1.downstream]
proxy_tls_cert = "/path/to/cert.pem"
proxy_tls_key = "/path/to/key.pem"
```

With this configuration, the proxy offers both VeNCrypt (encrypted) and
plain VNC auth (unencrypted). Clients that support VeNCrypt will use TLS;
clients that don't will connect without encryption.

### Requiring TLS

To reject unencrypted connections entirely, add:

```toml
[screen1.downstream]
proxy_tls_cert = "/path/to/cert.pem"
proxy_tls_key = "/path/to/key.pem"
proxy_tls_required = true
```

When `proxy_tls_required` is set, the proxy only offers VeNCrypt as a
security type. Clients that do not support VeNCrypt will be unable to
connect. This is useful in environments where all traffic must be
encrypted.

### VeNCrypt Sub-Types

The proxy offers two VeNCrypt sub-types:

- **TLSVnc (258)**: Anonymous Diffie-Hellman key exchange (no certificate
  verification). Works without client configuration.
- **X509Vnc (261)**: Certificate-based TLS. The client may prompt to
  verify the server certificate.

After the TLS handshake, VNC authentication proceeds as normal over the
encrypted channel.

## Upstream TLS Encryption (VeNCrypt)

If the upstream VNC server supports VeNCrypt, the proxy can encrypt its
connection to the server.

```toml
[screen1.upstream]
vnc_tls = true
# optional: verify the server certificate
# vnc_tls_ca = "/path/to/ca.pem"
```

When `vnc_tls = true`, the proxy will select VeNCrypt if offered by the
upstream server. It prefers X509Vnc (certificate-based) when available and
falls back to TLSVnc (anonymous DH). If `vnc_tls_ca` is set, the upstream
server's certificate is verified against the provided CA; otherwise
certificate verification is skipped.

If the upstream server does not offer VeNCrypt, or `vnc_tls` is false, the
proxy falls back to plain VNC authentication.

## Upstream Reconnection

If the upstream VNC server disconnects, the proxy automatically attempts to
reconnect every `upstream_reconnect_delay` seconds (default: 10). During
reconnection:

- Downstream clients remain connected but receive no screen updates.
- Once the upstream connection is re-established, all clients receive a
  full screen refresh.

Set `upstream_reconnect_delay = 0` to disable reconnection. In this mode,
if the upstream server disconnects, all downstream clients are disconnected
and the proxy process for that screen terminates.

## Logging

By default, each screen process logs to stderr. To log to a file:

```toml
[screen1]
logfile = "vnc_fanout_screen1.log"
loglevel = 10
```

Log files are automatically rotated when they reach `log_maxsize` bytes
(default 20 MB), keeping `log_backups` old files (default 4).

### Log Level Reference

| Level | Value | Description |
|---|---|---|
| DEBUG | 10 | Detailed protocol messages, encoding info, client state |
| INFO | 20 | Client connect/disconnect, upstream status, control grabs |
| WARNING | 30 | Unexpected conditions that don't prevent operation |
| ERROR | 40 | Exceptions and failures |

For production use, `loglevel = 20` (INFO) is recommended. For
troubleshooting connection or protocol issues, use `loglevel = 10` (DEBUG).

## Limitations

- The upstream connection uses RAW encoding only. The proxy negotiates RAW
  with the upstream server regardless of what encodings it offers
  downstream.
- Downstream clients are offered Tight encoding (for clients that support
  it) or RAW. Other encodings (Hextile, ZRLE, etc.) are not supported.
- Authentication uses VNC authentication (challenge-response with DES).
  Other authentication schemes are not supported.
- The proxy operates at the RFB 3.8 protocol level.
