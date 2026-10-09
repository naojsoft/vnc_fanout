#
# main.py -- entry point for vnc_fanout
#
"""
This is a VNC fanout script that makes a connection to an "upstream" actual
VNC (RFB) server and fans that single connection out to multiple "downstream"
clients.  The goal is to reduce the load on the VNC server by making only a
single view-only TCP connection to the actual VNC server.  An additional
benefit is that a different VNC password can be used for the fanout, thus
adding a modicum of security.

Usage
=====
$ vnc_fanout -f examples/example_config.toml

$ vnc_fanout --help

to see options.

Starts a VNC fanout for each screen defined in the configuration file.
See examples/example_config.toml for details of the config file format.

Limitations
===========
*** MANY ***; the program only currently supports RAW encoding and simple
VNCAuth authentication
"""
# stdlib imports
import sys
import os
import asyncio
import logging
import logging.handlers
from argparse import ArgumentParser
import tomllib
import multiprocessing as mp

# Local
from vnc_fanout.proxy import VNCProxy

# needed on Linux, so that we get a new event loop for each child
mp.set_start_method('spawn', force=True)

LOG_FORMAT = '%(asctime)s | %(levelname)1.1s | %(filename)s:%(lineno)d (%(funcName)s) | %(message)s'  # noqa

# max size of log file before rotating
LOG_MAXSIZE = 20 * 1024 * 1024
LOG_BACKUPS = 4


def run_proxy(scr_d):
    # Runs a VNC fanout proxy whose configuration is defined in the dict
    # ``scr_d``.

    name = scr_d['name']
    # Create logger.
    logfile = scr_d.get('logfile', None)
    loglevel = scr_d.get('loglevel', logging.WARNING)
    log_maxsize = scr_d.get('log_maxsize', LOG_MAXSIZE)
    log_backups = scr_d.get('log_backups', LOG_BACKUPS)

    logger = logging.Logger(f'vnc_fanout_{name}')
    fmt = logging.Formatter(LOG_FORMAT)

    if logfile is not None:
        fileHdlr = logging.handlers.RotatingFileHandler(logfile,
                                                        maxBytes=log_maxsize,
                                                        backupCount=log_backups)
        fileHdlr.setLevel(loglevel)
        fileHdlr.setFormatter(fmt)
        logger.addHandler(fileHdlr)

    else:
        stderrHdlr = logging.StreamHandler()
        stderrHdlr.setLevel(loglevel)
        stderrHdlr.setFormatter(fmt)
        logger.addHandler(stderrHdlr)

    upstream_host = scr_d['upstream'].get('vnc_host', "localhost")
    upstream_port = scr_d['upstream'].get('vnc_port', None)
    upstream_password = scr_d['upstream'].get('vnc_password', None)
    upstream_tls = scr_d['upstream'].get('vnc_tls', False)
    upstream_tls_ca = scr_d['upstream'].get('vnc_tls_ca', None)

    downstream_host = scr_d['downstream'].get('proxy_host', "localhost")
    downstream_port = scr_d['downstream'].get('proxy_port', None)
    downstream_viewonly_password = scr_d['downstream'].get('proxy_viewonly_password', None)
    downstream_control_password = scr_d['downstream'].get(
        'proxy_control_password', None)

    reconnect_delay = scr_d.get('upstream_reconnect_delay', 10)
    grab_key = scr_d['downstream'].get('grab_key', 'f1')
    downstream_tls_cert = scr_d['downstream'].get('proxy_tls_cert', None)
    downstream_tls_key = scr_d['downstream'].get('proxy_tls_key', None)
    downstream_tls_required = scr_d['downstream'].get('proxy_tls_required', False)
    client_write_timeout = scr_d['downstream'].get('client_write_timeout',
                                                   10.0)
    send_queues = scr_d['downstream'].get('send_queues', False)

    try:
        logger.info(f"starting {name} VNC fanout proxy...")
        asyncio.run(VNCProxy(logger,
                             upstream_host,
                             upstream_port,
                             upstream_password,
                             downstream_host,
                             downstream_port,
                             downstream_viewonly_password,
                             downstream_control_password=downstream_control_password,
                             reconnect_delay=reconnect_delay,
                             grab_key=grab_key,
                             downstream_tls_cert=downstream_tls_cert,
                             downstream_tls_key=downstream_tls_key,
                             downstream_tls_required=downstream_tls_required,
                             upstream_tls=upstream_tls,
                             upstream_tls_ca=upstream_tls_ca,
                             client_write_timeout=client_write_timeout,
                             send_queues=send_queues).start())

    except Exception as e:
        logger.error(f"exception in {name} VNC fanout proxy: {e}",
                     exc_info=True)

    logger.info("terminating VNC fanout proxy...")
    return name


def main():

    argprs = ArgumentParser(description="VNC view-only repeater")

    argprs.add_argument("-f", "--config", dest="config_file", metavar="FILE",
                        default=None,
                        help="Specify FILE as configuration file")
    argprs.add_argument("--pidfile", dest="pidfile", metavar="FILE",
                        default=None, help="Write pid of process to FILE")
    argprs.add_argument("--send-queues", dest="send_queues",
                        action="store_true", default=False,
                        help="Use per-client send queues for all screens "
                        "(overrides send_queues in the config file)")

    (options, args) = argprs.parse_known_args(sys.argv[1:])
    if len(args) != 0:
        argprs.error("incorrect number of arguments")

    if options.config_file is None:
        argprs.error("Please specify a configuration file with -f")

    # Read configuration file
    print("reading configuration file...")
    with open(options.config_file, 'rb') as cfg_f:
        cfg_d = tomllib.load(cfg_f)

    print("starting fanouts")
    cfgs = []
    for key in cfg_d:
        if not key.startswith('screen'):
            continue
        scr_d = cfg_d[key]
        if 'name' not in scr_d:
            scr_d['name'] = key
        if options.send_queues:
            scr_d.setdefault('downstream', {})['send_queues'] = True
        cfgs.append(scr_d)

    if options.pidfile is not None:
        # user specified a path to a pid file
        with open(options.pidfile, 'w') as pid_f:
            pid_f.write("{}\n".format(os.getpid()))

    try:
        num = len(cfgs)
        with mp.Pool(num) as pool:
            print(list(pool.map(run_proxy, cfgs)))

    except KeyboardInterrupt:
        print("Closed by keyboard interrupt...")


if __name__ == "__main__":
    main()
