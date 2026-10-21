#!/usr/bin/env python3

# MIT License
#
# Copyright (c) 2018 James Gebbie-Rayet
# Modifications (c) 2026 ExtraIoT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Restart an OpenVPN client whose tunnel has gone stale.

Every --interval seconds the supervisor checks two things:
  * the tunnel interface (--interface, default tun0) exists and, when
    --remoteip is given, carries that address;
  * --ip (normally the VPN server or another host on the VPN) answers a ping.

A wrong/missing tunnel address triggers an immediate restart. Ping failures
must happen --failures times in a row (default 2) before a restart, so one
lost packet does not drop a working tunnel. A failed restart is logged and
retried on the next cycle; the supervisor never exits on its own.
"""

import argparse
import fcntl
import logging
import os
import socket
import struct
import subprocess
import sys
import time
from logging.handlers import TimedRotatingFileHandler

LOGFOLDER = "/var/log/openvpn-supervisor/"


def parse_args():
    parser = argparse.ArgumentParser(
        prog="openvpn-supervisor",
        description="Restart stale OpenVPN client connections")
    parser.add_argument("--ip", required=True,
                        help="address to ping through the tunnel")
    parser.add_argument("--service", required=True,
                        help="openvpn-client@<service> instance name")
    parser.add_argument("--remoteip", default=None,
                        help="expected tunnel address (optional)")
    parser.add_argument("--interface", default="tun0")
    parser.add_argument("--interval", type=int, default=120,
                        help="seconds between checks")
    parser.add_argument("--startup-delay", type=int, default=300,
                        help="seconds to wait before the first check")
    parser.add_argument("--failures", type=int, default=2,
                        help="consecutive ping failures before a restart")
    parser.add_argument("--settle", type=int, default=30,
                        help="seconds to wait after a restart before checking again")
    return parser.parse_args()


def logging_setup():
    logger = logging.getLogger("openvpn-supervisor")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s - %(message)s", "%Y-%m-%d %H:%M:%S")

    # Always log to stdout so systemd's journal has the history.
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(stream)

    try:
        os.makedirs(LOGFOLDER, exist_ok=True)
        filelog = TimedRotatingFileHandler(
            filename=os.path.join(LOGFOLDER, "openvpn-supervisor.log"),
            when="D", interval=30, backupCount=5)
        filelog.setFormatter(fmt)
        logger.addHandler(filelog)
    except OSError as err:  # e.g. read-only or full /var/log
        logger.warning("File logging disabled: %s", err)

    return logger


def sendtoshell(cmd):
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          shell=False, check=False)
    return (proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
            proc.returncode)


def get_ip_linux(interface):
    """Return the IPv4 address of interface, or None if it has none."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed_iface = struct.pack("256s", interface.encode("utf_8")[:15])
        packed_addr = fcntl.ioctl(sock.fileno(), 0x8915, packed_iface)[20:24]
        return socket.inet_ntoa(packed_addr)
    except OSError:
        return None
    finally:
        sock.close()


def ping(address):
    return sendtoshell(["ping", "-c", "1", "-w", "2", address])[2] == 0


def restart_openvpn(service, logger):
    out, err, code = sendtoshell(
        ["systemctl", "restart", "openvpn-client@" + service])
    if code == 0:
        logger.info("OpenVPN has been successfully restarted.")
    else:
        logger.info("ERROR - OpenVPN could not be restarted (code %s): %s %s",
                    code, out.strip(), err.strip())
    return code == 0


def main():
    args = parse_args()
    logger = logging_setup()

    logger.info("Starting the OpenVPN Supervisor (service %s, ping %s, "
                "interface %s, expected ip %s).", args.service, args.ip,
                args.interface, args.remoteip or "any")
    time.sleep(args.startup_delay)
    logger.info("Monitoring started.")

    failures = 0
    while True:
        reason = None
        current = get_ip_linux(args.interface)

        if current is None:
            reason = "%s has no IPv4 address" % args.interface
        elif args.remoteip and current != args.remoteip:
            reason = "VPN IP not correct: %s, expected %s" % (current, args.remoteip)
        elif ping(args.ip):
            failures = 0
        else:
            failures += 1
            logger.info("Ping to %s failed (%d/%d).", args.ip, failures, args.failures)
            if failures >= args.failures:
                reason = "Stale VPN connection detected"

        if reason:
            logger.info("%s - restarting OpenVPN service.", reason)
            restart_openvpn(args.service, logger)
            failures = 0
            time.sleep(args.settle)

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
