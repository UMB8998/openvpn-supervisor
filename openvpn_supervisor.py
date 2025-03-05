#!/usr/bin/env python

# MIT License
#
# Copyright (c) 2018 James Gebbie-Rayet
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

"""Blah"""

import logging
from logging.handlers import TimedRotatingFileHandler
import os
import subprocess
import time
import argparse
import fcntl
import socket
import struct

logfolder = "/var/log/openvpn-supervisor/"

parser = argparse.ArgumentParser(
                    prog='OPenVPN-Supervisor',
                    description='Restart Stale OpenVPN Connections')
parser.add_argument('--ip')
parser.add_argument('--service')
parser.add_argument('--remoteip')
args = parser.parse_args()


def loggingsetup():
    """Blah"""

    logger = logging.getLogger("openvpn-supervisor")
    logger.setLevel(logging.INFO)

    if not os.path.exists(logfolder):
        os.makedirs(logfolder)
    
    logpath = os.path.join(
        logfolder, "openvpn-supervisor.log")

    logformat = logging.Formatter(
        '%(asctime)s - %(message)s', '%Y-%m-%d %H:%M:%S')

    logformatter = TimedRotatingFileHandler(filename=logpath,when='D',interval=30,backupCount=5)
    logformatter.setFormatter(logformat)
    logger.addHandler(logformatter)

    return logger


def openvpnservicerestart():
    """Blah"""

    status = sendtoshell("service openvpn-client@" + args.service + " restart")

    return status


def sendtoshell(cmd):
    """Blah"""

    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True)

    stdout, stderr = proc.communicate()
    errcode = proc.returncode

    # Format the stdout to utf-8 for python 3.
    if not isinstance(stdout, str):

        stdout = stdout.decode("utf-8")

    # Format the stderr to utf-8 for python 3.
    if not isinstance(stdout, str):

        stderr = stderr.decode("utf-8")

    return stdout, stderr, errcode

def get_ip_linux(interface: str) -> str:
    """
    Uses the Linux SIOCGIFADDR ioctl to find the IP address associated
    with a network interface, given the name of that interface, e.g.
    "eth0". Only works on GNU/Linux distributions.
    Source: https://bit.ly/3dROGBN
    Returns:
        The IP address in quad-dotted notation of four decimal integers.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packed_iface = struct.pack('256s', interface.encode('utf_8'))
    packed_addr = fcntl.ioctl(sock.fileno(), 0x8915, packed_iface)[20:24]
    return socket.inet_ntoa(packed_addr)


def main():
    """Blah"""

    notdone = True

    logger = loggingsetup()

    currentip = get_ip_linux('tun0')

    logger.info("Starting the OpenVPN Supervisor.")
    logger.info("This simple software utility is designed to monitor the "
                "status of an OpenVPN connection and restart the OpenVPN "
                "service when the connection becomes stale.")
    logger.info("This software utility was developed by James Gebbie-Rayet "
                "and is made available under the MIT license terms.")
    logger.info("We are using ip: " + args.ip + " and service: " + args.service)
    logger.info("Current ip: " + currentip + " and supossed ip: " + args.remoteip)

    time.sleep(300)

    logger.info("Monitoring started - logs will appear at " + logfolder)

    while notdone:

        # Ping out
        status = sendtoshell("ping -c 1 -w2 " + args.ip)

        if currentip != args.remoteip:
            logger.info("VPN IP not Correct")

            status = openvpnservicerestart()

            if status[2] == 0:

                logger.info("OpenVPN has been successfully restarted.")

            else:

                notdone = False

                logger.info("ERROR - OpenVPN could not be restarted, here is "
                            "the output of stdout, stderr and the errorcode:"
                            "\n\nstdout:\n{0}\n\nstderr:{1}\n\nerrcode = {2}"
                            .format(status[0], status[1], status[2]))

                logger.info("If the error message is to do with 'permissions' "
                            "or 'access denied' then you need to make sure "
                            "that this utility is running as root.")

                time.sleep(120)          

        # If can't ping, issue restart.
        if status[2] > 0:

            logger.info("Stale VPN connection detected - restarting OpenVPN "
                        "service.")

            status = openvpnservicerestart()

            if status[2] == 0:

                logger.info("OpenVPN has been successfully restarted.")

            else:

                notdone = False

                logger.info("ERROR - OpenVPN could not be restarted, here is "
                            "the output of stdout, stderr and the errorcode:"
                            "\n\nstdout:\n{0}\n\nstderr:{1}\n\nerrcode = {2}"
                            .format(status[0], status[1], status[2]))

                logger.info("If the error message is to do with 'permissions' "
                            "or 'access denied' then you need to make sure "
                            "that this utility is running as root.")

        time.sleep(120)

    logger.info("Exiting the OpenVPN Supervisor.")
    logger.info("Goodbye for now!")

if __name__ == "__main__":

    main()
