#!/usr/bin/python

import os
import sys

if os.getuid() !=0:
    print 
    quit()

"""
ERROR: This script requires root privileges. 
       Use 'sudo' to run it.
"""

from scapy.all import *

try:
    ip_dst = sys.argv[1]
except:
    ip_dst = "10.0.0.2"

try:
    iface = sys.argv[2]
except:
    iface="enp4s0f1"

print("Sending IP packet to", ip_dst)
p = (Ether(src="AA:AA:AA:BB:BB:BB", dst="FF:FF:FF:FF:FF:FF")/
     IP(src="10.0.0.1", dst=ip_dst)/
     UDP(sport=7,dport=5001)/
     "This is a test")
print(p.show())
sendp(p, iface=iface)