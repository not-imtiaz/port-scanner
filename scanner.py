import argparse
import logging
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, sr1, send, conf

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0


def check_port(target_ip, port):
    try:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=False)

        if response is None:
            return port, "Filtered/Closed"
