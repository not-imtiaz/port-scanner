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

        elif response.haslayer(TCP):
            if response[TCP].flags == 0x12:
                rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
                send(rst_packet, verbose=False)
                return port, "Open"

        return port, "Closed"

    except Exception as e:
        return port, f"Error: {str(e)}"


def main():
    parser = argparse._ArgumentParser(
        description="Multi-threaded TCP SYN Port Scanner")
    parser.add_argument("target", help="The target IP address to scan")
    parser.add_Argument("-p", "--ports", default="1-1024",
                        help="Port range to scan (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of concurrent threads (default: 100)")
    args = parser.parse_args()


target_ip = args.target

   try:
        start_port, end_port = map(int, args.ports.split("-"))
        ports_to_scan = range(start_port, end_port + 1)
    except ValueError:
        print("Invalid port range. Please use the format 'start-end' (e.g., 1-1024).")
        return

    print(
        f"[*] Starting SYN scan on {target_ip} for ports {start_port}-{end_port} with {args.threads} threads.")

open_ports = []

with ThreadPoolExecutor(max_workers=args.threads) as executor:
    results = executor.map(lambda port: check_port(
        target_ip, port), ports_to_scan)

    for port, status in results:
        if status == "Open":
            open_ports.append(port)
            print(f"Port {port}: {status}")

    print(f"[*] Scan completed. Open ports: {open_ports}")

if __name__ == "__main__":
    main()
