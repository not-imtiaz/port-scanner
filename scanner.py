import argparse
import logging
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, sr1, send, conf
import warnings
warnings.filterwarnings("ignore", module="scapy")

# Suppress Scapy's verbose console output and IPv6 warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0


def check_port(target_ip, port):
    """
    Sends a SYN packet to the target IP/Port and analyzes the response.
    Returns a tuple: (port, status)
    """
    try:
        # Craft the SYN packet
        packet = IP(dst=target_ip) / TCP(dport=port, flags='S')

        # Send packet and wait for a single response (timeout prevents hanging)
        response = sr1(packet, timeout=1, verbose=False)

        # No response usually means a firewall dropped the packet (Filtered)
        if response is None:
            return port, "Filtered/Closed"

        # Check if we got a TCP response
        elif response.haslayer(TCP):
            # 0x12 indicates both SYN and ACK flags are set
            if response.getlayer(TCP).flags == 0x12:
                # Polite scanning: Send a RST packet to tear down the half-open connection
                rst_packet = IP(dst=target_ip) / TCP(dport=port, flags='R')
                send(rst_packet, verbose=False)
                return port, "Open"

        # If we get a RST-ACK (0x14), the port is explicitly closed
        return port, "Closed"

    except Exception as e:
        return port, f"Error: {str(e)}"


def main():
    # Setup command-line arguments
    parser = argparse.ArgumentParser(
        description="Multi-threaded TCP SYN Port Scanner")
    parser.add_argument(
        "target", help="The target IP address (e.g., 192.168.1.10)")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range to scan (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of concurrent threads (default: 100)")
    args = parser.parse_args()

    target_ip = args.target

    # Parse the port range (e.g., "20-80")
    try:
        start_port, end_port = map(int, args.ports.split('-'))
        ports_to_scan = range(start_port, end_port + 1)
    except ValueError:
        print("[-] Invalid port format. Please use start-end (e.g., 1-1024).")
        return

    print(
        f"[*] Starting SYN scan on {target_ip} for ports {start_port}-{end_port} with {args.threads} threads...")

    open_ports = []

    # Initialize the thread pool
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Map our check_port function to the list of ports
        results = executor.map(
            lambda p: check_port(target_ip, p), ports_to_scan)

        # Process the results as they complete
        for port, status in results:
            if status == "Open":
                open_ports.append(port)
                print(f"[+] Port {port} is OPEN")

    print(f"[*] Scan complete. Found {len(open_ports)} open ports.")


if __name__ == "__main__":
    main()
