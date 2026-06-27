# api.py
import warnings
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, sr1, send, conf
import socket

# Suppress Scapy warnings
warnings.filterwarnings("ignore", module="scapy")
conf.verb = 0

app = FastAPI()

# Allow our frontend to communicate with this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target_ip: str
    port_range: str
    threads: int = 50


def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"


def check_port(target_ip, port):
    try:
        packet = IP(dst=target_ip) / TCP(dport=port, flags='S')
        response = sr1(packet, timeout=1, verbose=False)

        if response is None:
            return port, "Filtered/Closed"
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                # Send RST to close half-open connection
                send(IP(dst=target_ip) / TCP(dport=port, flags='R'), verbose=False)
                return port, "Open"
        return port, "Closed"
    except Exception as e:
        return port, "Error"


@app.post("/scan")
def run_scan(req: ScanRequest):
    try:
        start_port, end_port = map(int, req.port_range.split('-'))
        ports_to_scan = range(start_port, end_port + 1)
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Invalid port format. Use start-end (e.g., 1-1024)")

    # materialise before executor consumes it
    ports_list = list(ports_to_scan)
    open_ports = []
    closed_filtered = 0

    with ThreadPoolExecutor(max_workers=req.threads) as executor:
        results = executor.map(lambda p: check_port(
            req.target_ip, p), ports_list)

        for port, status in results:
            if status == "Open":
                open_ports.append({
                    "port": port,
                    "service": get_service_name(port)
                })
            else:
                closed_filtered += 1

    open_ports.sort(key=lambda x: x["port"])   # return in ascending port order

    return {
        "target": req.target_ip,
        "total_scanned": len(ports_list),
        "open_ports": open_ports,
        "closed_filtered": closed_filtered
    }
