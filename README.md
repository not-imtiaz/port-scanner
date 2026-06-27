# SYN Scanner

A small TCP SYN port scanner with both a command-line interface and a browser-based dashboard.

## What’s Included

- `scanner.py` for terminal-based scans
- `api.py` for a FastAPI backend that exposes `/scan`
- `index.html` for a browser UI that talks to the API
- `requirements.txt` for Python dependencies

## Features

- Multi-threaded SYN scanning with Scapy
- Port range input such as `1-1024`
- Service name lookup for common open ports
- Web UI with live results and a summary chart
- CORS-enabled API so the HTML frontend can call the backend locally

## Requirements

- Python 3.10+ recommended
- Linux/macOS with raw packet privileges
- `pip` for installing dependencies
- `sudo` for the CLI scanner on most systems, since SYN scanning requires elevated privileges

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the Command-Line Scanner

```bash
sudo python scanner.py 192.168.1.10 -p 1-1024 -t 100
```

Arguments:

- `target`: target IP address
- `-p, --ports`: port range in `start-end` format
- `-t, --threads`: number of worker threads

Example:

```bash
sudo python scanner.py 192.168.1.10 -p 20-80 -t 50
```

## Run the Web UI

Start the API server first:

```bash
uvicorn api:app --host 127.0.0.1 --port 8000 --reload
```

Then open `index.html` in your browser.

The page sends requests to:

```text
POST http://127.0.0.1:8000/scan
```

If you move the backend to a different host or port, update the URL in `index.html`.

## API

### `POST /scan`

Request body:

```json
{
  "target_ip": "127.0.0.1",
  "port_range": "1-1024",
  "threads": 50
}
```

Response example:

```json
{
  "target": "127.0.0.1",
  "total_scanned": 1024,
  "open_ports": [
    { "port": 22, "service": "ssh" }
  ],
  "closed_filtered": 1023
}
```

## Project Structure

```text
api.py
index.html
LICENSE
README.md
readme.md
requirements.txt
scanner.py
```

## Notes

- The web UI is intended to be used with the local FastAPI backend running on port `8000`.
- The scanner uses raw packets and may require administrator privileges.
- Results can vary depending on the target host, firewall rules, and network filtering.

## Disclaimer

Use this tool only on systems and networks you own or are explicitly authorized to test. Unauthorized port scanning can violate policy or law and may trigger intrusion detection systems.
