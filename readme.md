Examples
Scan ports 1 to 1024 on 192.168.1.1 using 50 threads:

Bash
sudo python scanner.py 192.168.1.1 -p 1-1024 -t 50
Note: If using a Conda environment with sudo on Linux/macOS, remember to use the absolute path to your Conda Python executable to avoid environment path resets (e.g., sudo /path/to/conda/bin/python scanner.py ...).

Disclaimer and Ethical Use
For educational and authorized testing purposes only. Port scanning can be interpreted as a malicious activity by network administrators and Intrusion Detection Systems (IDS). Never run this tool against networks, IP addresses, or systems you do not own or do not have explicit, written permission to test. The authors are not responsible for any damage or legal issues caused by the misuse of this tool.
