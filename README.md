# 🔍 Advanced Network Scanner - Ultimate Edition v2.0

A comprehensive, multi-platform Python script designed for **network discovery** and **security assessment**. This tool helps identify active devices on a local network, gather detailed information about them (MAC address, vendor, hostname, OS guess), perform port scanning, and generate a detailed security report.

**Disclaimer:** This tool is intended for **Educational Lab Use Only**. Always ensure you have explicit permission from the network owner before running any network scanning tools. Unauthorized scanning may be illegal or violate network policies.

## ✨ Features

The Advanced Network Scanner provides a robust set of features for network analysis:

*   **Host Discovery:** Uses enhanced ping techniques to identify online hosts.
*   **Detailed Host Information:** Resolves hostname, MAC address, and performs vendor lookup based on the MAC OUI.
*   **OS Guessing:** Attempts to guess the operating system (Windows/Linux/Unix) based on TTL values.
*   **Multi-threaded Port Scanning:** Supports quick (common ports) and full (0-1024) port scans using concurrent execution for speed.
*   **Service Banner Grabbing:** Fetches service banners and version information for open ports (e.g., HTTP, SSH, FTP).
*   **Security Assessment:** Calculates a basic security score for each device based on open high-risk and medium-risk ports.
*   **Reporting:** Exports scan results to:
    *   Formatted console output (using `tabulate`).
    *   JSON file (`network_scan_results.json`).
    *   CSV file (`network_scan_results.csv`).
    *   Comprehensive, styled HTML Security Report (`network_security_report.html`).

## ⚙️ Prerequisites

To run this script, you need:

*   **Python 3.x**
*   The `tabulate` library for formatted console output.

## 🚀 Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ROHITCRAFTSYT/Advanced-Network-Scanner.git
    cd Advanced-Network-Scanner
    ```

2.  **Install dependencies:**
    ```bash
    pip3 install -r requirements.txt
    ```

    *Note: The script uses standard Python libraries like `socket`, `ipaddress`, `subprocess`, and `concurrent.futures` for core functionality.*

## 💻 Usage

The script must be run with administrative privileges for the best results, especially for accurate MAC address resolution and ARP table manipulation.

### Running the Scanner

```bash
python3 network_scanner.py
```

The script will present an interactive menu with four scan options:

| Option | Name | Description | Scan Ports | Quick Scan |
| :---: | :--- | :--- | :---: | :---: |
| **1** | Quick Scan | Hostname, MAC, Vendor only. | No | Yes |
| **2** | Deep Scan | **Recommended.** Adds common port and service scanning. | Yes | Yes |
| **3** | Full Scan | **Thorough.** Scans all ports (0-1024) and performs comprehensive security assessment. | Yes | No |
| **4** | Custom Range | Allows specifying a custom network range (e.g., `192.168.1.0/24`). | Optional | Optional |

### Example Output

The console output will display a summary table and a detailed security risk summary for devices with a score less than 100.

### Exporting Results

After the scan, you will be prompted to export the results to JSON, CSV, and the HTML Security Report.

## 🛠️ Technical Details

The script is designed to be cross-platform, using `subprocess` calls for platform-specific commands like `ping`, `arp`, `ipconfig`, and `ifconfig`.

*   **Concurrency:** Uses `concurrent.futures.ThreadPoolExecutor` to speed up the network and port scanning process.
*   **Risk Assessment:** Ports are categorized into HIGH, MEDIUM, and LOW risk based on common security practices.
*   **HTML Report:** The `export_to_html` function generates a single, self-contained HTML file with a modern, responsive design for easy viewing and sharing of the security assessment.

## 🤝 Contributing

Contributions are welcome! If you have suggestions for new features, bug fixes, or vendor OUI updates, please feel free to open an issue or submit a pull request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
