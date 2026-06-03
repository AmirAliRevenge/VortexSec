# 🌪️ VortexSec - Advanced Async Pentest Framework

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?logo=python)
![Asyncio](https://img.shields.io/badge/Async-Asyncio-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

VortexSec is a high-performance, modular penetration testing framework built with Python's Asyncio architecture. It rapidly scans target networks, identifies open ports, intelligently grabs service banners, and cross-references them against a vulnerability database.

> ⚠️ **Disclaimer:** This tool is strictly for authorized penetration testing and educational purposes. Unauthorized scanning of networks is illegal. Always obtain proper permission before scanning any target.

## ✨ Key Features
- ⚡ **Async Engine:** Utilizes `asyncio` and `Semaphores` for lightning-fast scanning of thousands of ports.
- 🕵️‍♂️ **Smart Banner Grabbing:** Sends protocol-aware payloads (e.g., HTTP GET for port 80) to extract accurate service versions.
- 🧠 **OS Fingerprinting:** Passive detection of target Operating System (Windows/Linux/Ubuntu) based on service headers.
- 💀 **Vulnerability Engine:** Matches extracted banners against a signature database with **CVE IDs**.
- 🛡️ **Security Assessment:** Calculates overall target security level (Critical, High, Medium, Low, Secure).
- 🎯 **Interactive TUI:** Beautiful terminal user interface with progress bars and colorful tables using `Rich`.
- 📂 **Export Reports:** Option to save scan results in structured JSON format for further analysis.
- ⚙️ **Scan Profiles:** Choose between Quick Scan (Top ports), Standard Scan (1-1024), or Full Scan (All 65535 ports).

## 📋 Prerequisites
- **Python 3.7 or higher** installed on your system. (Download from [python.org](https://www.python.org/downloads/))
- **pip** (Python package installer) usually comes pre-installed with Python.

> 💡 **How to check your Python version?** Open your terminal and type:
> ```bash
> python --version
> ```

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/AmirAliRevenge/VortexSec.git
   ```
2. Navigate to the project directory:
   ```bash
   cd VortexSec
   ```
3. Install the required dependency:
   ```bash
   pip install rich
   ```

## 🚀 Usage

Run the framework:
```bash
python vortex.py
```
*(If `python` doesn't work on Windows, try `py vortex.py`)*

The interactive menu will guide you through:
1. Entering Target IP or Domain
2. Selecting Scan Profile (Quick, Standard, Full)
3. Viewing Open Ports, OS Info, and Vulnerabilities
4. Exporting the report to JSON

## 📸 Screenshot
<img width="1500" height="832" alt="screenshot" src="https://github.com/user-attachments/assets/773154a6-31dd-4cd2-b334-331ef382d4d3" />
