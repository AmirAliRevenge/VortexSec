<p align="center">
  <img src="https://github.com/user-attachments/assets/e51471dc-33ff-4b4e-8936-ec1d0e5814fb" alt="VortexSec Logo" width="150"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.1-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.8%2B-brightgreen?style=for-the-badge" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Mac-lightgrey?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

VortexSec is an advanced, Python-based APT (Advanced Persistent Threat) Framework designed for authorized penetration testing. It features a high-performance asynchronous port scanner, a vulnerability analysis engine, OS fingerprinting, and a devastating DDoS module—now fully integrated into a professional graphical user interface.

---

## 🚀 Features

### 🖥️ Professional GUI (v1.0.1 New!)
- **VS Code-Inspired Interface:** Sleek dark mode built with PyQt6.
- **Integrated Terminal:** Built-in AuraScript terminal inside the app (`Ctrl+``).
- **Syntax Highlighting:** Custom highlighting for scan results and vulnerabilities.
- **Search Functionality (`Ctrl+F`):** Quickly find IPs, ports, or CVEs.
- **Auto-Save Database:** Scan results and target configurations are saved automatically using SQLite.
- **Theme Engine:** Switch between VS Code Dark, Monokai, and Light Mode.

### 🛡️ Reconnaissance & Exploitation
- **Asynchronous Port Scanning:** Ultra-fast scanning using `asyncio` with configurable concurrency.
- **OS Fingerprinting:** Passive OS detection based on open ports and service banners.
- **Vulnerability Engine:** Automated detection of CVEs and insecure services (e.g., VSFTPD 2.3.4 Backdoor, OpenSSH User Enumeration).
- **Security Assessment:** Automatic risk rating (Critical, High, Medium, Low).

### ⚔️ DDoS Attack Engine
- **Multi-Core UDP Flood:** Utilizes 2x CPU cores for maximum network throughput.
- **Live Dashboard:** Real-time statistics (PPS, Bandwidth, CPU Usage, Time Left).
- **Stop Button:** Safely terminate an ongoing attack at any time.

---

## 📸 Screenshots

<details>
<summary>Click to view the new GUI</summary>

<img width="1280" height="719" alt="VortexSec GUI" src="https://github.com/user-attachments/assets/34b13981-58e5-41f7-a79a-8400041b77dc" />
</details>

---

## 📥 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip

### 1. Clone the Repository
```bash
git clone https://github.com/AmirAliRevenge/VortexSec.git
cd VortexSec
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run VortexSec
**To run the new GUI IDE:**
```bash
python ide.py
```
**To run the CLI version:**
```bash
python vortex.py
```

---

## 🎮 Usage (GUI)

1. **Set Target:** Enter the target IP or Domain in the sidebar.
2. **Scan Profile:** Choose Quick, Standard, or Full scan.
3. **Launch Scan:** Click `▶ Run` or press `Ctrl+R`.
4. **Analyze:** View open ports, OS info, and vulnerabilities in the output panel.
5. **Attack (Authorized Only):** Set the DDoS duration and click `⚔️ Launch DDoS`.

---

## ⚠️ Disclaimer

This tool is provided for **educational purposes and authorized penetration testing only**. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Always ensure you have explicit permission before scanning or attacking any target.

---

<p align="center">
  Built with ❤️ and ☕ by <a href="https://github.com/AmirAliRevenge">AmirAli</a>
</p>
