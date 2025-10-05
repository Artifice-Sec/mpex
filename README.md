# mpex

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Masscan](https://img.shields.io/badge/Requires-Masscan-orange)](https://github.com/robertdavidgraham/masscan)
[![Nmap](https://img.shields.io/badge/Optional-Nmap-lightgrey)](https://nmap.org/)

**mpex** (**Masscan Port EXtractor**) is a Python-based orchestration tool that automates fast port discovery, parsing, and post-processing in one command.

---

## 🚀 Key Features

* Runs **Masscan** under the hood and writes per-port results to `port-<port>.txt` files  
* Generates a **single `all_ips.txt`** containing all unique hosts discovered  
* Supports **rate control** (`--rate`) to balance speed vs. stealth  
* Offers **host exclusions** (`--exclude` / `--excludefile`)  
* Includes **`--auto-route`** for automatic interface and gateway MAC detection  
* Provides **live output streaming** with `--live`  
* Supports **async plugin hooks** (`--hook-cmd`) with configurable concurrency (`--hook-concurrency`)  
* Runs **aggregated Nmap** scans in formats `-oN`, `-oX`, `-oG`, or `-oA`  
* Optional **JSON summaries** (`--json-output`)  
* Optional **timestamped outputs** (`--timestamp-output`) for organized archives  

---

## 📋 Prerequisites

* **Python 3.8+**
* **Masscan** installed and in your `$PATH`
* **Nmap** *(optional)* for aggregated scans

---

## ⚙️ Installation

```bash
git clone https://github.com/Artifice-Sec/mpex.git
cd mpex
chmod +x mpex.py
