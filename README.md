# mpex

**mpex** (Masscan Port EXtractor) is a Python-based orchestration tool that automates fast port discovery, parsing, and post-processing in one command. It:

* Runs **Masscan** under the hood and writes per-port results to `port-<port>` files.
* Supports **rate control** (`--rate`) to balance speed vs. stealth.
* Offers **host exclusions** via `--exclude` and `--excludefile`.
* Includes **`--auto-route`**: automatically detect your default network interface and gateway MAC, and apply them to Masscan (`--interface`/`--router-mac`).
* Provides **live feedback** (`--live`) showing Masscan output and parsing progress.
* Supports **plugin hooks** (`--hook-cmd`) to trigger any command per `{ip}`/`{port}` (e.g., curl, Nikto, email alerts).
* Can run an **aggregated Nmap** scan on all discoveries in formats `-oN`, `-oX`, `-oG`, `-oS`, or `-oA` via `--nmap-output`/`--nmap-format`.

---

## 📋 Prerequisites

* **Python 3.6+**
* **Masscan** installed and in your `$PATH`
* **Nmap** (optional, for aggregated scans)

---

## ⚙️ Installation

```bash
git clone https://github.com/Artifice-Sec/mpex.git
cd mpex
chmod +x mpex.py    # optional
```

---

## 🏃‍♂️ Usage

```bash
python3 mpex.py [TARGET] --ports PORTS [OPTIONS]
```

### Target Specification (choose one)

* `--ip 192.168.0.117`
* `--cidr 192.168.0.0/24`
* `--input-file hosts.txt`

### Core Options

| Option             | Description                                      |
| ------------------ | ------------------------------------------------ |
| `--ports PORTS`    | Ports or ranges (e.g., `22,80,443,8000-8100`)    |
| `--rate RATE`      | Packets per second (default: `1000`)             |
| `--output-dir DIR` | Directory for `port-<port>` files (default: `.`) |

### Routing Options

| Option              | Description                                                 |
| ------------------- | ----------------------------------------------------------- |
| `--auto-route`      | Detect & apply default interface and gateway MAC to Masscan |
| `--interface IFACE` | Manually specify network interface (e.g. `eth0`, `tun0`)    |
| `--router-mac MAC`  | Manually specify gateway MAC (e.g. `00:11:22:33:44:55`)     |

### Exclusion Controls

| Option               | Description                                   |
| -------------------- | --------------------------------------------- |
| `--exclude LIST`     | Comma-separated IPs/CIDRs to skip             |
| `--excludefile FILE` | File listing IPs/CIDRs to skip (one per line) |

### Live & Plugin Hooks

| Option           | Description                                          |
| ---------------- | ---------------------------------------------------- |
| `--live`         | Stream Masscan output and show parsing progress      |
| `--hook-cmd CMD` | Run a command per discovery; use `{ip}` and `{port}` |

### Aggregated Nmap Integration

| Option               | Description                                                                        |
| -------------------- | ---------------------------------------------------------------------------------- |
| `--nmap-output NAME` | Base name for aggregated Nmap output files                                         |
| `--nmap-format FMT`  | Format: `N` (normal), `X` (XML), `G` (grepable), `S` (script), `A` (all via `-oA`) |

---

## 🔧 Examples

1. **Scan a /24 with auto-route & exclusions**

```bash
python3 mpex.py --cidr 192.168.0.0/24 --ports 80,443,22 --rate 2000 --auto-route --exclude 192.168.0.1
```

2. **Single-host live scan**

```bash
python3 mpex.py --ip 192.168.0.117 --ports 445 --rate 2000 --live
```

3. **Banner grabs & Nikto hooks**

```bash
python3 mpex.py --cidr 10.0.0.0/24 --ports 80 --rate 2000 --hook-cmd "curl http://{ip}:{port}" --hook-cmd "nikto -h http://{ip}:{port}"
```

4. **Email alerts on SSH discovery**

```bash
python3 mpex.py --cidr 10.0.0.0/24 --ports 22 --rate 2000 --hook-cmd "echo 'SSH open on {ip}' | mail -s 'SSH Alert' you@domain.com"
```

5. **Aggregated Nmap (all formats)**

```bash
python3 mpex.py --input-file hosts.txt --ports 22,80,443 --rate 2000 --nmap-output fullscan --nmap-format A
```

---

## 🛠️ Troubleshooting

* **Masscan not found**: Install or add to `$PATH`.
* **Permission denied**: Run with `sudo` or use a writable `--output-dir`.
* **Nmap missing**: Required for `--nmap-output`.
* **Auto-route fails**: Verify `ip route` and `ip neigh` on your system.

---

## 🤝 Contributing & License

Fork, file issues, or submit PRs! Licensed under MIT. See [LICENSE](LICENSE) for details.

---

*© 2025 Artifice Security*
