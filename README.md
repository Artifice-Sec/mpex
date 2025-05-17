# mpex

**mpex** (Masscan Port EXtractor) is a Python-based orchestration tool that automates Masscan scans against single hosts, CIDR ranges, or bulk target lists. It runs Masscan under the hood, parses its output into per-port IP files, supports live streaming feedback, custom host exclusions, and plugin hooks for any downstream command (curl, Nikto, custom scripts, etc.).

For deeper analysis, it can perform one aggregated Nmap run in your choice of formats (normal, XML, grepable, script, or all). By consolidating scanning, parsing, and post-processing into a single command, **mpex** dramatically reduces manual effort and accelerates large-scale network-discovery workflows.

---

## 🚀 Key Features

- **Flexible Targeting**: Scan a single IP (`--ip`), entire CIDR ranges (`--cidr`), or bulk lists (`--input-file`).
- **Port Specification**: Accept individual ports, comma-separated lists, and ranges (e.g., `80,443,1000-1100`).
- **Automated Masscan Execution**: Runs Masscan under the hood to discover open ports.
- **Per-Port Output Files**: Automatically writes each port’s IPs to separate files named `port-<port>`.
- **Rate Control**: Adjust scan speed via `--rate` (packets per second).
- **Host Exclusions**: Skip localhost, your own interfaces, inline CIDRs (`--exclude`), or file-based exclusions (`--excludefile`).
- **Live Feedback**: Stream Masscan output in real time and display parsing progress (`--live`).
- **Plugin Hooks**: Trigger any tool or script per discovery using `{ip}` and `{port}` placeholders. Examples:
  - `curl http://{ip}:{port}` – simple banner grabs
  - `nikto -h http://{ip}:{port}` – web vulnerability scans
  - `echo "Found {port} on {ip}" | mail -s "Port Alert" you@domain.com` – notifications
  - `./custom-script.sh {ip} {port}` – custom integrations
- **Aggregated Nmap Scans**: Perform a single Nmap run on all discovered hosts using `--nmap-output` and choose from multiple formats (`--nmap-format`: N, X, G, S, or A).

---

## 📋 Prerequisites

- **Python**: 3.6 or later
- **Masscan**: Installed and available in your `$PATH`
- **Nmap**: For aggregated scanning (optional)

---

## ⚙️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/youruser/mpex.git
   cd mpex
   ```

2. **Verify dependencies**
   ```bash
   python3 --version  # should be >= 3.6
   masscan --version  # for Masscan integration
   nmap --version     # optional, for Nmap integration
   ```

3. **Make the script executable** (optional)
   ```bash
   chmod +x mpex.py
   ```

---

## 🏃‍♂️ Usage

```bash
python3 mpex.py [TARGET] --ports PORTS [OPTIONS]
```

### Target Specification (choose one):
| Option               | Description                   |
|----------------------|-------------------------------|
| `--ip <IP>`          | Single host                   |
| `--cidr <CIDR>`      | CIDR network                  |
| `--input-file FILE`  | File with one IP/CIDR per line|

### Core Options:
| Option               | Description                                        |
|----------------------|----------------------------------------------------|
| `--ports PORTS`      | Ports/ranges (e.g., `22,80,443,8000-8100`)         |
| `--rate RATE`        | Packets per second (default: `1000`)               |
| `--output-dir DIR`   | Directory for outputs and hook results             |

### Exclusion Controls:
| Option               | Description                                        |
|----------------------|----------------------------------------------------|
| `--exclude LIST`     | Comma-separated IPs/CIDRs to skip                  |
| `--excludefile FILE` | File listing IPs/CIDRs to skip                     |

### Live Mode & Hooks:
| Option               | Description                                                   |
|----------------------|---------------------------------------------------------------|
| `--live`             | Stream Masscan output and show parsing progress               |
| `--hook-cmd CMD`     | Run any command per discovery; use `{ip}` and `{port}` (repeatable) |

### Aggregated Nmap Integration:
| Option               | Description                                                              |
|----------------------|--------------------------------------------------------------------------|
| `--nmap-output NAME` | Base name for aggregated Nmap outputs                                    |
| `--nmap-format FMT`  | Format: N=normal, X=XML, G=grepable, S=script, A=all (default: X)        |

---

## 📂 Output Structure

- **Per-port lists**: `port-<port>` files, one IP per line.
- **Aggregated Nmap**: Files named `NAME.<ext>` (or `NAME.*` for `-oA`) based on chosen format.

---

## 🔧 Examples

1. **Scan a /24 and exclude gateway**
   ```bash
   python3 mpex.py \
     --cidr 192.168.0.0/24 \
     --ports 80,443,22 \
     --exclude 192.168.0.1
   ```

2. **Stream live results with parsing feedback**
   ```bash
   python3 mpex.py \
     --ip 192.168.0.117 \
     --ports 445 \
     --live
   ```

3. **Banner grabs and vulnerability scans**
   ```bash
   python3 mpex.py \
     --cidr 10.0.0.0/24 \
     --ports 80 \
     --hook-cmd "curl http://{ip}:{port}" \
     --hook-cmd "nikto -h http://{ip}:{port}"
   ```

4. **Send notifications on discovery**
   ```bash
   python3 mpex.py \
     --cidr 10.0.0.0/24 \
     --ports 22 \
     --hook-cmd "echo 'SSH open on {ip}' | mail -s 'SSH Alert' you@domain.com"
   ```

5. **Aggregated Nmap `all` formats**
   ```bash
   python3 mpex.py \
     --input-file hosts.txt \
     --ports 22,80,443 \
     --nmap-output fullscan \
     --nmap-format A
   ```

---

## 🛠️ Troubleshooting

- **Masscan not found**: Ensure installation or add to `PATH`.
- **Permission denied**: Use `sudo` for raw packet scanning.
- **Nmap missing**: Install if using `--nmap-output`.
- **Packet loss**: Reduce `--rate` on congested networks.

---

## 🤝 Contributing & License

Contributions welcome! Fork, branch, and submit pull requests. See [LICENSE](LICENSE) for MIT terms.

---

*© 2025 Artifice Security – Streamline your port-scanning workflow.*
