# masscan-port-extractor

A lightweight Python wrapper for [Masscan](https://github.com/robertdavidgraham/masscan) that automates TCP port scanning, excludes your local host from results, and cleanly extracts per-port host lists for further processing.

---

## 🚀 Features

- **Single or bulk target input**: Accepts a CIDR range or a file containing arbitrary IPs/networks.
- **Port list support**: Scan individual ports, comma-separated lists, or ranges (e.g. `80,443,1000-1100`).
- **Rate control**: Fine-tune packet-per-second (`--max-rate`) for speed vs. stealth.
- **Open-only filter**: Only emit hosts with open ports.
- **Local IP exclusion**: Automatically detects and excludes your own machine’s IP addresses (including loopback).
- **Per-port outputs**: Generates one file per port (e.g. `port-80`) listing only the remote IP addresses where that port is open.
- **Minimal dependencies**: Pure Python 3 script calling Masscan—no extra libraries.

---

## 📋 Requirements

- Python 3.6+
- [Masscan](https://github.com/robertdavidgraham/masscan) installed and in your `$PATH`

---

## ⚙️ Installation

1. Clone or download this repository:

   ```bash
   git clone https://github.com/youruser/masscan-port-extractor.git
   cd masscan-port-extractor
   ```

2. Ensure Python 3 is available:

   ```bash
   python3 --version
   ```

3. Make the script executable (optional):

   ```bash
   chmod +x masscan-port-extractor.py
   ```

---

## 🏃‍♂️ Usage

```bash
usage: masscan-port-extractor.py [-h] (--cidr CIDR | --input-file INPUT_FILE)\                                  
                                 --ports PORTS [--rate RATE]
                                 [--output-dir OUTPUT_DIR] [--open-only]

masscan-port-extractor: scan targets and write per-port IP lists

required arguments:
  --cidr CIDR            CIDR range to scan (e.g. 192.168.0.0/24)
  --input-file INPUT_FILE
                         File containing targets, one per line
  --ports PORTS          Comma-separated ports or ranges (e.g. 22,80,8000-8100)

optional arguments:
  --rate RATE            Packets-per-second rate (default: 1000)
  --output-dir OUTPUT_DIR
                         Directory for per-port output files (default: .)
  --open-only            Only show open ports (adds Masscan `--open` flag)
  -h, --help             show this help message and exit
```

### Examples

- **Scan a /24 for HTTP and HTTPS**:
  ```bash
  python3 masscan-port-extractor.py --cidr 10.0.0.0/24 --ports 80,443 --rate 1000
  ```
  Produces files `port-80` and `port-443` in the current directory, excluding your local IP.

- **Scan from a host list file and save to `results/`**:
  ```bash
  python3 masscan-port-extractor.py --input-file hosts.txt --ports 22 --rate 1000 --output-dir results
  ```
  Creates `results/port-22` with all SSH-enabled hosts, excluding your own machine.

- **Only list open ports**:
  ```bash
  python3 masscan-port-extractor.py --cidr 192.168.1.0/24 --ports 3389,445 --open-only
  ```

---

## 📂 Output

For each unique port scanned, you’ll find a file named:

```
port-<port_number>
```

Each file contains one remote IP address per line, sorted, deduplicated, and your local IPs excluded.

---

## 🔧 Troubleshooting

- **`masscan: command not found`**: Ensure Masscan is installed (`brew install masscan` on macOS, or compile from source).
- **Permission errors**: Masscan may require elevated privileges to send raw packets. Try:
  ```bash
  sudo python3 masscan-port-extractor.py ...
  ```
- **Tool includes your own IP**: If you still see your machine’s IP, double-check your network interfaces or add static exclusions.
- **High false positives**: Lower the `--rate` or combine with `--open-only` to filter likely open ports.

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Open a Pull Request

Please keep style consistent, run `flake8` or `pylint` to lint, and update this `README.md` when adding features.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE). Feel free to copy, modify, and redistribute.

---

*Happy scanning!*
