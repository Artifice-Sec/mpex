# mpex

`mpex` is a Python wrapper around Masscan that automates fast port discovery, parsing, and post processing in one command. It can detect your default route on Linux, supports host exclusions, streams live Masscan output, runs per-discovery hooks, writes per-port files, and can run an aggregated Nmap scan on discoveries. It also produces a single `all_ips.txt` file that lists every unique IP discovered, without ports.

## TL;DR

- Run Masscan sweeps and get per-port files plus one aggregated IP list.
- Run commands per discovery with hooks.
- Optionally run an aggregated Nmap scan on discoveries.

## Features

- Run Masscan with rate control (`--rate`).
- Auto-detect interface and gateway MAC on Linux (`--auto-route`).
- Skip hosts or networks with `--exclude` or `--excludefile`.
- Live parsing mode to stream Masscan output (`--live`).
- Async hook execution with concurrency control (`--hook-cmd`, `--hook-concurrency`).
- Per-port files: `port-<port>.txt`.
- Aggregated unique IP list: `all_ips.txt`.
- Optional timestamped outputs (`--timestamp-output`) and JSON summary (`--json-output`).
- Optional aggregated Nmap run (`--nmap-output`, `--nmap-format`).

## Requirements

- Python 3.8 or newer
- Masscan installed and on your `PATH`
- Nmap only if you want aggregated Nmap output
- Linux for `--auto-route` (the script uses `ip route` and `ip neigh`)

## Install

    git clone https://github.com/Artifice-Sec/mpex.git
    cd mpex
    chmod +x mpex.py

Run the script with Python:

    python3 mpex.py --cidr 192.168.0.0/24 --ports 80,443

## Usage examples

Scan a /24 using auto-route detection:

    sudo python3 mpex.py \
      --cidr 192.168.0.0/24 \
      --ports 80,443,22 \
      --auto-route \
      --rate 2000

Scan hosts from a file:

    python3 mpex.py --input-file hosts.txt --ports 22,80 --rate 1500

Live streaming with hooks (echo example):

    python3 mpex.py \
      --cidr 192.168.0.0/24 \
      --ports 80 \
      --live \
      --hook-cmd "echo OPEN {ip}:{port} >> hooks.log" \
      --hook-concurrency 20 \
      --output-dir out

Per-port files plus a single all-IPs file:

    python3 mpex.py --cidr 192.168.0.0/24 --ports 22,80 --output-dir out
    # output: out/port-22.txt, out/port-80.txt, out/all_ips.txt

Aggregated Nmap run (requires nmap):

    python3 mpex.py \
      --input-file hosts.txt \
      --ports 22,80,443 \
      --nmap-output fullscan \
      --nmap-format A \
      --output-dir out
    # result: fullscan.nmap fullscan.xml fullscan.gnmap

Save JSON summary too:

    python3 mpex.py --cidr 192.168.0.0/24 --ports 80 --json-output --output-dir out
    # result: out/results.json

## CLI options (common)

Run `python3 mpex.py -h` for full help. Most used flags:

- `--cidr` : CIDR to scan. Choose one of `--cidr`, `--input-file`, or `--ip`.
- `--input-file` : newline-separated list of targets.
- `--ip` : scan a single IP.
- `--ports` : comma-separated ports and ranges, e.g. `22,80,8000-8100`.
- `--rate` : masscan `--max-rate` value.
- `--auto-route` : detect interface and gateway MAC automatically on Linux.
- `--interface` : set interface manually.
- `--router-mac` : set router MAC manually.
- `--exclude` : comma-separated IPs or CIDRs to skip.
- `--excludefile` : file listing IPs or CIDRs to skip, one per line. this is your skip.txt equivalent.
- `--live` : stream masscan output and show parsing progress.
- `--hook-cmd` : shell template run for each discovery. use `{ip}` and `{port}` placeholders.
- `--hook-concurrency` : maximum concurrent hook processes. default 20.
- `--nmap-output` : base name for aggregated nmap outputs.
- `--nmap-format` : N, X, G, S, or A (A uses `-oA`).
- `--timestamp-output` : append a UTC timestamp to output filenames.
- `--json-output` : write `results.json` with ports and lists of IPs.

## Exclusion file (skip.txt)

Your exclusion file is what you would call `skip.txt` or `exclude.txt`. It contains IPs or CIDRs to omit. Example:

    192.168.0.1/32
    192.168.0.20/32
    10.0.0.0/8

Behavior notes:

- The script reads that file and adds those networks to the internal exclusion list used when writing outputs.
- The same file is passed to Masscan with `--excludefile` so Masscan will attempt to avoid those addresses during the scan.
- Exclusions apply both during scanning and when the script parses Masscan output, so excluded IPs will not appear in `port-*.txt` or `all_ips.txt`.

## Hooks safety and usage

- Hook templates run via the shell. The script quotes `{ip}` and `{port}` when inserting values, which reduces injection risk for those fields. The hook command itself runs under a shell, so only use trusted hook templates.
- Hook execution is async and limited by `--hook-concurrency`. You can increase or decrease that value depending on system load.
- Hook logs are written to `output_dir` as `hook-<sanitized-cmd>.log`. Long command strings are sanitized and truncated. If you need unique file names for repeated commands, add a short hash suffix.

Example hooks:

- Simple echo:

      --hook-cmd "echo 'HTTP open at {ip}:{port}' >> http-open.log"

- Nikto scan for HTTP port hits:

      --hook-cmd "nikto -h http://{ip}:{port} -o nikto-{ip}-{port}.txt"

- Curl banner grab:

      --hook-cmd "curl -m 3 -s http://{ip}:{port} | head -n 10 > curl-{ip}-{port}.txt"

## Output files and naming

- Per-port: `port-<port>.txt` (one IP per line). If `--timestamp-output` is set the file name will be `port-<port>-YYYYMMDDThhmmss.txt`.
- Aggregated unique IP list: `all_ips.txt` or `all_ips-YYYYMMDDThhmmss.txt` if timestamping. This file contains only unique IP addresses with no ports.
- Optional JSON: `results.json` or `results-YYYYMMDDThhmmss.json`.
- Hook logs: `hook-<sanitized-cmd>.log`.
- Temporary file for Nmap: `_all_ips.txt` is created while Nmap runs and then removed.

All files go under the `--output-dir` you set.

## Troubleshooting

- `masscan binary not found` : install masscan and ensure it is on `PATH`.
- `nmap binary not found` : install nmap when using `--nmap-output`.
- Auto-route works on Linux only. If `--auto-route` fails, use `--interface` and `--router-mac` manually.
- Hook failures do not stop the main run. Hook output goes to hook log files in `output-dir`.
- If you want to preserve every run, enable `--timestamp-output` or move outputs to an archive folder between runs.

## Security notes

- Hooks run in the shell. Only use trusted hook templates or change to a non-shell execution mode if you need strict safety.
- Validate and sanitize hook templates if you allow other people to run the script.
- Running Masscan at high rates can disrupt network equipment. Set `--rate` responsibly and get permission before scanning networks you do not own.

## Contributing

Open a PR or file an issue. If you add features, include unit tests for parsing logic and the hook runner.

## License

MIT. See LICENSE file.

## Contact

Jason Zaffuto  
Artifice Security  
jason@artificesecurity.com
