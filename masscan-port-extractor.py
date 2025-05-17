#!/usr/bin/env python3
"""
masscan-port-extractor.py: A Python wrapper around Masscan to scan targets and output per-port IP lists.

Usage examples:
  python masscan-port-extractor.py --cidr 192.168.0.0/24 --ports 80,443 --rate 1000
  python masscan-port-extractor.py --input-file targets.txt --ports 22,80,8080 --rate 5000 --output-dir results
"""
import argparse
import subprocess
import re
import os
import sys

# TODO: Consider adding a check for masscan binary availability before proceeding
def parse_args():
    parser = argparse.ArgumentParser(
        description="masscan-port-extractor: scan targets and write per-port IP lists"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cidr", help="CIDR range to scan, e.g. 192.168.0.0/24")
    group.add_argument("--input-file", help="File containing targets (one per line)")
    parser.add_argument(
        "--ports", required=True,
        help="Comma-separated list of ports or port ranges, e.g. 80,443,8000-8100"
    )
    parser.add_argument(
        "--rate", type=int, default=1000,
        help="Max packets per second (masscan --max-rate), default=1000"
    )
    parser.add_argument(
        "--output-dir", default=".",
        help="Directory to save per-port output files"
    )
    parser.add_argument(
        "--open-only", action="store_true",
        help="Only show open ports (adds --open flag to masscan)"
    )
    # TODO: Validate port format/ranges here to catch user errors early
    return parser.parse_args()

# Consider adding timeout to prevent subprocess from hanging indefinitely
def run_masscan(cidr, input_file, ports, rate, open_only):
    cmd = ["masscan", "-p", ports]
    if input_file:
        cmd += ["-iL", input_file]
    else:
        cmd.append(cidr)
    cmd += ["--max-rate", str(rate)]
    if open_only:
        cmd.append("--open")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True
            # , timeout=300
        )
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] masscan failed: {e}\n{e.stderr}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[ERROR] failed to execute masscan: {e}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.splitlines()


def parse_and_write(lines, output_dir):
    # TODO: Consider using JSON/NDJSON output for more robust parsing instead of regex
    pattern = re.compile(r"Discovered open port (\d+)/\w+ on ([0-9\.]+)")
    ports_map = {}
    for line in lines:
        m = pattern.search(line)
        if not m:
            continue
        port = m.group(1)
        ip = m.group(2)
        ports_map.setdefault(port, set()).add(ip)
    os.makedirs(output_dir, exist_ok=True)
    for port, ips in ports_map.items():
        filename = os.path.join(output_dir, f"port-{port}")
        with open(filename, 'w') as f:
            for ip in sorted(ips):
                f.write(ip + "\n")
        print(f"[+] Wrote {len(ips)} addresses to {filename}")

if __name__ == '__main__':
    args = parse_args()
    print(f"[INFO] Running masscan-port-extractor with ports {args.ports} at rate {args.rate}...")
    lines = run_masscan(args.cidr, args.input_file, args.ports, args.rate, args.open_only)
    print(f"[INFO] Parsing output and writing per-port IP lists...")
    parse_and_write(lines, args.output_dir)
    print("[DONE] Clustered per-port IP lists written to output directory.")
