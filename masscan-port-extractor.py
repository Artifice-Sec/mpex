#!/usr/bin/env python3
"""
masscan-port-extractor.py: A Python wrapper around Masscan to scan targets, exclude hosts, live-status, plugin hooks, and flexible aggregated Nmap output.

Usage examples:
  python masscan-port-extractor.py --cidr 192.168.0.0/24 --ports 80,443 --rate 1000 \
      --exclude 192.168.0.1 --nmap-output webscan --nmap-format A
  python masscan-port-extractor.py --ip 192.168.0.117 --ports 445 --rate 1000 --live
  python masscan-port-extractor.py --input-file targets.txt --ports 22,80 --rate 2000 \
      --excludefile skip.txt --hook-cmd "echo Found {port} on {ip}" \
      --nmap-output fullscan --nmap-format G
"""
import argparse
import subprocess
import re
import os
import sys
import socket
import ipaddress

def parse_args():
    parser = argparse.ArgumentParser(
        description="masscan-port-extractor: scan targets, exclude hosts, live output, plugin hooks, and flexible aggregated Nmap"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cidr", help="CIDR range to scan, e.g. 192.168.0.0/24")
    group.add_argument("--input-file", help="File containing targets (one per line)")
    group.add_argument("--ip", help="Single IP address to scan, e.g. 192.168.0.117")
    parser.add_argument("--ports", required=True,
                        help="Comma-separated list of ports or port ranges, e.g. 80,443,1000-1100")
    parser.add_argument("--rate", type=int, default=1000,
                        help="Max packets per second (masscan --max-rate), default=1000")
    parser.add_argument("--output-dir", default=".",
                        help="Directory to save per-port outputs and hooks")
    parser.add_argument("--exclude",
                        help="Comma-separated list of IPs or CIDRs to exclude from scan/output")
    parser.add_argument("--excludefile",
                        help="File containing IPs/CIDRs (one per line) to exclude from scan/output")
    parser.add_argument("--live", action="store_true",
                        help="Show live processing status during scan and parse")
    parser.add_argument("--hook-cmd", action="append",
                        help="Simple per-result command; use {ip} and {port} placeholders")
    parser.add_argument("--nmap-output",
                        help="Base name for aggregated Nmap output (prefix for files)")
    parser.add_argument("--nmap-format", choices=["N","X","G","S","A"], default="X",
                        help="Nmap output format: N=normal (-oN), X=xml (-oX), G=grepable (-oG), S=script (-oS), A=all (-oA), default=X")
    return parser.parse_args()

def run_masscan(args):
    cmd = ["masscan", "-p", args.ports]
    if args.input_file:
        cmd += ["-iL", args.input_file]
    elif args.ip:
        cmd.append(args.ip)
    else:
        cmd.append(args.cidr)
    cmd += ["--max-rate", str(args.rate)]
    if args.exclude:
        cmd += ["--exclude", args.exclude]
    if args.excludefile:
        cmd += ["--excludefile", args.excludefile]

    if args.live:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        except OSError as e:
            print(f"[ERROR] execution error: {e}", file=sys.stderr)
            sys.exit(1)
        print("[LIVE] Scanning... streaming results")
        lines = []
        for raw_line in proc.stdout:
            line = raw_line.rstrip()
            print(line)
            lines.append(line)
        proc.wait()
        if proc.returncode != 0:
            err = proc.stderr.read()
            print(f"[ERROR] masscan failed: {err}", file=sys.stderr)
            sys.exit(1)
        return lines
    else:
        try:
            proc = subprocess.run(cmd, capture_output=True,
                                  text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] masscan failed: {e}\n{e.stderr}", file=sys.stderr)
            sys.exit(1)
        except OSError as e:
            print(f"[ERROR] execution error: {e}", file=sys.stderr)
            sys.exit(1)
        return proc.stdout.splitlines()

def parse_and_write(args, lines):
    exclude_nets = [ipaddress.ip_network('127.0.0.1/32')]
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            exclude_nets.append(ipaddress.ip_network(f"{ip}/32"))
    except Exception:
        pass
    if args.exclude:
        for net in args.exclude.split(','):
            exclude_nets.append(ipaddress.ip_network(net))
    if args.excludefile:
        with open(args.excludefile) as ef:
            for line in ef:
                net=line.strip()
                if net:
                    exclude_nets.append(ipaddress.ip_network(net))

    pattern = re.compile(r"Discovered open port (\d+)/\w+ on ([0-9\.]+)")
    ports_map = {}
    total = len(lines)
    for idx, line in enumerate(lines, start=1):
        if args.live:
            print(f"Processing {idx}/{total} lines...", end="\r", flush=True)
        m = pattern.search(line)
        if not m:
            continue
        port, ip_str = m.group(1), m.group(2)
        ip_addr = ipaddress.ip_address(ip_str)
        if any(ip_addr in net for net in exclude_nets):
            continue
        ports_map.setdefault(port, set()).add(ip_str)
    if args.live:
        print()

    os.makedirs(args.output_dir, exist_ok=True)
    all_ips = set()
    for port, ips in ports_map.items():
        out_file = os.path.join(args.output_dir, f"port-{port}")
        with open(out_file, 'w') as f:
            for ip in sorted(ips):
                f.write(ip + "\n")
                all_ips.add(ip)
        print(f"[+] Wrote {len(ips)} addresses to {out_file}")
        if args.hook_cmd:
            for ip in sorted(ips):
                for tmpl in args.hook_cmd:
                    cmd = tmpl.format(ip=ip, port=port)
                    try:
                        subprocess.run(cmd, shell=True, check=True)
                    except subprocess.CalledProcessError:
                        print(f"[!] Hook failed: {cmd}")

    # Aggregated Nmap
    if args.nmap_output and all_ips:
        ip_list_file = os.path.join(args.output_dir, "_all_ips.txt")
        with open(ip_list_file, 'w') as f:
            for ip in sorted(all_ips):
                f.write(ip + "\n")
        # Build Nmap command with chosen format
        if args.nmap_format == 'A':
            nmap_cmd = f"nmap -p {args.ports} -iL {ip_list_file} -oA {args.nmap_output}"
        else:
            nmap_cmd = f"nmap -p {args.ports} -iL {ip_list_file} -o{args.nmap_format} {args.nmap_output}.{args.nmap_format.lower()}"
        print(f"[+] Running aggregated Nmap: {nmap_cmd}")
        try:
            subprocess.run(nmap_cmd, shell=True, check=True)
            print(f"[+] Aggregated Nmap output saved")
        except subprocess.CalledProcessError:
            print(f"[!] Aggregated Nmap failed: {nmap_cmd}")
        finally:
            os.remove(ip_list_file)

if __name__ == '__main__':
    args = parse_args()
    print(f"[INFO] Running scan: ports={args.ports}, rate={args.rate}")
    lines = run_masscan(args)
    if args.live:
        print(f"[INFO] Parsing {len(lines)} results...")
    else:
        print("[INFO] Parsing output...")
    parse_and_write(args, lines)
    print("[DONE] Completed masscan-port-extractor workflow.")
