#!/usr/bin/env python3
"""
mpex.py: A Python wrapper around Masscan to scan targets, exclude hosts, live-status, plugin hooks, and flexible aggregated Nmap outputs.

Usage examples:
  python mpex.py --cidr 192.168.0.0/24 --ports 80,443 --rate 1000 --exclude 192.168.0.1
  python mpex.py --input-file targets.txt --ports 22,80 --rate 5000 \
      --excludefile skip.txt --live --hook-cmd "nmap -p {port} -oX nmap_{port}_{ip}.xml {ip}"  
  python mpex.py --ip 192.168.0.117 --ports 445 --rate 1000  
  python mpex.py --cidr 192.168.0.0/24 --ports 22,80,443 --rate 1000 --nmap-output allscan --nmap-format A
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
        description="mpex: orchestrate Masscan scans with exclusions, live feedback, hooks, and aggregated Nmap"
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
                        help="Directory to save outputs and hook results")
    parser.add_argument("--exclude",
                        help="Comma-separated list of IPs or CIDRs to skip")
    parser.add_argument("--excludefile",
                        help="File containing IPs/CIDRs to skip, one per line")
    parser.add_argument("--live", action="store_true",
                        help="Stream Masscan output and show parsing progress")
    parser.add_argument("--hook-cmd", action="append",
                        help="Command to run per result; use {ip} and {port} placeholders")
    parser.add_argument("--nmap-output",
                        help="Base name for aggregated Nmap outputs")
    parser.add_argument("--nmap-format", choices=["N","X","G","S","A"], default="X",
                        help="Output format: N=normal, X=xml, G=grepable, S=script, A=all (default: X)")
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
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        print("[LIVE] Scanning... streaming results")
        lines = []
        for raw in proc.stdout:
            line = raw.rstrip()
            print(line)
            lines.append(line)
        proc.wait()
        if proc.returncode != 0:
            err = proc.stderr.read()
            print(f"[ERROR] Masscan failed: {err}", file=sys.stderr)
            sys.exit(1)
        return lines
    else:
        try:
            proc = subprocess.run(cmd, capture_output=True,
                                  text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Masscan failed: {e}\n{e.stderr}", file=sys.stderr)
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
                net = line.strip()
                if net:
                    exclude_nets.append(ipaddress.ip_network(net))

    pattern = re.compile(r"Discovered open port (\d+)/\w+ on ([0-9\.]+)")
    ports_map = {}
    total = len(lines)
    for idx, line in enumerate(lines, start=1):
        if args.live:
            print(f"Processing {idx}/{total}...", end="\r", flush=True)
        m = pattern.search(line)
        if not m:
            continue
        port, ip = m.group(1), m.group(2)
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in exclude_nets):
            continue
        ports_map.setdefault(port, set()).add(ip)
    if args.live:
        print()

    os.makedirs(args.output_dir, exist_ok=True)
    all_ips = set()
    for port, ips in ports_map.items():
        fname = os.path.join(args.output_dir, f"port-{port}")
        with open(fname, 'w') as f:
            for ip in sorted(ips):
                f.write(ip + "\n")
                all_ips.add(ip)
        print(f"[+] Wrote {len(ips)} IPs to {fname}")
        if args.hook_cmd:
            for ip in sorted(ips):
                for tmpl in args.hook_cmd:
                    cmd = tmpl.format(ip=ip, port=port)
                    subprocess.run(cmd, shell=True)

    if args.nmap_output and all_ips:
        ip_file = os.path.join(args.output_dir, "_all_ips.txt")
        with open(ip_file, 'w') as f:
            for ip in sorted(all_ips):
                f.write(ip + "\n")
        if args.nmap_format == 'A':
            ncmd = f"nmap -p {args.ports} -iL {ip_file} -oA {args.nmap_output}"
        else:
            ext = args.nmap_format.lower()
            ncmd = f"nmap -p {args.ports} -iL {ip_file} -o{args.nmap_format} {args.nmap_output}.{ext}"
        print(f"[+] Running Nmap: {ncmd}")
        subprocess.run(ncmd, shell=True)
        os.remove(ip_file)

if __name__ == '__main__':
    args = parse_args()
    print(f"[INFO] mpex scanning ports={args.ports}, rate={args.rate}")
    res = run_masscan(args)
    if args.live:
        print(f"[INFO] Parsing {len(res)} lines...")
    else:
        print("[INFO] Parsing output...")
    parse_and_write(args, res)
    print("[DONE] Completed mpex workflow.")
