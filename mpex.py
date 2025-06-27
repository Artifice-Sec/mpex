#!/usr/bin/env python3
"""
mpex.py: A Python wrapper around Masscan with automatic interface/gateway detection, host exclusions, live feedback, plugin hooks, and flexible aggregated Nmap outputs.

Usage examples:
  python mpex.py --cidr 192.168.0.0/24 --ports 80,443 --rate 1000 --auto-route
  python mpex.py --input-file targets.txt --ports 22,80 --rate 5000 --auto-route --live --hook-cmd "nikto -h http://{ip}:{port}"
  python mpex.py --ip 192.168.0.117 --ports 445 --rate 1000 --nmap-output fullscan --nmap-format A
"""
import argparse
import subprocess
import re
import os
import sys
import socket
import shutil
import ipaddress

# Validate ports string: e.g. "80,443,1000-1010"
PORTS_PATTERN = re.compile(r"^(\d+(-\d+)?)(,(\d+(-\d+)?))*$")


def detect_route():
    try:
        out = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
        parts = out.split()
        gw = parts[2]  # gateway IP
        iface = parts[4]  # interface
    except Exception:
        print('[ERROR] Unable to detect default route.', file=sys.stderr)
        sys.exit(1)
    try:
        neigh = subprocess.check_output(['ip', 'neigh'], text=True)
        mac = None
        for line in neigh.splitlines():
            if line.startswith(gw + ' '):
                cols = line.split()
                if 'lladdr' in cols:
                    mac = cols[cols.index('lladdr') + 1]
                    break
        if not mac:
            raise ValueError('MAC not found')
    except Exception:
        print(f'[ERROR] Unable to detect MAC for gateway {gw}.', file=sys.stderr)
        sys.exit(1)
    return iface, mac


def parse_args():
    parser = argparse.ArgumentParser(
        description="mpex: orchestrate Masscan scans with auto-route, exclusions, live feedback, hooks, and aggregated Nmap"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cidr", help="CIDR range to scan, e.g. 192.168.0.0/24")
    group.add_argument("--input-file", help="File containing targets (one per line)")
    group.add_argument("--ip", help="Single IP address to scan, e.g. 192.168.0.117")
    parser.add_argument("--ports", required=True,
                        help="Comma-separated list of ports or ranges, e.g. 80,443,1000-1100")
    parser.add_argument("--rate", type=int, default=1000,
                        help="Max packets per second (masscan --max-rate), default=1000")
    parser.add_argument("--output-dir", default=".",
                        help="Directory to save outputs and hook results")
    parser.add_argument("--auto-route", action="store_true",
                        help="Auto-detect default interface and gateway MAC, and apply them to Masscan")
    parser.add_argument("--interface", help="Network interface for Masscan, e.g. eth0 or tun0")
    parser.add_argument("--router-mac", help="Router MAC address for proper routing, e.g. 00:11:22:33:44:55")
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
                        help="Format: N=normal, X=xml, G=grepable, S=script, A=all (default: X)")
    args = parser.parse_args()

    # Auto-route detection and override
    if args.auto_route:
        iface, mac = detect_route()
        args.interface = iface
        args.router_mac = mac
        print(f"[INFO] Auto-detected interface={iface}, router-mac={mac}")

    # Binary checks
    if not shutil.which("masscan"):
        print("[ERROR] masscan binary not found.", file=sys.stderr)
        sys.exit(1)
    if args.nmap_output and not shutil.which("nmap"):
        print("[ERROR] nmap binary not found.", file=sys.stderr)
        sys.exit(1)

    # Validate ports
    if not PORTS_PATTERN.match(args.ports):
        print(f"[ERROR] Invalid ports format: {args.ports}", file=sys.stderr)
        sys.exit(1)

    # Validate targets
    try:
        if args.ip:
            ipaddress.ip_address(args.ip)
        elif args.cidr:
            ipaddress.ip_network(args.cidr)
        elif args.input_file:
            if not os.path.isfile(args.input_file):
                raise FileNotFoundError(args.input_file)
    except Exception as e:
        print(f"[ERROR] Invalid target or missing file: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate excludes
    if args.exclude:
        for net in args.exclude.split(','):
            try:
                ipaddress.ip_network(net)
            except Exception:
                print(f"[ERROR] Invalid --exclude entry: {net}", file=sys.stderr)
                sys.exit(1)
    if args.excludefile and not os.path.isfile(args.excludefile):
        print(f"[ERROR] Exclusion file not found: {args.excludefile}", file=sys.stderr)
        sys.exit(1)

    return args


def run_masscan(args, timeout=300):
    cmd = ["masscan", "-p", args.ports]
    if args.input_file:
        cmd += ["-iL", args.input_file]
    elif args.ip:
        cmd.append(args.ip)
    else:
        cmd.append(args.cidr)
    cmd += ["--max-rate", str(args.rate)]
    if args.interface:
        cmd += ["--interface", args.interface]
    if args.router_mac:
        cmd += ["--router-mac", args.router_mac]
    if args.exclude:
        cmd += ["--exclude", args.exclude]
    if args.excludefile:
        cmd += ["--excludefile", args.excludefile]

    if args.live:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        print("[LIVE] Scanning... streaming results")
        lines = []
        try:
            for raw in proc.stdout:
                line = raw.rstrip()
                print(line)
                lines.append(line)
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            print("[ERROR] masscan timed out.", file=sys.stderr)
            sys.exit(1)
        if proc.returncode != 0:
            err = proc.stderr.read()
            print(f"[ERROR] masscan failed: {err}", file=sys.stderr)
            sys.exit(1)
        return lines
    else:
        try:
            proc = subprocess.run(cmd, capture_output=True,
                                  text=True, check=True, timeout=timeout)
            return proc.stdout.splitlines()
        except subprocess.TimeoutExpired:
            print("[ERROR] masscan timed out.", file=sys.stderr)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] masscan failed: {e}\n{e.stderr}", file=sys.stderr)
            sys.exit(1)


def parse_and_write(args, lines):
    if not lines:
        print("[WARNING] No open ports found; exiting.")
        sys.exit(0)

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
        try:
            with open(fname, 'w') as f:
                for ip in sorted(ips):
                    f.write(ip + "\n")
                    all_ips.add(ip)
            print(f"[+] Wrote {len(ips)} IPs to {fname}")
        except IOError as e:
            print(f"[ERROR] Failed to write {fname}: {e}", file=sys.stderr)

        if args.hook_cmd:
            for ip in sorted(ips):
                for tmpl in args.hook-cmd:
                    cmd = tmpl.format(ip=ip, port=port)
                    subprocess.run(cmd, shell=True)

    # Aggregated Nmap run
    if args.nmap-output and all_ips:
        ip_file = os.path.join(args.output_dir, "_all_ips.txt")
        try:
            with open(ip_file, 'w') as f:
                for ip in sorted(all_ips):
                    f.write(ip + "\n")

            if args.nmap-format == 'A':
                ncmd = f"nmap -p {args.ports} -iL {ip_file} -oA {args.nmap-output}"
            else:
                ext = args.nmap-format.lower()
                ncmd = f"nmap -p {args.ports} -iL {ip_file} -o{args.nmap-format} {args.nmap-output}.{ext}"
            print(f"[+] Running Nmap: {ncmd}")
            subprocess.run(ncmd, shell=True, check=True)
            print(f"[+] Aggregated Nmap output saved to {args.nmap-output}.*")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Aggregated Nmap failed: {e}", file=sys.stderr)
        except IOError as e:
            print(f"[ERROR] Failed writing temp file {ip_file}: {e}", file=sys.stderr)
        finally:
            try:
                os.remove(ip_file)
            except OSError:
                pass


def main():
    try:
        args = parse_args()
        print(f"[INFO] mpex scanning ports={args.ports}, rate={args.rate}")
        lines = run_masscan(args)
        if args.live:
            print(f"[INFO] Parsing {len(lines)} lines...")
        else:
            print("[INFO] Parsing output...")
        parse_and_write(args, lines)
        print("[DONE] Completed mpex workflow.")
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user. Cleaning up and exiting.")
        sys.exit(1)

if __name__ == '__main__':
    main()
