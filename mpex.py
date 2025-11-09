#!/usr/bin/env python3
"""
mpex.py: A polished Python wrapper around Masscan with:
 - automatic interface/gateway detection
 - host exclusions
 - live feedback
 - async plugin hooks
 - per-port output files (<port>-<proto>.txt)
 - single aggregated all-IPs file (all_ips.txt)
 - safer subprocess usage for Nmap (list args) and quoted hook substitutions

Usage examples:
  python mpex.py --cidr 192.168.0.0/24 --ports 80,443 --rate 1000 --auto-route
  python mpex.py --input-file targets.txt --ports 53,161 --udp --rate 5000 --auto-route --live \
      --hook-cmd "nikto -h http://{ip}:{port}" --nmap-output nmap-agg --nmap-open
"""
import argparse
import asyncio
import subprocess
import re
import os
import sys
import socket
import shutil
import ipaddress
import shlex
from datetime import datetime

PORTS_PATTERN = re.compile(r"^(\d+(-\d+)?)(,(\d+(-\d+)?))*$")
MASSCAN_PATTERN = re.compile(r"Discovered open port (\d+)/(tcp|udp) on ([0-9a-fA-F:\.]+)")
DEFAULT_HOOK_CONCURRENCY = 20

def detect_route():
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        m = re.search(r"default\s+via\s+([0-9a-fA-F\.:]+)\s+dev\s+(\S+)", out)
        if not m:
            raise ValueError("Could not parse 'ip route' output")
        gw = m.group(1)
        iface = m.group(2)
    except Exception as e:
        print(f"[ERROR] Unable to detect default route: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        neigh = subprocess.check_output(["ip", "neigh"], text=True)
        mac = None
        for line in neigh.splitlines():
            cols = line.split()
            if not cols:
                continue
            if cols[0] == gw and "lladdr" in cols:
                mac = cols[cols.index("lladdr") + 1]
                break
        if not mac:
            raise ValueError("MAC not found for gateway")
    except Exception as e:
        print(f"[ERROR] Unable to detect MAC for gateway {gw}: {e}", file=sys.stderr)
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
    parser.add_argument("--ports", required=True, help="Comma-separated list of ports or ranges, e.g. 80,443,1000-1100")
    parser.add_argument("--rate", type=int, default=1000, help="Max packets per second (masscan --max-rate), default=1000")
    parser.add_argument("--output-dir", default=".", help="Directory to save outputs and hook results")
    parser.add_argument("--auto-route", action="store_true", help="Auto-detect default interface and gateway MAC")
    parser.add_argument("--interface", help="Network interface for Masscan, e.g. eth0 or tun0")
    parser.add_argument("--router-mac", help="Router MAC address for proper routing")
    parser.add_argument("--exclude", help="Comma-separated list of IPs or CIDRs to skip")
    parser.add_argument("--excludefile", help="File containing IPs/CIDRs to skip, one per line")
    parser.add_argument("--live", action="store_true", help="Stream Masscan output and show parsing progress")
    parser.add_argument("--hook-cmd", action="append", help="Command to run per result; use {ip} and {port} placeholders.")
    parser.add_argument("--nmap-output", help="Base name for aggregated Nmap outputs")
    parser.add_argument("--nmap-format", choices=["N", "X", "G", "S", "A"], default="X", help="Format: N=normal, X=xml, G=grepable, S=script, A=all (default: X)")
    parser.add_argument("--udp", action="store_true", help="Scan UDP ports as well.")
    parser.add_argument("--nmap-open", action="store_true", help="Pass --open to nmap so it only shows open ports")
    args = parser.parse_args()

    if args.auto_route:
        iface, mac = detect_route()
        args.interface = iface
        args.router_mac = mac
        print(f"[INFO] Auto-detected interface={iface}, router-mac={mac}")

    if not shutil.which("masscan"):
        print("[ERROR] masscan binary not found.", file=sys.stderr)
        sys.exit(1)
    if args.nmap_output and not shutil.which("nmap"):
        print("[ERROR] nmap binary not found.", file=sys.stderr)
        sys.exit(1)

    if not PORTS_PATTERN.match(args.ports):
        print(f"[ERROR] Invalid ports format: {args.ports}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.ip:
            ipaddress.ip_address(args.ip)
        elif args.cidr:
            ipaddress.ip_network(args.cidr)
        elif args.input_file and not os.path.isfile(args.input_file):
            raise FileNotFoundError(args.input_file)
    except Exception as e:
        print(f"[ERROR] Invalid target or missing file: {e}", file=sys.stderr)
        sys.exit(1)

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

def masscan_ports_from_user(ports_str, udp=False):
    tokens = [t.strip() for t in ports_str.split(',') if t.strip()]
    out_tokens = []
    for t in tokens:
        if udp:
            if not t.upper().startswith('U:'):
                out_tokens.append('U:' + t)
            else:
                out_tokens.append(t)
        else:
            out_tokens.append(t.lstrip('U:'))
    return ','.join(out_tokens)

def build_masscan_cmd(args):
    masscan_port_spec = masscan_ports_from_user(args.ports, udp=args.udp)
    cmd = ["masscan", "-p", masscan_port_spec]
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
    return cmd

def run_masscan(args, timeout=300):
    cmd = build_masscan_cmd(args)
    if args.live:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        print("[LIVE] Scanning... streaming results")
        lines = []
        try:
            while True:
                raw = proc.stdout.readline()
                if raw == "" and proc.poll() is not None:
                    break
                if raw:
                    line = raw.rstrip()
                    print(line)
                    lines.append(line)
            rc = proc.wait(timeout=timeout)
            if rc != 0:
                err = proc.stderr.read()
                raise subprocess.CalledProcessError(rc, cmd, output=None, stderr=err)
        except subprocess.TimeoutExpired:
            proc.kill()
            print("[ERROR] masscan timed out.", file=sys.stderr)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] masscan failed: {e}\n{e.stderr}", file=sys.stderr)
            sys.exit(1)
        return lines
    else:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=timeout)
            return proc.stdout.splitlines()
        except subprocess.TimeoutExpired:
            print("[ERROR] masscan timed out.", file=sys.stderr)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] masscan failed: {e}\n{e.stderr}", file=sys.stderr)
            sys.exit(1)

async def _run_hook_shell(cmd, sem):
    async with sem:
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await proc.communicate()
        out_text = out.decode(errors="ignore") if out else ""
        return proc.returncode, out_text

async def run_hooks_async(hook_cmds, ip, port, output_dir):
    sem = asyncio.Semaphore(DEFAULT_HOOK_CONCURRENCY)
    tasks = []
    results = []
    for tmpl in hook_cmds:
        q_ip = shlex.quote(ip)
        q_port = shlex.quote(str(port))
        cmd = tmpl.format(ip=q_ip, port=q_port)
        tasks.append(asyncio.create_task(_run_hook_shell(cmd, sem)))
        results.append((cmd, None, None))
    completed = await asyncio.gather(*tasks, return_exceptions=False)
    final = []
    for (cmd_entry, res) in zip(results, completed):
        cmd = cmd_entry[0]
        returncode, output = res
        safe_fname = os.path.join(output_dir, f"hook-{re.sub(r'[^A-Za-z0-9._-]+', '_', cmd)[:80]}.log")
        try:
            with open(safe_fname, "w") as hf:
                hf.write(f"CMD: {cmd}\n\n")
                hf.write(output or "")
        except Exception:
            pass
        final.append((cmd, returncode, output))
    return final

def parse_and_write(args, lines):
    if not lines:
        print("[WARNING] No output from masscan; exiting.")
        sys.exit(0)

    exclude_nets = {ipaddress.ip_network("127.0.0.1/32")}
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            exclude_nets.add(ipaddress.ip_network(f"{ip}/32"))
    except Exception:
        pass

    if args.exclude:
        for net in args.exclude.split(','):
            try:
                exclude_nets.add(ipaddress.ip_network(net))
            except Exception:
                pass

    if args.excludefile:
        try:
            with open(args.excludefile) as ef:
                for line in ef:
                    net = line.strip()
                    if net:
                        try:
                            exclude_nets.add(ipaddress.ip_network(net))
                        except Exception:
                            pass
        except Exception as e:
            print(f"[ERROR] Unable to read exclusion file: {e}", file=sys.stderr)
            sys.exit(1)

    ports_map = {}  # (port, proto) -> set of ips
    total = len(lines)
    for idx, line in enumerate(lines, start=1):
        if args.live:
            print(f"Processing {idx}/{total}...", end="\r", flush=True)
        m = MASSCAN_PATTERN.search(line)
        if not m:
            continue
        port, proto, ip = m.groups()
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            continue
        if any(addr in net for net in exclude_nets):
            continue
        key = (port, proto.lower())
        ports_map.setdefault(key, set()).add(str(addr))
    if args.live:
        print()

    os.makedirs(args.output_dir, exist_ok=True)
    all_ips = set()

    for (port, proto), ips in ports_map.items():
        base_name = f"{port}-{proto}"
        fname = os.path.join(args.output_dir, f"{base_name}.txt")
        try:
            with open(fname, "w") as f:
                for ip in sorted(ips):
                    f.write(ip + "\n")
                    all_ips.add(ip)
            print(f"[+] Wrote {len(ips)} IPs to {fname}")
        except IOError as e:
            print(f"[ERROR] Failed to write {fname}: {e}", file=sys.stderr)

    base_all_fname = os.path.join(args.output_dir, "all_ips.txt")
    try:
        with open(base_all_fname, "w") as af:
            for ip in sorted(all_ips):
                af.write(ip + "\n")
        print(f"[+] Wrote {len(all_ips)} unique IPs to {base_all_fname}")
    except IOError as e:
        print(f"[ERROR] Failed to write {base_all_fname}: {e}", file=sys.stderr)

    if args.hook_cmd and ports_map:
        async_tasks = []
        loop = asyncio.get_event_loop()
        for (port, proto), ips in ports_map.items():
            for ip in sorted(ips):
                async_tasks.append(run_hooks_async(args.hook_cmd, ip, port, args.output_dir))
        if async_tasks:
            print(f"[INFO] Running {len(async_tasks)} hook tasks (concurrency {DEFAULT_HOOK_CONCURRENCY})")
            loop.run_until_complete(asyncio.gather(*async_tasks))

    if args.nmap_output and all_ips:
        ip_file = os.path.join(args.output_dir, "_all_ips.txt")
        try:
            with open(ip_file, "w") as f:
                for ip in sorted(all_ips):
                    f.write(ip + "\n")

            nmap_args = ["nmap"]
            if args.udp:
                nmap_args.append("-sU")
            nmap_args += ["-p", args.ports, "-iL", ip_file]
            if args.nmap_open:
                nmap_args.append("--open")
            if args.nmap_format == "A":
                nmap_args += ["-oA", args.nmap_output]
            else:
                nmap_flag = "-o" + args.nmap_format
                nmap_args += [nmap_flag, args.nmap_output]

            print(f"[+] Running Nmap: {' '.join(shlex.quote(a) for a in nmap_args)}")
            subprocess.run(nmap_args, check=True)
            print(f"[+] Aggregated Nmap output saved to {args.nmap_output}.*")
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
