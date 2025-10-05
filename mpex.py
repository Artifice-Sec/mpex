#!/usr/bin/env python3
"""
mpex.py: A polished Python wrapper around Masscan with:
 - automatic interface/gateway detection
 - host exclusions
 - live feedback
 - async plugin hooks with concurrency control
 - per-port output files (port-<port>.txt)
 - single aggregated all-IPs file (all_ips.txt)
 - optional timestamped outputs
 - safer subprocess usage for Nmap (list args) and quoted hook substitutions

Usage examples:
  python mpex.py --cidr 192.168.0.0/24 --ports 80,443 --rate 1000 --auto-route
  python mpex.py --input-file targets.txt --ports 22,80 --rate 5000 --auto-route --live \
      --hook-cmd "nikto -h http://{ip}:{port}" --hook-concurrency 50
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
import json
from datetime import datetime

# Validate ports string: e.g. "80,443,1000-1010"
PORTS_PATTERN = re.compile(r"^(\d+(-\d+)?)(,(\d+(-\d+)?))*$")

# Accept typical masscan lines. Example:
# "Discovered open port 80/tcp on 192.168.0.5"
# "Discovered open port 22/tcp on 2001:db8::1"
MASSCAN_PATTERN = re.compile(r"Discovered open port (\d+)/\w+ on ([0-9a-fA-F:\.]+)")

DEFAULT_HOOK_CONCURRENCY = 20


def detect_route():
    """
    Detect default route and gateway MAC address. Returns (iface, mac).
    Tries to be robust against different 'ip route' output forms.
    """
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        # Example outputs:
        # "default via 192.168.0.1 dev eth0 proto dhcp metric 100"
        # "default via 10.0.0.1 dev ens3"
        m = re.search(r"default\s+via\s+([0-9a-fA-F\.:]+)\s+dev\s+(\S+)", out)
        if not m:
            raise ValueError("Could not parse 'ip route' output")
        gw = m.group(1)
        iface = m.group(2)
    except Exception as e:
        print(f"[ERROR] Unable to detect default route: {e}", file=sys.stderr)
        sys.exit(1)

    # Try to find MAC from 'ip neigh' for the gateway IP
    try:
        neigh = subprocess.check_output(["ip", "neigh"], text=True)
        mac = None
        for line in neigh.splitlines():
            # lines like: "192.168.0.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE"
            cols = line.split()
            if not cols:
                continue
            if cols[0] == gw:
                if "lladdr" in cols:
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
                        help="Command to run per result; use {ip} and {port} placeholders (shell executed).")
    parser.add_argument("--hook-concurrency", type=int, default=DEFAULT_HOOK_CONCURRENCY,
                        help=f"Max concurrent hook commands (default {DEFAULT_HOOK_CONCURRENCY})")
    parser.add_argument("--nmap-output",
                        help="Base name for aggregated Nmap outputs")
    parser.add_argument("--nmap-format", choices=["N", "X", "G", "S", "A"], default="X",
                        help="Format: N=normal, X=xml, G=grepable, S=script, A=all (default: X)")
    parser.add_argument("--timestamp-output", action="store_true",
                        help="Append a timestamp to output filenames (e.g., all_ips-YYYYMMDDThhmmss.txt)")
    parser.add_argument("--json-output", action="store_true",
                        help="Also save aggregated results as JSON (results.json)")
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

    # Validate targets and files
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

    # Validate excludes format (but do not yet load)
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


def build_masscan_cmd(args):
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
    return cmd


def run_masscan(args, timeout=300):
    cmd = build_masscan_cmd(args)
    if args.live:
        # Stream stdout lines
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        print("[LIVE] Scanning... streaming results")
        lines = []
        try:
            # Read stdout line by line
            while True:
                raw = proc.stdout.readline()
                if raw == "" and proc.poll() is not None:
                    break
                if raw:
                    line = raw.rstrip()
                    print(line)
                    lines.append(line)
            # Wait for process to finish
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
    """
    Run a hook command in shell under a semaphore.
    Returns (returncode, combined_stdout_stderr)
    """
    async with sem:
        # Use create_subprocess_shell to allow user commands with pipes etc.
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await proc.communicate()
        out_text = out.decode(errors="ignore") if out else ""
        return proc.returncode, out_text


async def run_hooks_async(hook_cmds, ip, port, concurrency, output_dir):
    """
    Run hook commands concurrently with a concurrency limit.
    hook_cmds: list of shell templates (strings) using {ip} and {port}
    ip and port are strings
    Returns list of (cmd, returncode, output)
    """
    sem = asyncio.Semaphore(concurrency)
    tasks = []
    results = []
    for tmpl in hook_cmds:
        # Quote ip and port when substituting to reduce injection risk
        q_ip = shlex.quote(ip)
        q_port = shlex.quote(str(port))
        cmd = tmpl.format(ip=q_ip, port=q_port)
        # Track commands and tasks
        tasks.append(asyncio.create_task(_run_hook_shell(cmd, sem)))
        results.append((cmd, None, None))  # placeholder
    # Wait for tasks to finish
    completed = await asyncio.gather(*tasks, return_exceptions=False)
    final = []
    for (cmd_entry, res) in zip(results, completed):
        cmd = cmd_entry[0]
        returncode, output = res
        # Save hook outputs to a file for auditing
        safe_fname = os.path.join(output_dir, f"hook-{sanitize_filename(cmd)[:80]}.log")
        try:
            with open(safe_fname, "w") as hf:
                hf.write(f"CMD: {cmd}\n\n")
                hf.write(output or "")
        except Exception:
            # don't fail the whole run for hook log write issues
            pass
        final.append((cmd, returncode, output))
    return final


def sanitize_filename(s: str) -> str:
    # Reduce arbitrary shell command to file-safe name
    return re.sub(r'[^A-Za-z0-9._-]+', '_', s)


def parse_and_write(args, lines):
    if not lines:
        print("[WARNING] No output from masscan; exiting.")
        sys.exit(0)

    # Build exclusion set of networks
    exclude_nets = set()
    # always exclude localhost
    exclude_nets.add(ipaddress.ip_network("127.0.0.1/32"))
    # exclude local addresses on the host
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
                # should not happen because validated earlier, but skip if so
                pass

    if args.excludefile:
        try:
            with open(args.excludefile) as ef:
                for line in ef:
                    net = line.strip()
                    if not net:
                        continue
                    try:
                        exclude_nets.add(ipaddress.ip_network(net))
                    except Exception:
                        pass
        except Exception as e:
            print(f"[ERROR] Unable to read exclusion file: {e}", file=sys.stderr)
            sys.exit(1)

    ports_map = {}  # port -> set of ips
    total = len(lines)
    for idx, line in enumerate(lines, start=1):
        if args.live:
            print(f"Processing {idx}/{total}...", end="\r", flush=True)
        m = MASSCAN_PATTERN.search(line)
        if not m:
            continue
        port, ip = m.group(1), m.group(2)
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            # skip malformed IPs
            continue
        # skip excludes
        if any(addr in net for net in exclude_nets):
            continue
        ports_map.setdefault(port, set()).add(str(addr))
    if args.live:
        print()

    os.makedirs(args.output_dir, exist_ok=True)
    all_ips = set()

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S") if args.timestamp_output else None

    # Write per-port files
    for port, ips in ports_map.items():
        fname = os.path.join(args.output_dir, f"port-{port}.txt")
        if timestamp:
            fname = os.path.join(args.output_dir, f"port-{port}-{timestamp}.txt")
        try:
            with open(fname, "w") as f:
                for ip in sorted(ips):
                    f.write(ip + "\n")
                    all_ips.add(ip)
            print(f"[+] Wrote {len(ips)} IPs to {fname}")
        except IOError as e:
            print(f"[ERROR] Failed to write {fname}: {e}", file=sys.stderr)

    # Write single all-IPs file (unique IPs; no ports)
    base_all_fname = os.path.join(args.output_dir, "all_ips.txt")
    all_fname = base_all_fname if not timestamp else os.path.join(args.output_dir, f"all_ips-{timestamp}.txt")
    try:
        with open(all_fname, "w") as af:
            for ip in sorted(all_ips):
                af.write(ip + "\n")
        print(f"[+] Wrote {len(all_ips)} unique IPs to {all_fname}")
    except IOError as e:
        print(f"[ERROR] Failed to write {all_fname}: {e}", file=sys.stderr)

    # JSON aggregated output (optional)
    if args.json_output:
        json_fname = os.path.join(args.output_dir, "results.json")
        if timestamp:
            json_fname = os.path.join(args.output_dir, f"results-{timestamp}.json")
        try:
            json_obj = {"generated_at": datetime.utcnow().isoformat() + "Z", "ports": {}}
            for port, ips in ports_map.items():
                json_obj["ports"][port] = sorted(list(ips))
            with open(json_fname, "w") as jf:
                json.dump(json_obj, jf, indent=2)
            print(f"[+] Wrote JSON summary to {json_fname}")
        except IOError as e:
            print(f"[ERROR] Failed to write JSON summary: {e}", file=sys.stderr)

    # Run hook commands if requested
    if args.hook_cmd and ports_map:
        # Build a list of tasks for each discovered ip
        # For each ip we will run the hook commands with that ip and the port
        async_tasks = []
        loop = asyncio.get_event_loop()
        # Collate tasks: run hooks per ip+port
        for port, ips in ports_map.items():
            for ip in sorted(ips):
                async_tasks.append(run_hooks_async(args.hook_cmd, ip, port, args.hook_concurrency, args.output_dir))
        # Run them in batches to avoid creating too many tasks at once
        if async_tasks:
            print(f"[INFO] Running {len(async_tasks)} hook tasks (concurrency {args.hook_concurrency})")
            loop.run_until_complete(asyncio.gather(*async_tasks))

    # Aggregated Nmap run if requested
    if args.nmap_output and all_ips:
        ip_file = os.path.join(args.output_dir, f"_all_ips-{timestamp}.txt") if timestamp else os.path.join(args.output_dir, "_all_ips.txt")
        try:
            with open(ip_file, "w") as f:
                for ip in sorted(all_ips):
                    f.write(ip + "\n")

            # Build nmap invocation as list for safety
            if args.nmap_format == "A":
                # -oA requires a base filename without extension
                nmap_args = ["nmap", "-p", args.ports, "-iL", ip_file, "-oA", args.nmap_output]
            else:
                # map format letter to nmap option (oN, oX, oG, oS)
                nmap_flag = "-o" + args.nmap_format
                # nmap expects flag and filename together in typical CLI, but pass as separate args
                nmap_args = ["nmap", "-p", args.ports, "-iL", ip_file, nmap_flag, args.nmap_output]
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
        sys.exit(1)


if __name__ == "__main__":
    main()
