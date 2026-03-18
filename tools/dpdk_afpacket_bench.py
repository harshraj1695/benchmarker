#!/usr/bin/env python3
import argparse
import csv
import json
import os
import shlex
import signal
import socket
import statistics
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
DEFAULT_NAMESPACE = "dpdkbench"
DEFAULT_HOST_IFACE = "dpdkbench0"
DEFAULT_PEER_IFACE = "dpdkbench1"
HOST_MAC = "02:00:00:00:00:01"
PEER_MAC = "02:00:00:00:00:02"
DEFAULT_HOST_IP = "198.18.0.1"
DEFAULT_PEER_IP = "198.18.0.2"
DEFAULT_PACKET_COUNT = 20000
DEFAULT_PACKET_SIZE = 128
DEFAULT_SETTLE_SECS = 1.5

# Each sent frame embeds an 8-byte float64 timestamp + 8-byte uint64 seq
# at the start of the UDP payload for RTT measurement.
# Latency is silently skipped if the payload is too small to hold both.
LATENCY_HEADER_BYTES = 16


@dataclass
class AppTarget:
    name: str
    cmd: str
    stdin: str
    description: str


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def run(cmd, check=True, capture_output=False, text=True):
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=text)


def require_root():
    if os.geteuid() != 0:
        print("Run this script as root or with sudo.", file=sys.stderr)
        sys.exit(1)


def mac_to_bytes(mac):
    return bytes(int(p, 16) for p in mac.split(":"))


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_udp_frame(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload):
    eth = mac_to_bytes(dst_mac) + mac_to_bytes(src_mac) + struct.pack("!H", ETH_P_IP)

    total_length = 20 + 8 + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0, 0, 64,
        socket.IPPROTO_UDP, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]

    udp_length = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, socket.IPPROTO_UDP, udp_length,
    )
    udp_sum = checksum(pseudo + udp_header + payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_sum)
    return eth + ip_header + udp_header + payload


# ---------------------------------------------------------------------------
# Network namespace management
# ---------------------------------------------------------------------------

def cleanup_netns(namespace, host_iface):
    subprocess.run(["ip", "netns", "del", namespace],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
    subprocess.run(["ip", "link", "del", host_iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)


def setup_netns(namespace, host_iface, peer_iface):
    cleanup_netns(namespace, host_iface)
    run(["ip", "netns", "add", namespace])
    run(["ip", "link", "add", host_iface, "type", "veth", "peer", "name", peer_iface])
    run(["ip", "link", "set", peer_iface, "netns", namespace])
    run(["ip", "link", "set", "dev", host_iface, "address", HOST_MAC])
    run(["ip", "link", "set", "dev", host_iface, "up"])
    run(["ip", "link", "set", "dev", host_iface, "promisc", "on"])
    run(["ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"])
    run(["ip", "netns", "exec", namespace, "ip", "link", "set", "dev",
         peer_iface, "address", PEER_MAC])
    run(["ip", "netns", "exec", namespace, "ip", "link", "set", "dev", peer_iface, "up"])
    run(["ip", "netns", "exec", namespace, "ip", "link", "set", "dev",
         peer_iface, "promisc", "on"])
    run(["ip", "addr", "flush", "dev", host_iface], check=False)
    run(["ip", "addr", "add", f"{DEFAULT_HOST_IP}/24", "dev", host_iface])
    run(["ip", "netns", "exec", namespace, "ip", "addr", "add",
         f"{DEFAULT_PEER_IP}/24", "dev", peer_iface])


# ---------------------------------------------------------------------------
# Process stats
# ---------------------------------------------------------------------------

def read_proc_cpu(pid):
    with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
        fields = fh.read().split()
    return int(fields[13]) + int(fields[14])


def read_proc_rss_mb(pid):
    with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024.0
    return 0.0


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

def launch_app(target, iface):
    cmd = target.cmd.format(iface=iface)
    proc = subprocess.Popen(
        cmd, shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True, bufsize=1,
        preexec_fn=os.setsid,
    )
    return proc, cmd


def validate_command_template(command):
    parts = shlex.split(command)
    if not parts:
        raise SystemExit("Empty app command.")
    if os.path.isdir(parts[0]):
        raise SystemExit(
            f"The app path '{parts[0]}' is a directory, not an executable. "
            "Point --app to the built binary."
        )
    if "{iface}" not in command:
        raise SystemExit(
            "Your --app command must contain '{iface}' so the benchmark "
            "can attach the DPDK app to the temporary AF_PACKET interface."
        )


def stop_app(proc):
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=3)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def collect_output(proc, limit=120):
    if not proc.stdout:
        return ""
    try:
        text = proc.stdout.read()
    except Exception:
        text = ""
    lines = [l for l in text.splitlines() if l.strip()]
    return "\n".join(lines[-limit:])


# ---------------------------------------------------------------------------
# Worker — runs inside the network namespace
#
# Latency measurement
# -------------------
# Every UDP payload starts with a 16-byte header:
#   bytes 0-7  : big-endian float64  — time.perf_counter() at send time
#   bytes 8-15 : big-endian uint64   — sequence number
#
# On receive the worker extracts the timestamp from the forwarded frame,
# computes RTT = now - send_ts, and accumulates per-packet samples.
# If the DUT does NOT forward packets back (RX-only pipeline), no RTT
# samples are collected and all lat_* fields are reported as null.
# ---------------------------------------------------------------------------

def worker_mode(args):
    send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.htons(ETH_P_ALL))
    send_sock.bind((args.iface, 0))
    recv_sock.bind((args.iface, 0))
    recv_sock.settimeout(0.2)

    payload_bytes = max(args.packet_size - 14 - 20 - 8, 16)
    can_measure_latency = payload_bytes >= LATENCY_HEADER_BYTES

    src_port, dst_port = 12345, 9000
    send_times: dict = {}   # seq -> perf_counter send timestamp
    rtts_us: list = []

    sent = received = 0
    start = time.perf_counter()
    wall_start = time.time()
    next_send = start

    for seq in range(args.count):
        ts = time.perf_counter()
        if can_measure_latency:
            payload = (struct.pack("!d", ts)
                       + struct.pack("!Q", seq)
                       + b"X" * (payload_bytes - LATENCY_HEADER_BYTES))
            send_times[seq] = ts
        else:
            payload = struct.pack("!Q", seq) + b"X" * (payload_bytes - 8)

        frame = build_udp_frame(
            src_mac=PEER_MAC, dst_mac=HOST_MAC,
            src_ip=DEFAULT_PEER_IP, dst_ip=DEFAULT_HOST_IP,
            src_port=src_port, dst_port=dst_port,
            payload=payload,
        )
        send_sock.send(frame)
        sent += 1

        if args.pps > 0:
            next_send += 1.0 / args.pps
            delay = next_send - time.perf_counter()
            if delay > 0:
                time.sleep(delay)

    send_done = time.perf_counter()
    wall_send_done = time.time()
    quiet_deadline = wall_send_done + args.settle_secs

    # Receive loop — drains forwarded packets and extracts RTTs
    while time.time() < quiet_deadline:
        try:
            packet, addr = recv_sock.recvfrom(65535)
        except socket.timeout:
            continue

        recv_ts = time.perf_counter()

        if addr[2] == socket.PACKET_OUTGOING:
            continue
        if len(packet) < 42:
            continue
        if struct.unpack("!H", packet[12:14])[0] != ETH_P_IP:
            continue

        received += 1
        quiet_deadline = time.time() + 0.1   # extend window while packets arrive

        if can_measure_latency and len(packet) >= 42 + LATENCY_HEADER_BYTES:
            udp_payload = packet[42:]
            try:
                sent_ts = struct.unpack("!d", udp_payload[:8])[0]
                seq_back = struct.unpack("!Q", udp_payload[8:16])[0]
                if seq_back in send_times:
                    rtt_us = (recv_ts - sent_ts) * 1e6
                    if 0 < rtt_us < 10_000_000:   # sanity filter
                        rtts_us.append(rtt_us)
                        del send_times[seq_back]
            except struct.error:
                pass

    end_wall = time.time()
    send_duration = max(send_done - start, 1e-9)
    wall_duration  = max(end_wall - wall_start, 1e-9)
    total_bits = sent * args.packet_size * 8
    recv_bits  = received * args.packet_size * 8

    # Latency percentiles
    if rtts_us:
        s = sorted(rtts_us)
        n = len(s)
        lat = {
            "lat_samples":  n,
            "lat_avg_us":   statistics.mean(s),
            "lat_med_us":   statistics.median(s),
            "lat_p95_us":   s[int(n * 0.95)],
            "lat_p99_us":   s[int(n * 0.99)],
            "lat_min_us":   s[0],
            "lat_max_us":   s[-1],
            "lat_stdev_us": statistics.stdev(s) if n > 1 else 0.0,
        }
    else:
        lat = {k: None for k in (
            "lat_samples", "lat_avg_us", "lat_med_us",
            "lat_p95_us", "lat_p99_us", "lat_min_us",
            "lat_max_us", "lat_stdev_us",
        )}
        lat["lat_samples"] = 0

    result = {
        "sent":             sent,
        "received":         received,
        "loss_percent":     (100.0 * max(sent - received, 0) / sent) if sent else 0.0,
        "send_duration_sec": send_duration,
        "wall_sec":         wall_duration,
        "send_pps":         sent / send_duration,
        "send_mbps":        total_bits / send_duration / 1e6,
        "return_pps":       received / wall_duration,
        "goodput_mbps":     recv_bits / wall_duration / 1e6,
        **lat,
    }
    print(json.dumps(result))


def execute_worker(script_path, namespace, peer_iface,
                   count, packet_size, pps, settle_secs):
    cmd = [
        "ip", "netns", "exec", namespace,
        sys.executable, str(script_path),
        "--worker",
        "--iface",       peer_iface,
        "--count",       str(count),
        "--packet-size", str(packet_size),
        "--pps",         str(pps),
        "--settle-secs", str(settle_secs),
    ]
    result = run(cmd, capture_output=True)
    return json.loads(result.stdout.strip())


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _fmt(val, fmt=".2f"):
    return format(val, fmt) if val is not None else "n/a"


def print_result_table(results):
    """Single-size summary table (one row per app)."""
    headers = [
        "name", "pkt_size", "sent", "recv", "loss%",
        "send_pps", "return_pps", "goodput_mbps",
        "lat_avg_us", "lat_p99_us", "cpu%", "rss_mb",
    ]
    rows = []
    for r in results:
        rows.append([
            r["name"],
            str(r.get("packet_size", "?")),
            str(r["sent"]),
            str(r["received"]),
            _fmt(r["loss_percent"]),
            _fmt(r["send_pps"], ".0f"),
            _fmt(r["return_pps"], ".0f"),
            _fmt(r["goodput_mbps"]),
            _fmt(r.get("lat_avg_us")),
            _fmt(r.get("lat_p99_us")),
            _fmt(r["cpu_percent"], ".1f"),
            _fmt(r["rss_mb"], ".1f"),
        ])

    widths = [
        max(len(h), max((len(row[i]) for row in rows), default=0))
        for i, h in enumerate(headers)
    ]
    hdr = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "  ".join("-" * w for w in widths)
    print(hdr)
    print(sep)
    for row in rows:
        print("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))


def print_sweep_table(sweep_results):
    """
    Multi-size / multi-app comparison table.
    Apps are grouped with a separator line between them.
    """
    print("\n=== Sweep Summary ===")
    headers = [
        "name", "pkt_size", "loss%", "send_pps", "goodput_mbps",
        "lat_avg_us", "lat_p50_us", "lat_p99_us", "cpu%", "rss_mb",
    ]
    rows = []
    for r in sweep_results:
        rows.append([
            r["name"],
            str(r.get("packet_size", "?")),
            _fmt(r["loss_percent"]),
            _fmt(r["send_pps"], ".0f"),
            _fmt(r["goodput_mbps"]),
            _fmt(r.get("lat_avg_us")),
            _fmt(r.get("lat_med_us")),
            _fmt(r.get("lat_p99_us")),
            _fmt(r["cpu_percent"], ".1f"),
            _fmt(r["rss_mb"], ".1f"),
        ])

    widths = [
        max(len(h), max((len(row[i]) for row in rows), default=0))
        for i, h in enumerate(headers)
    ]
    hdr = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "  ".join("-" * w for w in widths)
    print(hdr)
    print(sep)

    prev_name = None
    for row, r in zip(rows, sweep_results):
        if prev_name is not None and r["name"] != prev_name:
            print(sep)
        prev_name = r["name"]
        print("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))


def write_csv(sweep_results, path):
    fields = [
        "name", "packet_size", "sent", "received", "loss_percent",
        "send_pps", "return_pps", "goodput_mbps", "send_mbps",
        "lat_samples", "lat_avg_us", "lat_med_us",
        "lat_p95_us", "lat_p99_us", "lat_min_us", "lat_max_us", "lat_stdev_us",
        "cpu_percent", "rss_mb",
    ]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(sweep_results)
    print(f"\nCSV written to: {path}")


# ---------------------------------------------------------------------------
# Target loading
# ---------------------------------------------------------------------------

def parse_custom_target(spec, stdin_text):
    if "::" in spec:
        name, cmd = spec.split("::", 1)
    else:
        name = f"app{abs(hash(spec)) % 10000}"
        cmd = spec
    name = name.strip()
    cmd  = cmd.strip()
    if not name or not cmd:
        raise SystemExit("Each --app value must be 'name::command' or just 'command'.")
    validate_command_template(cmd)
    return AppTarget(name=name, cmd=cmd, stdin=stdin_text or "", description="Custom command")


def load_targets(args):
    targets = [parse_custom_target(spec, args.stdin_text) for spec in args.app]
    if not targets:
        raise SystemExit("Provide at least one app with --app 'name::command'.")
    return targets


# ---------------------------------------------------------------------------
# Core: single (app, packet_size) measurement
# ---------------------------------------------------------------------------

def run_one(target, proc, script_path, args, packet_size):
    cpu_before  = read_proc_cpu(proc.pid)
    wall_before = time.time()

    worker = execute_worker(
        script_path=script_path,
        namespace=args.namespace,
        peer_iface=args.peer_iface,
        count=args.count,
        packet_size=packet_size,
        pps=args.pps,
        settle_secs=args.settle_secs,
    )

    wall_after = time.time()
    cpu_after  = read_proc_cpu(proc.pid)
    rss_mb     = read_proc_rss_mb(proc.pid)

    clk_tck     = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    cpu_seconds = (cpu_after - cpu_before) / clk_tck
    elapsed     = max(wall_after - wall_before, 1e-9)
    cpu_percent = 100.0 * cpu_seconds / elapsed

    return {"name": target.name, "packet_size": packet_size,
            "cpu_percent": cpu_percent, "rss_mb": rss_mb, **worker}


# ---------------------------------------------------------------------------
# Benchmark mode
# ---------------------------------------------------------------------------

def benchmark_mode(args):
    require_root()
    script_path  = Path(__file__).resolve()
    targets      = load_targets(args)
    packet_sizes = args.sweep_sizes if args.sweep_sizes else [args.packet_size]
    is_sweep     = len(packet_sizes) > 1 or len(targets) > 1
    all_results  = []

    setup_netns(args.namespace, args.host_iface, args.peer_iface)
    try:
        for target in targets:
            print(f"\n{'='*60}")
            print(f"  App: {target.name}  —  {target.description}")
            print(f"{'='*60}")

            for pkt_size in packet_sizes:
                print(f"\n--- packet_size={pkt_size}B ---")
                proc, rendered_cmd = launch_app(target, args.host_iface)
                print(f"  cmd: {rendered_cmd}")
                time.sleep(args.app_warmup_secs)

                if proc.poll() is not None:
                    out = collect_output(proc)
                    raise SystemExit(
                        f"App '{target.name}' exited before benchmarking.\n"
                        f"Command: {rendered_cmd}\nOutput:\n{out}"
                    )

                if target.stdin and proc.stdin:
                    proc.stdin.write(target.stdin)
                    proc.stdin.flush()
                    time.sleep(0.5)

                if proc.poll() is not None:
                    out = collect_output(proc)
                    raise SystemExit(
                        f"App '{target.name}' exited after stdin.\n"
                        f"Command: {rendered_cmd}\nOutput:\n{out}"
                    )

                result = run_one(target, proc, script_path, args, pkt_size)
                stop_app(proc)
                out = collect_output(proc)
                result["cmd"]         = rendered_cmd
                result["stdout_tail"] = out
                all_results.append(result)

                # Inline per-run summary
                print(
                    f"  sent={result['sent']}  recv={result['received']}  "
                    f"loss={result['loss_percent']:.2f}%  "
                    f"pps={result['send_pps']:.0f}  "
                    f"goodput={result['goodput_mbps']:.2f}Mbps  "
                    f"lat_avg={_fmt(result.get('lat_avg_us'))}µs  "
                    f"lat_p99={_fmt(result.get('lat_p99_us'))}µs  "
                    f"cpu={result['cpu_percent']:.1f}%  "
                    f"rss={result['rss_mb']:.1f}MB"
                )

                if args.show_app_output and out:
                    print("\n--- app output tail ---")
                    print(out)

        # Final table
        if is_sweep:
            print_sweep_table(all_results)
        else:
            print("\n=== Summary ===")
            print_result_table(all_results)

        if args.json:
            print("\n=== JSON ===")
            print(json.dumps(all_results, indent=2))

        if args.csv:
            write_csv(all_results, args.csv)

    finally:
        cleanup_netns(args.namespace, args.host_iface)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Benchmark DPDK apps over AF_PACKET with a veth pair and network namespace.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single run
  sudo python3 bench.py \\
    --app 'parser::/path/to/app --no-huge -l 0-1 --vdev=net_af_packet0,iface={iface}'

  # Sweep packet sizes and compare two apps, save CSV
  sudo python3 bench.py \\
    --app 'parser::/path/parser --no-huge -l 0-1 --vdev=net_af_packet0,iface={iface}' \\
    --app 'firewall::/path/fw   --no-huge -l 0-1 --vdev=net_af_packet0,iface={iface}' \\
    --sweep-sizes 64 128 256 512 1024 1500 \\
    --count 50000 --csv results.csv

  # Rate-limited send at exactly N pps
  sudo python3 bench.py --app 'fw::...' --pps 100000 --count 200000
""",
    )

    # Hidden — used when the script re-invokes itself inside the netns
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)

    # Shared worker/benchmark args
    parser.add_argument("--iface",       default=DEFAULT_PEER_IFACE)
    parser.add_argument("--count",       type=int,   default=DEFAULT_PACKET_COUNT,
                        help="Packets per run (default: %(default)s)")
    parser.add_argument("--packet-size", type=int,   default=DEFAULT_PACKET_SIZE,
                        help="Packet size in bytes for a single run (default: %(default)s)")
    parser.add_argument("--pps",         type=int,   default=0,
                        help="Send rate in pps; 0 = full speed (default: %(default)s)")
    parser.add_argument("--settle-secs", type=float, default=DEFAULT_SETTLE_SECS,
                        help="Wait time after sending for in-flight packets (default: %(default)s)")

    # App targets
    parser.add_argument("--app", action="append", default=[],
                        help="'name::command'. Use {iface} where the veth iface goes. Repeatable.")
    parser.add_argument("--stdin-text", default="",
                        help="Text written to stdin of every --app after launch.")

    # Multi-size sweep
    parser.add_argument("--sweep-sizes", type=int, nargs="+", metavar="BYTES",
                        help="Test multiple packet sizes, e.g. --sweep-sizes 64 128 256 512 1024 1500")

    # Netns / interface names
    parser.add_argument("--namespace",  default=DEFAULT_NAMESPACE)
    parser.add_argument("--host-iface", default=DEFAULT_HOST_IFACE)
    parser.add_argument("--peer-iface", default=DEFAULT_PEER_IFACE)

    # Timing
    parser.add_argument("--app-warmup-secs", type=float, default=2.0,
                        help="Seconds to wait after app launch before sending (default: %(default)s)")

    # Output
    parser.add_argument("--show-app-output", action="store_true",
                        help="Print the last 120 lines of app stdout/stderr after each run.")
    parser.add_argument("--json", action="store_true",
                        help="Also print all results as a JSON array.")
    parser.add_argument("--csv", metavar="FILE",
                        help="Write all results to a CSV file.")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.worker:
        worker_mode(args)
    else:
        benchmark_mode(args)


if __name__ == "__main__":
    main()