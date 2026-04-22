#!/usr/bin/env python3
# Author: Kevin Leon (original), enhanced for CTF frequency scanning
# Date: 2026
import argparse
import zmq
import signal
import sys
import pmt
import string
import struct
import time
import socket
import select
import threading
import re
import os
from datetime import datetime

try:
    from bridge import bridge
except ImportError:
    bridge = None
    print("[!] bridge module not found — running in ZMQ-only mode.")

DEFAULT_PLUTO_SOURCE = "ip:pluto.local"
DEFAULT_DOWNLINK_ADDRESS = "tcp://127.0.0.1:5009"
DEFAULT_UPLINK_ADDRESS = "tcp://127.0.0.1:5007"
DEFAULT_BRIDGE_HOST = "127.0.0.1"
DEFAULT_BRIDGE_PORT = 5008

DOWNLINK_FREQ = 916000000
DOWNLINK_BW = 250000
DOWNLINK_SF = 7

# Scanning defaults
SCAN_FREQ_START = 900000000   # 900 MHz
SCAN_FREQ_END   = 960000000   # 960 MHz
SCAN_FREQ_STEP  = 1000000     # 1 MHz steps
SCAN_DWELL_TIME = 2.0         # seconds per frequency
SCAN_BANDWIDTHS = [125000, 250000, 500000]
SCAN_SPREAD_FACTORS = [7, 8, 9, 10, 11, 12]

# Common CTF flag patterns (case-insensitive)
FLAG_PATTERNS = [
    rb'(?i)flag\{[^\}]{1,64}\}',
    rb'(?i)ctf\{[^\}]{1,64}\}',
    rb'(?i)bhasia\{[^\}]{1,64}\}',
    rb'(?i)bh\{[^\}]{1,64}\}',
    rb'(?i)key\{[^\}]{1,64}\}',
    rb'(?i)secret\{[^\}]{1,64}\}',
    rb'(?i)hack\{[^\}]{1,64}\}',
]

# PCAP Constants
PCAP_GLOBAL_HEADER_FORMAT = "<LHHIILL"
PCAP_PACKET_HEADER_FORMAT = "<llll"
PCAP_MAGIC_NUMBER = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_MAX_PACKET_SIZE = 0x0000FFFF

# ─────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────

def is_hex_encoded(data: bytes) -> bool:
    if len(data) % 2 != 0:
        return False
    hex_chars = set(string.hexdigits.encode('ascii'))
    return all(byte in hex_chars for byte in data)

def pcap_header(interface=148):
    return struct.pack(PCAP_GLOBAL_HEADER_FORMAT, PCAP_MAGIC_NUMBER,
                       PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR, 0, 0,
                       PCAP_MAX_PACKET_SIZE, interface)

class Pcap:
    def __init__(self, packet: bytes, timestamp_seconds: float):
        self.packet = packet
        self.timestamp_seconds = timestamp_seconds
        self.pcap_packet = self.pack()

    def pack(self):
        int_timestamp = int(self.timestamp_seconds)
        timestamp_offset = int((self.timestamp_seconds - int_timestamp) * 1_000_000)
        return struct.pack(PCAP_PACKET_HEADER_FORMAT, int_timestamp,
                           timestamp_offset, len(self.packet),
                           len(self.packet)) + self.packet

    def get(self):
        return self.pcap_packet

def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_bytes = ' '.join(f"{b:02X}" for b in chunk)
        hex_bytes = hex_bytes.ljust(width * 3)
        ascii_bytes = ''.join(chr(b) if chr(b) in string.printable and b >= 0x20 else '.'
                              for b in chunk)
        lines.append(f"{offset:08X}  {hex_bytes}  {ascii_bytes}")
    return "\n".join(lines)

def hex_char_to_nibble(c: int) -> int:
    if ord('0') <= c <= ord('9'):
        return c - ord('0')
    if ord('A') <= c <= ord('F'):
        return c - ord('A') + 10
    if ord('a') <= c <= ord('f'):
        return c - ord('a') + 10
    return -1

def hex_to_bytes(input_bytes: bytes) -> bytes:
    output = bytearray()
    i = 0
    length = len(input_bytes)
    while i < length:
        if input_bytes[i] == ord(' '):
            i += 1
            continue
        if i + 1 >= length:
            break
        high = hex_char_to_nibble(input_bytes[i])
        low = hex_char_to_nibble(input_bytes[i + 1])
        if high < 0 or low < 0:
            break
        output.append((high << 4) | low)
        i += 2
    return bytes(output)

def hex_string_to_bytes(data_bytes: bytes) -> bytes:
    try:
        return hex_to_bytes(data_bytes)
    except Exception as e:
        print(f"[!] Error converting hex string: {e}")
        return b""

def show_args_config(args):
    print("========== Configuration ==========")
    for k, v in vars(args).items():
        print(f"  {k:25}: {v}")
    print("====================================\n")

# ─────────────────────────────────────────────
# Flag Detection
# ─────────────────────────────────────────────

class FlagDetector:
    """Detects potential CTF flags in received data."""

    def __init__(self, log_file="flags_found.log"):
        self.found_flags = set()
        self.log_file = log_file
        self.lock = threading.Lock()
        # Precompile regex patterns
        self.compiled_patterns = [re.compile(p) for p in FLAG_PATTERNS]

    def check_printable_string(self, data: bytes) -> list:
        """Extract printable ASCII strings of length 1-10 from data."""
        results = []
        # Find all runs of printable ASCII
        printable_runs = re.findall(rb'[\x20-\x7e]{1,10}', data)
        for run in printable_runs:
            if len(run) >= 1:
                results.append(run)
        return results

    def check_flag_patterns(self, data: bytes) -> list:
        """Check data against known CTF flag patterns."""
        matches = []
        for pattern in self.compiled_patterns:
            for m in pattern.finditer(data):
                matches.append(m.group())
        return matches

    def analyze(self, data: bytes, freq_hz: int, bw_hz: int, sf: int) -> list:
        """
        Analyze a received packet for potential flags.
        Returns list of found flag candidates.
        """
        candidates = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        freq_mhz = freq_hz / 1e6
        bw_khz = bw_hz / 1e3

        # 1. Check for regex flag patterns (highest confidence)
        pattern_matches = self.check_flag_patterns(data)
        for match in pattern_matches:
            entry = {
                "type": "PATTERN_MATCH",
                "value": match,
                "freq_mhz": freq_mhz,
                "bw_khz": bw_khz,
                "sf": sf,
                "timestamp": timestamp,
                "raw_hex": data.hex(),
                "confidence": "HIGH"
            }
            candidates.append(entry)

        # 2. Check for printable ASCII strings (potential flags)
        printable_strings = self.check_printable_string(data)
        for s in printable_strings:
            # Skip if already matched by pattern
            if any(s in m for m in pattern_matches):
                continue
            entry = {
                "type": "PRINTABLE_STRING",
                "value": s,
                "freq_mhz": freq_mhz,
                "bw_khz": bw_khz,
                "sf": sf,
                "timestamp": timestamp,
                "raw_hex": data.hex(),
                "confidence": "MEDIUM"
            }
            candidates.append(entry)

        # 3. Short payloads (1-10 bytes) are always suspicious in this contest
        if 1 <= len(data) <= 10:
            entry = {
                "type": "SHORT_PAYLOAD",
                "value": data,
                "freq_mhz": freq_mhz,
                "bw_khz": bw_khz,
                "sf": sf,
                "timestamp": timestamp,
                "raw_hex": data.hex(),
                "confidence": "LOW"
            }
            candidates.append(entry)

        # Log and display
        with self.lock:
            for c in candidates:
                val = c["value"]
                if isinstance(val, bytes):
                    val_str = val.decode("ascii", errors="replace")
                else:
                    val_str = str(val)

                flag_key = f"{val_str}@{freq_mhz}MHz"
                if flag_key not in self.found_flags:
                    self.found_flags.add(flag_key)
                    self._print_flag(c, val_str)
                    self._log_flag(c, val_str)

        return candidates

    def _print_flag(self, candidate, val_str):
        conf = candidate["confidence"]
        color = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[96m"}.get(conf, "")
        reset = "\033[0m"
        print(f"\n{color}{'='*60}")
        print(f"  🚩 POTENTIAL FLAG DETECTED [{conf} confidence]")
        print(f"  Type      : {candidate['type']}")
        print(f"  Value     : {val_str}")
        print(f"  Hex       : {candidate['raw_hex']}")
        print(f"  Frequency : {candidate['freq_mhz']:.3f} MHz")
        print(f"  Bandwidth : {candidate['bw_khz']:.0f} kHz")
        print(f"  SF        : {candidate['sf']}")
        print(f"  Time      : {candidate['timestamp']}")
        print(f"{'='*60}{reset}\n")

    def _log_flag(self, candidate, val_str):
        try:
            with open(self.log_file, "a") as f:
                f.write(f"[{candidate['timestamp']}] "
                        f"[{candidate['confidence']}] "
                        f"[{candidate['type']}] "
                        f"Freq={candidate['freq_mhz']:.3f}MHz "
                        f"BW={candidate['bw_khz']:.0f}kHz "
                        f"SF={candidate['sf']} "
                        f"Value=\"{val_str}\" "
                        f"Hex={candidate['raw_hex']}\n")
        except Exception as e:
            print(f"[!] Log write error: {e}")

    def print_summary(self):
        print(f"\n{'='*60}")
        print(f"  FLAG DETECTION SUMMARY — {len(self.found_flags)} unique candidates found")
        print(f"{'='*60}")
        for f in sorted(self.found_flags):
            print(f"  • {f}")
        print(f"{'='*60}\n")


# ─────────────────────────────────────────────
# Controller (original + scanning mode)
# ─────────────────────────────────────────────

class Controller:
    def __init__(self, args):
        self.args = args
        self.rxctx = None
        self.rxsock = None
        self.txctx = None
        self.txsock = None
        self.tb = None
        self.running = False
        self.f_output = None
        self.f_pcap_output = None
        self.bridge_sock = None
        self.last_reconnect_time = 0

        # Scanning state
        self.current_freq = int(args.frequency)
        self.current_bw = int(args.bandwidth)
        self.current_sf = int(args.spread_factor)
        self.scan_lock = threading.Lock()

        # Flag detector
        self.flag_detector = FlagDetector(
            log_file=args.flag_log if hasattr(args, 'flag_log') and args.flag_log else "flags_found.log"
        )

    # ── File I/O ──

    def file_write_frame(self, data: bytes):
        if self.f_output is not None:
            ts = time.time_ns()
            length = len(data)
            header = struct.pack("<QH", ts, length)
            self.f_output.write(header)
            self.f_output.write(data)
            self.f_output.flush()

    def file_open(self):
        self.f_output = open(self.args.output_file, "wb")

    def file_close(self):
        if self.f_output:
            self.f_output.close()

    def pcap_write_frame(self, data: bytes):
        if self.f_pcap_output is not None:
            pcap_packet = Pcap(data, time.time()).get()
            self.f_pcap_output.write(pcap_packet)
            self.f_pcap_output.flush()

    def pcap_open(self):
        self.f_pcap_output = open(self.args.pcap_output_file, "wb")
        self.f_pcap_output.write(pcap_header())
        self.f_pcap_output.flush()

    def pcap_close(self):
        if self.f_pcap_output:
            self.f_pcap_output.close()

    # ── Setup ──

    def setup(self):
        if bridge is not None:
            self.tb = bridge()
            self.tb.set_frequency(float(self.args.frequency))
            self.tb.set_bandwidth(int(self.args.bandwidth))
            self.tb.set_zmq_address(self.args.downlink_address)
            self.tb.set_pluto_source(str(self.args.pluto_address))
            self.tb.set_tx_zmq_address(str(self.args.uplink_address))
        else:
            print("[!] Warning: bridge module not found. Running in ZMQ-only mode.")

        if self.args.output_file:
            self.file_open()
        if self.args.pcap_output_file:
            self.pcap_open()

    # ── SDR TX ──

    def send_to_sdr(self, data):
        print(f"\nSending payload to radio: {data.hex()}")
        (header, frequency, bandwidth, spreadfactor, payload_len) = struct.unpack_from(">HIHHH", data)
        mhz_freq = frequency / 100
        hz_freq = int(mhz_freq * 1000000)
        khz_bw = bandwidth / 100
        hz_bw = int(khz_bw * 1000)
        payload = data[12:-3]
        print(f"FQ: {hz_freq} | BW: {hz_bw} | SF: {spreadfactor} | "
              f"Payload len: {payload_len} Payload: {payload}")

        self.tb.set_tx_frequency(hz_freq)
        self.tb.set_tx_bandwidth(hz_bw)
        self.tb.set_tx_spread_factor(spreadfactor)

        pdu_bytes = pmt.serialize_str(pmt.intern(payload.hex()))
        print(f"[+] Sending payload via ZMQ...")
        try:
            self.txsock.send(pdu_bytes, flags=zmq.NOBLOCK)
        except zmq.error.Again:
            print("[!] TX Queue full. Packet dropped.")

    # ── Bridge (GTK GUI) ──

    def connect_to_bridge(self):
        now = time.time()
        if self.bridge_sock is None and (now - self.last_reconnect_time) > 2:
            self.last_reconnect_time = now
            try:
                self.bridge_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.bridge_sock.settimeout(0.2)
                self.bridge_sock.connect((self.args.bridge_host, self.args.bridge_port))
                self.bridge_sock.setblocking(False)
                print(f"[*] Connected to C GUI Bridge at "
                      f"{self.args.bridge_host}:{self.args.bridge_port}")
            except (ConnectionRefusedError, socket.error, socket.timeout):
                self.bridge_sock = None

    def send_to_bridge(self, data: bytes):
        if self.bridge_sock:
            payload = (bytes([0x64, 0x83]) +
                       struct.pack(">B", len(data)) +
                       data +
                       bytes([0x64, 0x69]))
            try:
                self.bridge_sock.sendall(payload)
            except socket.error:
                print("[!] Bridge connection lost")
                self.bridge_sock.close()
                self.bridge_sock = None

    def parse_bridge_data(self, data: bytes):
        if len(data) < 12:
            return
        try:
            header = struct.unpack_from(">H", data)[0]
            if header == 0x6483:
                (header, frequency, bandwidth, spreadfactor, tail) = \
                    struct.unpack_from(">HIHHH", data)
                if header == 0x6483 and tail == 0x6469:
                    pass  # Config packet ack
            elif header == 0x6383:
                self.send_to_sdr(data)
        except struct.error as e:
            print(f"[!] Parsing error: {e}")

    # ── Frequency tuning ──

    def tune_radio(self, freq_hz, bw_hz, sf):
        """Change the SDR RX frequency, bandwidth, and spreading factor."""
        with self.scan_lock:
            self.current_freq = freq_hz
            self.current_bw = bw_hz
            self.current_sf = sf
        if self.tb:
            try:
                self.tb.set_frequency(float(freq_hz))
                self.tb.set_bandwidth(int(bw_hz))
                # set SF if the bridge exposes it for RX
                if hasattr(self.tb, 'set_spread_factor'):
                    self.tb.set_spread_factor(sf)
                elif hasattr(self.tb, 'set_rx_spread_factor'):
                    self.tb.set_rx_spread_factor(sf)
            except Exception as e:
                print(f"[!] Tune error: {e}")

    # ── Start / Stop ──

    def start(self):
        self.running = True
        if self.tb:
            self.tb.start()
            print("[+] GNU Radio flowgraph started")

        # RX ZMQ
        self.rxctx = zmq.Context()
        self.rxsock = self.rxctx.socket(zmq.SUB)
        self.rxsock.connect(self.args.downlink_address)
        self.rxsock.setsockopt(zmq.SUBSCRIBE, b"")

        # TX ZMQ
        self.txctx = zmq.Context()
        self.txsock = self.txctx.socket(zmq.PUSH)
        self.txsock.connect(self.args.uplink_address)
        self.txsock.setsockopt(zmq.LINGER, 0)
        self.txsock.setsockopt(zmq.RCVHWM, 20)
        self.txsock.setsockopt(zmq.SNDHWM, 20)

        print(f"[*] Subscribed to {self.args.downlink_address} "
              f"(Mode: {self.args.mode.upper()})")

    def stop(self):
        self.running = False
        print("\n[!] Stopping processes...")
        if self.tb:
            self.tb.stop()
            self.tb.wait()
        if self.rxsock: self.rxsock.close(0)
        if self.rxctx: self.rxctx.term()
        if self.txsock: self.txsock.close(0)
        if self.txctx: self.txctx.term()
        if self.bridge_sock: self.bridge_sock.close()
        self.file_close()
        self.pcap_close()

        # Print summary of found flags
        self.flag_detector.print_summary()
        print("[*] Clean exit")

    # ── Threads ──

    def thread_radio_rx(self):
        """Receive packets from GNU Radio and analyze for flags."""
        while self.running:
            try:
                if self.rxsock.poll(500, zmq.POLLIN):
                    raw_zmq = self.rxsock.recv()
                    processed = (hex_string_to_bytes(raw_zmq)
                                 if self.args.mode == "tc" else raw_zmq)

                    if processed:
                        with self.scan_lock:
                            freq = self.current_freq
                            bw = self.current_bw
                            sf = self.current_sf

                        print(f"\n=========== {self.args.mode.upper()} PACKET ===========")
                        print(f"Frequency : {freq/1e6:.3f} MHz | "
                              f"BW: {bw/1e3:.0f} kHz | SF: {sf}")
                        print(f"Length    : {len(processed)}")
                        print(hexdump(processed))

                        # Flag analysis
                        self.flag_detector.analyze(processed, freq, bw, sf)

                        # Forward to bridge / files
                        self.send_to_bridge(processed)
                        self.file_write_frame(processed)
                        self.pcap_write_frame(processed)

            except zmq.ZMQError:
                pass

    def thread_bridge_rx(self):
        """Receive commands from the C GTK GUI."""
        while self.running:
            self.connect_to_bridge()
            if self.bridge_sock:
                try:
                    readable, _, _ = select.select([self.bridge_sock], [], [], 0.5)
                    if readable:
                        bridge_data = self.bridge_sock.recv(1024)
                        if not bridge_data:
                            print("[!] Bridge disconnected")
                            self.bridge_sock.close()
                            self.bridge_sock = None
                        else:
                            self.parse_bridge_data(bridge_data)
                except (socket.error, select.error):
                    self.bridge_sock = None
            else:
                time.sleep(1)

    def thread_freq_scanner(self):
        """
        Sweep frequencies from scan_start to scan_end.
        For each frequency, try each bandwidth and spreading factor combo.
        Dwell on each combination for scan_dwell seconds.
        """
        freq_start = int(self.args.scan_start)
        freq_end = int(self.args.scan_end)
        freq_step = int(self.args.scan_step)

        bandwidths = [int(b) for b in self.args.scan_bw.split(",")]
        spread_factors = [int(s) for s in self.args.scan_sf.split(",")]
        dwell = float(self.args.scan_dwell)

        total_combos = 0
        for f in range(freq_start, freq_end + 1, freq_step):
            for bw in bandwidths:
                for sf in spread_factors:
                    total_combos += 1

        print(f"\n[SCANNER] Starting frequency sweep")
        print(f"  Range     : {freq_start/1e6:.1f} — {freq_end/1e6:.1f} MHz "
              f"(step {freq_step/1e6:.3f} MHz)")
        print(f"  Bandwidths: {[b/1e3 for b in bandwidths]} kHz")
        print(f"  SFs       : {spread_factors}")
        print(f"  Dwell     : {dwell}s per combo")
        print(f"  Total     : {total_combos} combinations per sweep\n")

        sweep_count = 0
        while self.running:
            sweep_count += 1
            print(f"\n[SCANNER] ═══ Sweep #{sweep_count} starting ═══")
            combo_idx = 0

            for freq_hz in range(freq_start, freq_end + 1, freq_step):
                if not self.running:
                    break
                for bw in bandwidths:
                    if not self.running:
                        break
                    for sf in spread_factors:
                        if not self.running:
                            break

                        combo_idx += 1
                        freq_mhz = freq_hz / 1e6
                        bw_khz = bw / 1e3

                        print(f"[SCANNER] [{combo_idx}/{total_combos}] "
                              f"Tuning → {freq_mhz:.3f} MHz | "
                              f"BW {bw_khz:.0f} kHz | SF{sf} "
                              f"(dwell {dwell}s)")

                        self.tune_radio(freq_hz, bw, sf)
                        time.sleep(dwell)

            print(f"[SCANNER] ═══ Sweep #{sweep_count} complete ═══")
            self.flag_detector.print_summary()

    # ── Main Run ──

    def run(self):
        def handler(sig, frame):
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

        self.setup()
        self.start()

        # Always start the RX and bridge threads
        t_rx = threading.Thread(target=self.thread_radio_rx, daemon=True)
        t_bridge = threading.Thread(target=self.thread_bridge_rx, daemon=True)
        t_rx.start()
        t_bridge.start()

        # Start scanner thread if in scan mode
        if self.args.scan:
            t_scanner = threading.Thread(target=self.thread_freq_scanner, daemon=True)
            t_scanner.start()
            print("[+] Frequency scanner thread started")
        else:
            print("[*] Running in fixed-frequency mode "
                  f"({self.current_freq/1e6:.3f} MHz)")

        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop()


# ─────────────────────────────────────────────
# Main / Argument Parsing
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="pylora_rx",
        description="GNU Radio LoRa Receiver with CTF Frequency Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fixed frequency (original behavior):
  python3 worker.py -f 916000000 -bw 250000 -sf 7

  # Scan 900-960 MHz with all SF and BW combos:
  python3 worker.py --scan

  # Scan custom range, fast dwell, specific SFs:
  python3 worker.py --scan --scan-start 915000000 --scan-end 928000000 \\
      --scan-step 500000 --scan-dwell 1.0 --scan-sf 7,8,9 \\
      --scan-bw 125000,250000 -pcap capture.pcap

  # Scan and save all packets to pcap:
  python3 worker.py --scan -pcap lora_scan.pcap --flag-log my_flags.log
        """
    )

    # Original arguments
    parser.add_argument("-f", "--frequency", default=DOWNLINK_FREQ,
                        help="Fixed RX frequency in Hz (default: 916 MHz)")
    parser.add_argument("-bw", "--bandwidth", default=DOWNLINK_BW,
                        help="RX bandwidth in Hz (default: 250000)")
    parser.add_argument("-sf", "--spread-factor", default=DOWNLINK_SF,
                        help="Spreading factor (default: 7)")
    parser.add_argument("-da", "--downlink-address", default=DEFAULT_DOWNLINK_ADDRESS)
    parser.add_argument("-ua", "--uplink-address", default=DEFAULT_UPLINK_ADDRESS)
    parser.add_argument("-o", "--output-file",
                        help="Raw binary output file")
    parser.add_argument("-pcap", "--pcap-output-file",
                        help="PCAP output file (viewable in Wireshark)")
    parser.add_argument("-p", "--pluto-address", default=DEFAULT_PLUTO_SOURCE)
    parser.add_argument("-m", "--mode", choices=["tm", "tc"], default="tm",
                        help="tm=telemetry (raw), tc=telecommand (hex-encoded)")
    parser.add_argument("--bridge-host", default=DEFAULT_BRIDGE_HOST)
    parser.add_argument("--bridge-port", type=int, default=DEFAULT_BRIDGE_PORT)

    # Scanner arguments
    scanner = parser.add_argument_group("Frequency Scanner Options")
    scanner.add_argument("--scan", action="store_true",
                         help="Enable frequency scanning mode")
    scanner.add_argument("--scan-start", type=int, default=SCAN_FREQ_START,
                         help="Scan start frequency in Hz (default: 900 MHz)")
    scanner.add_argument("--scan-end", type=int, default=SCAN_FREQ_END,
                         help="Scan end frequency in Hz (default: 960 MHz)")
    scanner.add_argument("--scan-step", type=int, default=SCAN_FREQ_STEP,
                         help="Scan step in Hz (default: 1 MHz)")
    scanner.add_argument("--scan-dwell", type=float, default=SCAN_DWELL_TIME,
                         help="Dwell time per combo in seconds (default: 2.0)")
    scanner.add_argument("--scan-bw", type=str,
                         default=",".join(str(b) for b in SCAN_BANDWIDTHS),
                         help="Comma-separated bandwidths to scan (default: 125000,250000,500000)")
    scanner.add_argument("--scan-sf", type=str,
                         default=",".join(str(s) for s in SCAN_SPREAD_FACTORS),
                         help="Comma-separated spreading factors to scan (default: 7,8,9,10,11,12)")

    # Flag detection
    parser.add_argument("--flag-log", default="flags_found.log",
                        help="File to log detected flags (default: flags_found.log)")

    args = parser.parse_args()
    show_args_config(args)

    ctrl = Controller(args)
    ctrl.run()


if __name__ == "__main__":
    main()
