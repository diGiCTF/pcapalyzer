#!/usr/bin/env python3
"""
pcapalyzer_light.py
Lightweight PCAP analyzer that generates human-readable reports WITHOUT any LLM step.

How to run:
  $ python3 pcapalyzer_light.py

What it does:
  * Auto-discovers *.pcap and *.pcapng files in the current directory (non-recursive)
  * For each file, creates ./reports/<pcap_basename>/ with:
      - <pcap_basename>_report.txt  => main report (no LLM section)
      - top_talkers.csv             => IP talker counts
      - dns_queries.csv             => DNS query log
      - http_hosts.csv              => HTTP host log
      - tls_sni.csv                 => TLS SNI server names
  * Uses tshark/capinfos if available; degrades gracefully with helpful notes

The ONLY difference from the full version is that the "LLM Observation" section is omitted.

Created by diGi - reach me on discord: 0x3444
"""

import os
import re
import csv
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional

BANNER = "Created by diGi — reach me on Discord: 0x3444"

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def run_cmd(cmd: List[str], timeout: int = 90) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"

def find_pcaps() -> List[Path]:
    here = Path(".")
    pcaps = list(here.glob("*.pcap")) + list(here.glob("*.pcapng"))
    return sorted(pcaps)

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def write_file(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", errors="ignore")

def write_csv(path: Path, rows: List[List[str]], header: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if header:
            w.writerow(header)
        w.writerows(rows)

def capinfos_summary(pcap: Path) -> str:
    capinfos_path = which("capinfos")
    if not capinfos_path:
        return "[capinfos not found] Install Wireshark CLI tools to include file metadata (capinfos)."
    code, out, err = run_cmd([capinfos_path, str(pcap)])
    if code != 0:
        return f"[capinfos error]\n{err.strip()}"
    return out.strip()

def tshark_available() -> bool:
    return which("tshark") is not None

def tshark_fields(pcap: Path, display_filter: str, fields: List[str]) -> List[List[str]]:
    tshark = which("tshark")
    if not tshark:
        return []
    cmd = [tshark, "-r", str(pcap), "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    # Avoid adding headers; empty fields become blank columns
    code, out, err = run_cmd(cmd, timeout=180)
    if code != 0:
        return []
    rows = []
    for line in out.splitlines():
        # Fields are tab-separated by default
        cols = line.split("\t")
        # Pad to consistent width
        while len(cols) < len(fields):
            cols.append("")
        rows.append(cols[:len(fields)])
    return rows

def tshark_stat_block(pcap: Path, stat_what: str) -> str:
    """
    stat_what examples:
      "io,phs"        -> Protocol hierarchy
      "conv,ip"       -> IP conversations
      "endpoints,ip"  -> IP endpoints
    """
    tshark = which("tshark")
    if not tshark:
        return "[tshark not found]"
    cmd = [tshark, "-r", str(pcap), "-q", "-z", stat_what]
    code, out, err = run_cmd(cmd, timeout=240)
    if code != 0:
        return f"[tshark -z {stat_what} error]\n{err.strip()}"
    return out.strip()

def top_talkers(pcap: Path) -> List[Tuple[str, int]]:
    rows = tshark_fields(pcap, "ip.src", ["ip.src"])
    counts = {}
    for r in rows:
        ip = r[0].strip()
        if ip:
            counts[ip] = counts.get(ip, 0) + 1
    # sort by count desc
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)

def dns_queries(pcap: Path) -> List[List[str]]:
    # query (not response)
    return tshark_fields(pcap, "dns.flags.response == 0", ["frame.time", "ip.src", "dns.qry.name"])

def http_hosts(pcap: Path) -> List[List[str]]:
    return tshark_fields(pcap, "http.host", ["frame.time", "ip.dst", "http.host"])

def tls_sni(pcap: Path) -> List[List[str]]:
    # Server Name Indication
    return tshark_fields(pcap, "tls.handshake.extensions_server_name", ["frame.time", "ip.dst", "tls.handshake.extensions_server_name"])

def count_filter(pcap: Path, display_filter: str) -> int:
    rows = tshark_fields(pcap, display_filter, ["frame.number"])
    return len(rows)

def average_dns_txt_len(pcap: Path) -> float:
    rows = tshark_fields(pcap, "dns.txt", ["dns.txt"])
    if not rows:
        return 0.0
    lengths = [len(r[0]) for r in rows if r and r[0]]
    return (sum(lengths) / len(lengths)) if lengths else 0.0

def syn_vs_synack_ratio(pcap: Path) -> Tuple[int, int]:
    syn = count_filter(pcap, "tcp.flags.syn == 1 and tcp.flags.ack == 0")
    synack = count_filter(pcap, "tcp.flags.syn == 1 and tcp.flags.ack == 1")
    return syn, synack

def detect_suspicious(pcap: Path) -> List[str]:
    sus = []
    # Lots of outbound DNS TXT or large TXT payloads
    txt_count = count_filter(pcap, "dns.txt")
    if txt_count >= 20:
        avg_len = average_dns_txt_len(pcap)
        sus.append(f"High DNS TXT activity: {txt_count} records (avg length ~{avg_len:.1f} chars). Possible DNS-based exfiltration.")
    # Many ICMP echo requests
    icmp_req = count_filter(pcap, "icmp.type == 8")
    if icmp_req >= 100:
        sus.append(f"Unusual ICMP echo volume: {icmp_req} requests. Could indicate covert channel or scanning.")
    # SYN flood-ish pattern
    syn, synack = syn_vs_synack_ratio(pcap)
    if syn >= 200 and synack == 0:
        sus.append(f"Many TCP SYNs ({syn}) but zero SYN-ACKs. Potential scanning or blocked egress.")
    elif synack > 0 and syn / max(1, synack) >= 5:
        sus.append(f"High SYN:SYN-ACK ratio ({syn}:{synack}). Possible scanning or connectivity issues.")
    # Non-standard high ports targeted frequently
    high_ports = tshark_fields(pcap, "tcp && tcp.dstport >= 49152", ["tcp.dstport"])
    if len(high_ports) >= 200:
        sus.append(f"Frequent connections to ephemeral/high ports: {len(high_ports)} frames.")
    return sus

def write_main_report(report_path: Path, pcap: Path, sections: List[Tuple[str, str]]) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("=" * 80)
    lines.append(f"PCAPALYZER LIGHT REPORT — {pcap.name}")
    lines.append(f"Generated: {now}")
    lines.append(BANNER)
    lines.append("=" * 80)
    lines.append("")

    for title, body in sections:
        lines.append(f"# {title}")
        lines.append(body if body.strip() else "[No data]")
        lines.append("")
    # Explicitly mention no LLM here (difference from full version)
    lines.append("# LLM Observation")
    lines.append("(omitted in pcapalyzer_light — no LLM is used)")
    lines.append("")
    write_file(report_path, "\n".join(lines))

def main():
    pcaps = find_pcaps()
    if not pcaps:
        print("No .pcap or .pcapng files found in the current directory.")
        print("Place your capture file beside this script and run again.")
        return

    print(BANNER)
    print("pcapalyzer_light: starting analysis (no LLM)...")

    have_tshark = tshark_available()
    if not have_tshark:
        print("[!] tshark not found. Install Wireshark CLI to enable deep analysis.")
        print("    On Debian/Ubuntu: sudo apt-get update && sudo apt-get install tshark")
    if not which("capinfos"):
        print("[!] capinfos not found. Install Wireshark CLI to include file metadata.")

    reports_root = Path("reports")
    ensure_dir(reports_root)

    for pcap in pcaps:
        base = pcap.stem
        outdir = reports_root / base
        ensure_dir(outdir)
        print(f"Analyzing {pcap.name} -> {outdir}/")

        # 1) File metadata
        meta = capinfos_summary(pcap)

        # 2) Protocol hierarchy / conversations / endpoints
        phs = tshark_stat_block(pcap, "io,phs") if have_tshark else "[tshark unavailable]"
        conv = tshark_stat_block(pcap, "conv,ip") if have_tshark else "[tshark unavailable]"
        endp = tshark_stat_block(pcap, "endpoints,ip") if have_tshark else "[tshark unavailable]"

        # 3) Extractions -> CSV outputs
        talkers = top_talkers(pcap) if have_tshark else []
        write_csv(outdir / "top_talkers.csv",
                  [[ip, str(cnt)] for ip, cnt in talkers],
                  ["ip", "frames"])

        dns = dns_queries(pcap) if have_tshark else []
        write_csv(outdir / "dns_queries.csv", dns, ["time", "src_ip", "query"])

        http = http_hosts(pcap) if have_tshark else []
        write_csv(outdir / "http_hosts.csv", http, ["time", "dst_ip", "host"])

        sni = tls_sni(pcap) if have_tshark else []
        write_csv(outdir / "tls_sni.csv", sni, ["time", "dst_ip", "sni"])

        # 4) Quick counters & suspicious notes
        icmp_req = count_filter(pcap, "icmp.type == 8") if have_tshark else 0
        dns_txt = count_filter(pcap, "dns.txt") if have_tshark else 0
        syn, synack = syn_vs_synack_ratio(pcap) if have_tshark else (0, 0)
        sus = detect_suspicious(pcap) if have_tshark else ["tshark unavailable; skipping heuristic checks."]

        counters_block = [
            f"ICMP echo requests: {icmp_req}",
            f"DNS TXT records:    {dns_txt}",
            f"TCP SYN:SYN-ACK:     {syn}:{synack}",
            f"Top talkers saved:   {len(talkers)} (see top_talkers.csv)",
            f"DNS queries saved:   {len(dns)} (see dns_queries.csv)",
            f"HTTP hosts saved:    {len(http)} (see http_hosts.csv)",
            f"TLS SNI saved:       {len(sni)} (see tls_sni.csv)",
        ]
        counters_text = "\n".join(counters_block)

        sus_text = "- " + "\n- ".join(sus) if sus else "No obvious issues detected by heuristics."

        # 5) Assemble report
        sections = [
            ("File Metadata (capinfos)", meta),
            ("Protocol Hierarchy (tshark -z io,phs)", phs),
            ("IP Conversations (tshark -z conv,ip)", conv),
            ("IP Endpoints (tshark -z endpoints,ip)", endp),
            ("Quick Counters", counters_text),
            ("Suspicious Indicators (heuristics)", sus_text),
        ]

        report_path = outdir / f"{base}_report.txt"
        write_main_report(report_path, pcap, sections)
        print(f"Done: {report_path}")

    print("All reports generated in ./reports/")
    print("pcapalyzer_light complete. (No LLM sections included.)")

if __name__ == "__main__":
    main()
