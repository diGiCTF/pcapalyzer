
#!/usr/bin/env python3
"""
pcapalyzer_light.py — lightweight PCAP analyzer (no LLM required)

Usage:
    python3 pcapalyzer_light.py <pcap_file>

What it does (quick):
- Validates dependencies (tshark, capinfos)
- Gathers capture metadata (packets, duration, start/end time, interfaces)
- Protocol hierarchy summary
- Top talkers (IP pairs) and IP endpoints
- TCP/UDP conversations
- DNS queries & answers (unique; counts)
- HTTP requests (host, method, URI)
- TLS SNI (server names) and ciphers (best-effort, if fields exist)
- JA3/JA3S (best-effort, if tshark supports the fields)
- Produces a Markdown report alongside the PCAP
- No LLM 'Observation' section by design

Created by diGi - reach me on discord: 0x3444
"""

import argparse
import os
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Dict, Optional


BANNER = "Created by diGi - reach me on discord: 0x3444"


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def run_cmd(cmd: List[str], timeout: int = 180) -> Tuple[int, str, str]:
    """Run a subprocess and return (code, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return 124, "", f"Timeout running: {' '.join(cmd)}"
    except Exception as e:
        return 1, "", f"Error running {' '.join(cmd)}: {e}"


def require_deps() -> None:
    missing = []
    for dep in ["tshark", "capinfos"]:
        if not which(dep):
            missing.append(dep)
    if missing:
        print("Dependency check failed.\n", file=sys.stderr)
        if "tshark" in missing:
            print("- tshark is required. Install Wireshark/tshark (e.g., sudo apt install tshark).", file=sys.stderr)
        if "capinfos" in missing:
            print("- capinfos is recommended (comes with Wireshark). Install with your package manager.", file=sys.stderr)
        sys.exit(1)


def capinfos_metadata(pcap: Path) -> str:
    code, out, err = run_cmd(["capinfos", "-Tmru", str(pcap)])
    if code != 0:
        return f"capinfos failed: {err.strip()}"
    return out.strip()


def tshark_protocol_hierarchy(pcap: Path) -> str:
    code, out, err = run_cmd(["tshark", "-r", str(pcap), "-q", "-z", "io,phs"])
    if code != 0:
        return f"tshark protocol hierarchy failed: {err.strip()}"
    return out.strip()


def tshark_endpoints(pcap: Path) -> str:
    code, out, err = run_cmd(["tshark", "-r", str(pcap), "-q", "-z", "endpoints,ip"])
    if code != 0:
        return f"tshark endpoints failed: {err.strip()}"
    return out.strip()


def tshark_conversations(pcap: Path, layer: str) -> str:
    # layer in {"ip","tcp","udp"}
    code, out, err = run_cmd(["tshark", "-r", str(pcap), "-q", "-z", f"conv,{layer}"])
    if code != 0:
        return f"tshark conversations ({layer}) failed: {err.strip()}"
    return out.strip()


def tshark_fields(pcap: Path, display_filter: str, fields: List[str]) -> List[Tuple[str, ...]]:
    cmd = ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd.extend(["-e", f])
    cmd.extend(["-E", "separator=|", "-E", "occurrence=f"])
    code, out, err = run_cmd(cmd)
    if code != 0:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split("|")
        rows.append(tuple(parts))
    return rows


def summarize_top_talkers(pcap: Path, limit: int = 20) -> str:
    # Use ip.src/ip.dst pairs
    rows = tshark_fields(pcap, "ip", ["ip.src", "ip.dst"])
    ctr = Counter()
    for src, dst in rows:
        if not src or not dst:
            continue
        pair = f"{src} → {dst}"
        ctr[pair] += 1
    lines = ["Pair,Packets"]
    for pair, count in ctr.most_common(limit):
        lines.append(f"{pair},{count}")
    return "\n".join(lines)


def summarize_dns(pcap: Path) -> Tuple[str, str]:
    # Queries
    q_rows = tshark_fields(pcap, "dns.flags.response==0", ["dns.id", "ip.src", "dns.qry.name"])
    query_ctr = Counter([r[2] for r in q_rows if len(r) >= 3 and r[2]])
    q_lines = ["Domain,Count"]
    for dom, c in query_ctr.most_common(50):
        q_lines.append(f"{dom},{c}")

    # Answers (A/AAAA/TXT/CNAME) best-effort
    a_rows = tshark_fields(pcap, "dns.flags.response==1", ["dns.resp.name", "dns.a", "dns.aaaa", "dns.cname", "dns.txt"])
    a_lines = ["Name,A,AAAA,CNAME,TXT"]
    for r in a_rows[:1000]:
        name = r[0] if len(r) > 0 else ""
        a = r[1] if len(r) > 1 else ""
        aaaa = r[2] if len(r) > 2 else ""
        cname = r[3] if len(r) > 3 else ""
        txt = r[4] if len(r) > 4 else ""
        if any([name, a, aaaa, cname, txt]):
            a_lines.append(f"{name},{a},{aaaa},{cname},{txt}")
    return "\n".join(q_lines), "\n".join(a_lines)


def summarize_http(pcap: Path) -> str:
    rows = tshark_fields(pcap, "http.request", ["ip.src", "http.host", "http.request.method", "http.request.uri"])
    lines = ["SrcIP,Host,Method,URI"]
    for r in rows[:2000]:
        src = r[0] if len(r) > 0 else ""
        host = r[1] if len(r) > 1 else ""
        method = r[2] if len(r) > 2 else ""
        uri = r[3] if len(r) > 3 else ""
        if any([host, method, uri]):
            lines.append(f"{src},{host},{method},{uri}")
    return "\n".join(lines)


def summarize_tls(pcap: Path) -> str:
    # Try to pull SNI and selected cipher if fields exist
    rows = tshark_fields(pcap, "tls.handshake.extensions_server_name || ssl.handshake.extensions_server_name", [
        "ip.dst",
        "tls.handshake.extensions_server_name",
        "ssl.handshake.extensions_server_name",
        "tls.handshake.ciphersuite",
        "ssl.handshake.ciphersuite"
    ])
    lines = ["DstIP,SNI,Cipher"]
    for r in rows[:2000]:
        dst = r[0] if len(r) > 0 else ""
        sni = r[1] or (r[2] if len(r) > 2 else "") if len(r) > 1 else ""
        cipher = r[3] or (r[4] if len(r) > 4 else "") if len(r) > 3 else ""
        if dst or sni:
            lines.append(f"{dst},{sni},{cipher}")
    return "\n".join(lines)


def summarize_ja3(pcap: Path) -> str:
    # Best-effort JA3 / JA3S (requires tshark with those fields)
    rows = tshark_fields(pcap, "tls", [
        "ip.src", "ip.dst",
        "tls.handshake.ja3",
        "tls.handshake.ja3s"
    ])
    if not rows:
        return "JA3 fields not available in this tshark build or no TLS traffic found."
    lines = ["SrcIP,DstIP,JA3,JA3S"]
    for r in rows[:2000]:
        src = r[0] if len(r) > 0 else ""
        dst = r[1] if len(r) > 1 else ""
        ja3 = r[2] if len(r) > 2 else ""
        ja3s = r[3] if len(r) > 3 else ""
        if any([ja3, ja3s]):
            lines.append(f"{src},{dst},{ja3},{ja3s}")
    if len(lines) == 1:
        return "No JA3 fingerprints observed."
    return "\n".join(lines)


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def build_report(
    pcap: Path,
    outdir: Path,
    meta: str,
    protos: str,
    endpoints: str,
    conv_ip: str,
    conv_tcp: str,
    conv_udp: str,
    top_talkers_csv: str,
    dns_queries_csv: str,
    dns_answers_csv: str,
    http_csv: str,
    tls_csv: str,
    ja3_txt: str
) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M %Z")
    md = []
    md.append(f"# PCAPalyzer Light Report\n")
    md.append(f"- **File:** `{pcap}`")
    md.append(f"- **Generated:** {ts}")
    md.append("")
    md.append("> This is the *light* build (no LLM). The 'Observation' section is intentionally omitted.\n")

    md.append("## Banner\n")
    md.append(f"{BANNER}\n")

    md.append("## Capture Metadata (capinfos)\n")
    md.append("```\n" + meta + "\n```")

    md.append("## Protocol Hierarchy\n")
    md.append("```\n" + protos + "\n```")

    md.append("## IP Endpoints\n")
    md.append("```\n" + endpoints + "\n```")

    md.append("## Conversations (IP)\n")
    md.append("```\n" + conv_ip + "\n```")

    md.append("## Conversations (TCP)\n")
    md.append("```\n" + conv_tcp + "\n```")

    md.append("## Conversations (UDP)\n")
    md.append("```\n" + conv_udp + "\n```")

    md.append("## Top Talkers\n")
    md.append("_See CSV file in the report folder for full details._\n")

    md.append("## DNS Overview\n")
    md.append("**Top Queries (sample)** — see CSV for more.\n")
    md.append("```\n" + "\n".join(dns_queries_csv.splitlines()[:15]) + "\n```")
    md.append("**Answers (sample)** — see CSV for more.\n")
    md.append("```\n" + "\n".join(dns_answers_csv.splitlines()[:15]) + "\n```")

    md.append("## HTTP Requests (sample)\n")
    md.append("```\n" + "\n".join(http_csv.splitlines()[:15]) + "\n```")

    md.append("## TLS SNI (sample)\n")
    md.append("```\n" + "\n".join(tls_csv.splitlines()[:15]) + "\n```")

    md.append("## JA3 / JA3S\n")
    md.append("```\n" + "\n".join(ja3_txt.splitlines()[:30]) + "\n```")

    md.append("\n---\n")
    md.append(f"_Report folder_: `{outdir}`  \n")
    md.append(f"{BANNER}\n")

    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description="Lightweight PCAP analyzer (no LLM).")
    parser.add_argument("pcap", help="Path to the .pcap or .pcapng file")
    parser.add_argument("--limit", type=int, default=20, help="Top talkers limit (default: 20)")
    args = parser.parse_args()

    pcap = Path(args.pcap).expanduser().resolve()
    if not pcap.exists():
        print(f"Error: file not found: {pcap}", file=sys.stderr)
        sys.exit(1)

    require_deps()

    # Output folder
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = pcap.parent / f"{pcap.stem}_pcapalyzer_light_{stamp}"
    outdir.mkdir(parents=True, exist_ok=True)

    print(BANNER)
    print(f"Analyzing: {pcap}")
    print(f"Output:    {outdir}")

    # Sections
    meta = capinfos_metadata(pcap)
    protos = tshark_protocol_hierarchy(pcap)
    endpoints = tshark_endpoints(pcap)
    conv_ip = tshark_conversations(pcap, "ip")
    conv_tcp = tshark_conversations(pcap, "tcp")
    conv_udp = tshark_conversations(pcap, "udp")

    top_talkers_csv = summarize_top_talkers(pcap, args.limit)
    dns_q_csv, dns_a_csv = summarize_dns(pcap)
    http_csv = summarize_http(pcap)
    tls_csv = summarize_tls(pcap)
    ja3_txt = summarize_ja3(pcap)

    # Write artifacts
    write_text(outdir / "top_talkers.csv", top_talkers_csv)
    write_text(outdir / "dns_queries.csv", dns_q_csv)
    write_text(outdir / "dns_answers.csv", dns_a_csv)
    write_text(outdir / "http_requests.csv", http_csv)
    write_text(outdir / "tls_sni.csv", tls_csv)
    write_text(outdir / "ja3.txt", ja3_txt)

    report_md = build_report(
        pcap=pcap,
        outdir=outdir,
        meta=meta,
        protos=protos,
        endpoints=endpoints,
        conv_ip=conv_ip,
        conv_tcp=conv_tcp,
        conv_udp=conv_udp,
        top_talkers_csv=top_talkers_csv,
        dns_queries_csv=dns_q_csv,
        dns_answers_csv=dns_a_csv,
        http_csv=http_csv,
        tls_csv=tls_csv,
        ja3_txt=ja3_txt
    )
    write_text(outdir / "report.md", report_md)

    print("Done.")
    print(BANNER)


if __name__ == "__main__":
    main()
