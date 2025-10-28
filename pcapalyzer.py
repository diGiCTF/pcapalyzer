#!/usr/bin/env python3
# pcapalyzer.py - Automated PCAP triage with plain text report.
# - Requires: tshark
# - Optional: zeek (summaries if present)
# - LLM Observation: Ollama required AND --model argument must point to an installed model.
#
# Always performs:
#   - Zeek pass (if installed) in a temporary directory (summarized then cleaned)
#   - HTTP object export via tshark (folder kept only if non-empty)
#
# Outputs:
#   - pcapalyzer_output/<pcap_stem>/<pcap_stem>_report.txt
#   - pcapalyzer_output/<pcap_stem>/extracted_http/  (ONLY if files exported)
#
import argparse
import json
import math
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

BASE = Path(__file__).resolve().parent
OUTDIR = BASE / "pcapalyzer_output"
OUTDIR.mkdir(parents=True, exist_ok=True)

def which(cmd: str) -> bool:
    from shutil import which as _which
    return _which(cmd) is not None

def run(cmd: str, cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    print(f"[RUN] {cmd}")
    proc = subprocess.run(shlex.split(cmd), cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    if proc.returncode != 0:
        err = (proc.stderr or '').strip()
        if err:
            print(f"[ERR] {err}")
    return proc

def ensure_tooling():
    missing = []
    if not which("tshark"):
        missing.append("tshark")
    if missing:
        print("[!] Missing required tools:", ", ".join(missing))
        print("    Install tshark (Wireshark CLI). On Debian/Ubuntu/Kali: sudo apt-get install -y tshark")
        sys.exit(1)

# ---------- LLM helpers ----------
def check_ollama_and_model_or_exit(model_name: str) -> None:
    """Ensure Ollama is installed and the requested model is available; if not, print guidance and exit."""
    if not which("ollama"):
        print("[!] Ollama is not installed.")
        print("    Install options:")
        print("    - Linux download page: https://ollama.com/download/linux")
        print("    - Quick install:")
        print("      curl -fsSL https://ollama.com/install.sh | sh")
        print("    After installation, pull a model (recommended deepseek-r1:8b):")
        print("      ollama run deepseek-r1:8b")
        print("    Then run:")
        print("      pcapalyzer.py <file.pcap> --model <model>")
        sys.exit(2)
    # Check installed models
    res = run("ollama list --format json")
    names = []
    if res.returncode == 0 and res.stdout.strip().startswith("["):
        try:
            items = json.loads(res.stdout)
            names = [it.get("name","") for it in items if it.get("name")]
        except Exception:
            names = []
    if not names:
        # Fallback to plain output
        res = run("ollama list")
        for line in res.stdout.splitlines():
            if not line or line.lower().startswith("name "):
                continue
            parts = line.split()
            if parts:
                names.append(parts[0])
    names_lower = [n.lower() for n in names]
    # Accept base-name match (ignore tag) or exact
    target = model_name.strip()
    if not target:
        _fail_model_help()
    if target.lower() in names_lower:
        return
    tbase = target.split(":")[0].lower()
    for n in names:
        if n.split(":")[0].lower() == tbase:
            return
    print(f"[!] Ollama model not found locally: '{model_name}'")
    _fail_model_help()

def _fail_model_help():
    print("    Recommendation: install a small reasoning model:")
    print("      ollama run deepseek-r1:8b")
    print("    Then run:")
    print("      pcapalyzer.py <file.pcap> --model deepseek-r1:8b")
    sys.exit(3)

def build_llm_prompt(prefix: str, summary: Dict[str, Any]) -> str:
    def top_k(seq, k, fmt=lambda x: x):
        return ", ".join(fmt(x) for x in seq[:k]) if seq else "none"
    protos = summary.get("protocol_counts", [])
    top_protos = top_k(protos, 8, lambda x: f"{x[0]}({x[1]})")
    top_ports = top_k(summary.get("top_dst_ports", []), 8, lambda x: f"{x[0]}({x[1]})")
    top_domains = top_k(summary.get("top_domains", []), 8, lambda x: f"{x[0]}({x[1]})")
    ip_src = top_k(summary.get("ip_src_counts", []), 5, lambda x: f"{x[0]}({x[1]})")
    ip_dst = top_k(summary.get("ip_dst_counts", []), 5, lambda x: f"{x[0]}({x[1]})")
    flags = summary.get("flag_hits", {})
    flag_summary = []
    if flags.get("ascii_SKY_frames"): flag_summary.append(f"ASCII_SKY={len(flags['ascii_SKY_frames'])}")
    if flags.get("b64_U0tZ_frames"): flag_summary.append(f"B64_U0tZ={len(flags['b64_U0tZ_frames'])}")
    if flags.get("hex_534b592d_frames"): flag_summary.append(f"HEX_SKY={len(flags['hex_534b592d_frames'])}")
    susp = summary.get("suspicious", {})
    dur = 0.0
    if summary.get("first_ts") is not None and summary.get("last_ts") is not None:
        dur = max(0.0, summary["last_ts"] - summary["first_ts"])
    ctx = [
        f"PCAP: {prefix}",
        f"total_frames={summary.get('total_frames',0)} duration_s={round(dur,3)} avg_pps={summary.get('avg_pps',0.0)} unique_ips={summary.get('unique_ip_count',0)}",
        f"top_protocols={top_protos}",
        f"top_dst_ports={top_ports}",
        f"top_dns_domains={top_domains}",
        f"top_src_ips={ip_src}",
        f"top_dst_ips={ip_dst}",
        f"suspicious=dns_txt:{susp.get('dns_txt_count',0)}, http_post_no_host:{susp.get('http_post_no_host',0)}, tls_no_sni:{susp.get('tls_no_sni',0)}",
        f"flags={' '.join(flag_summary) if flag_summary else 'none'}",
    ]
    prompt = (
        "You are a seasoned network traffic analyst. Given the PCAP summary below, write a brief, professional, single-paragraph "
        "observation of what this capture likely represents (e.g., normal browsing, malware beaconing, data exfiltration, "
        "lateral movement, scanning). Be decisive but avoid speculation beyond the evidence. Mention the most telling indicators "
        "and any next steps an analyst should take. Keep it under 120 words.\n\n"
        "SUMMARY:\n" + "\n".join(ctx)
    )
    return prompt


def fallback_observation(summary: Dict[str, Any]) -> str:
    total = summary.get("total_frames", 0)
    dns_txt = summary.get("suspicious", {}).get("dns_txt_count", 0)
    http_no_host = summary.get("suspicious", {}).get("http_post_no_host", 0)
    tls_no_sni = summary.get("suspicious", {}).get("tls_no_sni", 0)
    protos = [p for p,_ in summary.get("protocol_counts", [])]
    webby = ("http" in protos) or ("tls" in protos)
    udp_heavy = protos.count("udp") > protos.count("tcp")
    note = []
    if tls_no_sni > 0: note.append(f"{tls_no_sni} TLS handshakes missing SNI")
    if dns_txt > 0: note.append(f"{dns_txt} DNS TXT record(s)")
    if http_no_host > 0: note.append(f"{http_no_host} HTTP POST(s) without Host")
    signal = "; ".join(note) if note else "no strong IOCs"
    if webby and tls_no_sni > 0: verdict = "encrypted web traffic with potential evasive TLS usage"
    elif udp_heavy and dns_txt > 0: verdict = "UDP/DNS-heavy traffic with possible data exfiltration via TXT"
    elif webby: verdict = "light web activity"
    else: verdict = "mixed background traffic"
    return f"This capture shows {verdict}. Indicators: {signal}. Next steps: review talkers and destinations, inspect DNS/TLS endpoints, and reconstruct artifacts where possible."


def query_ollama(model: str, prompt: str) -> Optional[str]:
    try:
        # Trim prompt if extremely long (guard against token overflow)
        if len(prompt) > 8000:
            prompt = prompt[-8000:]
        # Ask for a concise answer; set sane generation params
        cmd = f"ollama run {shlex.quote(model)} -p {shlex.quote(prompt)} -n 160 -o num_ctx=4096 -o temperature=0.2"
        res = run(cmd)
        if res.returncode != 0:
            return None
        txt = (res.stdout or '').strip()
        if not txt:
            return None
        txt = re.sub(r'\s+', ' ', txt).strip()
        return txt
    except Exception as e:
        print(f"[LLM] Exception: {e}")
        return None

# ---------- Tshark/Zeek pipeline ----------
def parse_zeek_log(path: Path) -> Tuple[List[str], List[List[str]]]:
    if not path.exists():
        return [], []
    header = []
    rows = []
    with path.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                if line.startswith("#fields"):
                    header = line.strip().split("\t")[1:]
                continue
            rows.append(line.rstrip("\n").split("\t"))
    return header, rows

def tshark_summary(pcap: Path) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "dns": [], "http": [], "tls": [],
        "ip_src_counts": [], "ip_dst_counts": [],
        "protocol_counts": [],
        "data_frames": [],
        "flag_hits": {"ascii_SKY_frames": [], "b64_U0tZ_frames": [], "hex_534b592d_frames": []},
        "total_frames": 0,
        "first_ts": None,
        "last_ts": None,
        "unique_ip_count": 0,
        "avg_pps": 0.0,
        "top_dst_ports": [],
        "top_domains": [],
        "tls_versions": [],
        "suspicious": {
            "dns_txt_count": 0,
            "http_post_no_host": 0,
            "tls_no_sni": 0
        },
        "top_talkers": [],
        "size_stats": {
            "mean": 0.0,
            "stdev": 0.0,
            "large_frames": []
        }
    }
    # Basic frame stream for totals, time, sizes
    r = run(f'tshark -r {shlex.quote(str(pcap))} -T fields -e frame.number -e frame.time_epoch -e frame.len')
    frame_nums = []
    frame_times = []
    frame_lens = []
    for line in r.stdout.splitlines():
        if not line.strip(): continue
        parts = line.split("\t")
        try:
            frame_nums.append(int(parts[0]))
        except Exception:
            continue
        if len(parts) > 1 and parts[1]:
            try:
                frame_times.append(float(parts[1]))
            except Exception:
                pass
        if len(parts) > 2 and parts[2]:
            try:
                frame_lens.append(int(parts[2]))
            except Exception:
                pass
    if frame_nums:
        summary["total_frames"] = len(frame_nums)
        if frame_times:
            summary["first_ts"] = min(frame_times)
            summary["last_ts"] = max(frame_times)
            dur = max(0.0, summary["last_ts"] - summary["first_ts"])
            summary["avg_pps"] = round((len(frame_nums) / dur), 3) if dur > 0 else 0.0
    # size stats
    if frame_lens:
        n = len(frame_lens)
        mean = sum(frame_lens) / n
        var = sum((x - mean) ** 2 for x in frame_lens) / n
        stdev = math.sqrt(var)
        summary["size_stats"]["mean"] = round(mean, 2)
        summary["size_stats"]["stdev"] = round(stdev, 2)
        threshold = mean + 3 * stdev
        # second pass to list larges
        r2 = run(f'tshark -r {shlex.quote(str(pcap))} -T fields -e frame.number -e frame.len')
        big = []
        for line in r2.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[0].isdigit():
                try:
                    ln = int(parts[1])
                    if ln > threshold:
                        big.append( (int(parts[0]), ln) )
                except Exception:
                    pass
        big.sort(key=lambda x: x[1], reverse=True)
        summary["size_stats"]["large_frames"] = big[:10]

    # DNS
    r = run(f'tshark -r {shlex.quote(str(pcap))} -Y "dns" -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.txt')
    dq = Counter()
    dns_txt_count = 0
    for line in r.stdout.splitlines():
        if not line.strip(): continue
        parts = line.split("\t")
        name = parts[2] if len(parts) > 2 else ""
        txt = parts[3] if len(parts) > 3 else ""
        if name:
            dq[name] += 1
        if txt:
            dns_txt_count += 1
        summary["dns"].append({
            "time": parts[0] if len(parts)>0 else "",
            "src":  parts[1] if len(parts)>1 else "",
            "qry":  name,
            "txt":  txt
        })
    summary["top_domains"] = dq.most_common(10)
    summary["suspicious"]["dns_txt_count"] = dns_txt_count

    # HTTP
    r = run(f'tshark -r {shlex.quote(str(pcap))} -Y "http.request" -T fields -e frame.time_epoch -e ip.src -e http.host -e http.request.uri -e http.user_agent -e http.request.method')
    hosts, uris, uas = Counter(), Counter(), Counter()
    http_post_no_host = 0
    for line in r.stdout.splitlines():
        if not line.strip(): continue
        parts = line.split("\t")
        host = parts[2] if len(parts)>2 else ""
        uri  = parts[3] if len(parts)>3 else ""
        ua   = parts[4] if len(parts)>4 else ""
        method = parts[5] if len(parts)>5 else ""
        if host: hosts[host] += 1
        if uri:  uris[uri] += 1
        if ua:   uas[ua]  += 1
        if method == "POST" and not host:
            http_post_no_host += 1
        summary["http"].append({
            "time": parts[0] if len(parts)>0 else "",
            "src":  parts[1] if len(parts)>1 else "",
            "host": host,
            "uri":  uri,
            "ua":   (ua[:200] if ua else ""),
            "method": method
        })
    summary["http_summary"] = {
        "unique_hosts": len(hosts),
        "unique_uris": len(uris),
        "unique_user_agents": len(uas),
        "top_hosts": hosts.most_common(10),
        "top_uris": uris.most_common(10)
    }
    summary["suspicious"]["http_post_no_host"] = http_post_no_host

    # TLS SNI + versions
    r = run(f'tshark -r {shlex.quote(str(pcap))} -Y "tls.handshake" -T fields -e tls.handshake.extensions_server_name -e tls.record.version')
    sni_counter, ver_counter = Counter(), Counter()
    for line in r.stdout.splitlines():
        if not line.strip(): continue
        parts = line.split("\t")
        sni = parts[0] if len(parts)>0 else ""
        ver = parts[1] if len(parts)>1 else ""
        if sni: sni_counter[sni] += 1
        if ver: ver_counter[ver] += 1
        if sni:
            summary["tls"].append({"sni": sni, "ver": ver})
    summary["tls_versions"] = ver_counter.most_common(10)
    # TLS without SNI
    r = run(f'tshark -r {shlex.quote(str(pcap))} -Y "tls.handshake and not tls.handshake.extensions_server_name" -T fields -e frame.number')
    summary["suspicious"]["tls_no_sni"] = len([ln for ln in r.stdout.splitlines() if ln.strip()])

    # IP / Ports / Pairs
    ip_src_counts, ip_dst_counts = Counter(), Counter()
    dst_ports = Counter()
    pair_counts = Counter()
    r = run(f'tshark -r {shlex.quote(str(pcap))} -Y "tcp or udp" -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport')
    all_ips = set()
    for line in r.stdout.splitlines():
        if not line.strip(): continue
        parts = line.split("\t")
        src = parts[0] if len(parts) >= 1 else ""
        dst = parts[1] if len(parts) >= 2 else ""
        tsrc = parts[2] if len(parts) >= 3 else ""
        tdst = parts[3] if len(parts) >= 4 else ""
        usrc = parts[4] if len(parts) >= 5 else ""
        udst = parts[5] if len(parts) >= 6 else ""
        if src:
            ip_src_counts[src] += 1
            all_ips.add(src)
        if dst:
            ip_dst_counts[dst] += 1
            all_ips.add(dst)
        dport = tdst or udst
        sport = tsrc or usrc
        if dport and (src and dst):
            dst_ports[dport] += 1
            pair_counts[(src, sport or "-", dst, dport)] += 1
    summary["ip_src_counts"] = ip_src_counts.most_common()
    summary["ip_dst_counts"] = ip_dst_counts.most_common()
    summary["unique_ip_count"] = len(all_ips)
    summary["top_dst_ports"] = [(p, c) for p, c in dst_ports.most_common(10)]
    summary["top_talkers"] = [ {"src": s, "sport": sp, "dst": d, "dport": dp, "count": c}
                                for (s, sp, d, dp), c in pair_counts.most_common(10) ]

    # Protocol usage
    proto_counts = Counter()
    r = run(f'tshark -r {shlex.quote(str(pcap))} -T fields -e frame.protocols')
    for line in r.stdout.splitlines():
        if not line.strip(): continue
        for token in line.split(":"):
            tok = token.strip()
            if tok: proto_counts[tok] += 1
    summary["protocol_counts"] = proto_counts.most_common()

    # Data frames
    r = run(f'tshark -r {shlex.quote(str(pcap))} -Y "data" -T fields -e frame.number')
    summary["data_frames"] = [x for x in r.stdout.splitlines() if x.strip()]

    # Flags
    r = run(f"tshark -r {shlex.quote(str(pcap))} -Y 'frame contains \"SKY-\"' -T fields -e frame.number")
    summary["flag_hits"]["ascii_SKY_frames"] = [x for x in r.stdout.splitlines() if x.strip()]
    r = run(f"tshark -r {shlex.quote(str(pcap))} -Y 'frame contains \"U0tZ\"' -T fields -e frame.number")
    summary["flag_hits"]["b64_U0tZ_frames"] = [x for x in r.stdout.splitlines() if x.strip()]
    r = run(f'tshark -r {shlex.quote(str(pcap))} -Y "frame contains 53:4b:59:2d" -T fields -e frame.number')
    summary["flag_hits"]["hex_534b592d_frames"] = [x for x in r.stdout.splitlines() if x.strip()]

    return summary

def export_http_objects_if_any(pcap: Path, outdir: Path) -> Tuple[Optional[str], Dict[str, Any]]:
    export_dir = outdir / "extracted_http"
    if export_dir.exists():
        shutil.rmtree(export_dir, ignore_errors=True)
    export_dir.mkdir(parents=True, exist_ok=True)
    run(f'tshark -r {shlex.quote(str(pcap))} --export-objects http,{shlex.quote(str(export_dir))}')
    files = [p for p in export_dir.iterdir() if p.is_file()]
    if files:
        total_size = sum(p.stat().st_size for p in files)
        top5 = sorted([(p.name, p.stat().st_size) for p in files], key=lambda x:x[1], reverse=True)[:5]
        return str(export_dir), {"count": len(files), "total_size": total_size, "top5": top5}
    shutil.rmtree(export_dir, ignore_errors=True)
    return None, {}

def render_text(prefix: str, full_path: Path, outdir: Path, summary: Dict[str, Any],
                http_export_stats: Dict[str, Any], zeek_stats: Dict[str, Any], observation_text: Optional[str]) -> Path:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out_lines: List[str] = []
    # Header
    out_lines.append(str(full_path))
    out_lines.append(now)
    out_lines.append("")

    # GENERAL METRICS
    out_lines.append("##############")
    out_lines.append("ANALYSIS")
    out_lines.append("##############")
    total = summary.get("total_frames", 0)
    dur = 0.0
    fts = summary.get("first_ts")
    lts = summary.get("last_ts")
    if fts is not None and lts is not None:
        dur = max(0.0, lts - fts)
    out_lines.append(f"Total frames: {total}")
    out_lines.append(f"Capture duration (s): {round(dur,3)}")
    out_lines.append(f"Average packets/sec: {summary.get('avg_pps', 0.0)}")
    out_lines.append(f"Unique IPs: {summary.get('unique_ip_count', 0)}")

    # Quick high-level hints
    protos = summary.get("protocol_counts", [])
    ip_src = summary.get("ip_src_counts", [])
    ip_dst = summary.get("ip_dst_counts", [])
    data_count = len(summary.get("data_frames", []))
    if protos:
        out_lines.append("Top protocols: " + ", ".join(f"{p} ({c})" for p,c in protos[:8]))
    if ip_src:
        out_lines.append("Top talkers (src): " + ", ".join(f"{ip} ({n})" for ip,n in ip_src[:5]))
    if ip_dst:
        out_lines.append("Top destinations: " + ", ".join(f"{ip} ({n})" for ip,n in ip_dst[:5]))
    if data_count:
        out_lines.append(f"Frames with data payload: {data_count}")
    size_stats = summary.get("size_stats", {})
    if size_stats:
        out_lines.append(f"Frame size mean/stdev: {size_stats.get('mean',0)}/{size_stats.get('stdev',0)}")

    # Observation (LLM output required by CLI; if somehow empty, print an advisory line)
    if observation_text and observation_text.strip():
        out_lines.append(f"Observation: {observation_text.strip()}")
    else:
        out_lines.append(f"Observation: {fallback_observation(summary)}")
    out_lines.append("")

    # PROTOCOLS
    out_lines.append("##############")
    out_lines.append("PROTOCOLS")
    out_lines.append("##############")
    for p,c in protos:
        out_lines.append(f"{p} ({c})")
    out_lines.append("")

    # TOP PORTS
    out_lines.append("##############")
    out_lines.append("TOP DESTINATION PORTS")
    out_lines.append("##############")
    for port,count in summary.get("top_dst_ports", []):
        out_lines.append(f"{port} ({count})")
    out_lines.append("")

    # TOP DOMAINS
    if summary.get("top_domains"):
        out_lines.append("##############")
        out_lines.append("TOP DNS DOMAINS")
        out_lines.append("##############")
        for dom,cnt in summary["top_domains"]:
            out_lines.append(f"{dom} ({cnt})")
        out_lines.append("")

    # HTTP SUMMARY
    if summary.get("http_summary"):
        hs = summary["http_summary"]
        out_lines.append("##############")
        out_lines.append("HTTP SUMMARY")
        out_lines.append("##############")
        out_lines.append(f"Unique hosts: {hs.get('unique_hosts',0)}")
        out_lines.append(f"Unique URIs: {hs.get('unique_uris',0)}")
        out_lines.append(f"Unique User-Agents: {hs.get('unique_user_agents',0)}")
        if hs.get("top_hosts"):
            out_lines.append("Top hosts:")
            for h,c in hs["top_hosts"]:
                out_lines.append(f"  {h} ({c})")
        if hs.get("top_uris"):
            out_lines.append("Top URIs:")
            for u,c in hs["top_uris"]:
                out_lines.append(f"  {u} ({c})")
        out_lines.append("")

    # TLS SUMMARY
    if summary.get("tls_versions"):
        out_lines.append("##############")
        out_lines.append("TLS SUMMARY")
        out_lines.append("##############")
        out_lines.append("TLS versions: " + ", ".join(f"{v} ({c})" for v,c in summary["tls_versions"]))
        distinct_sni = len(set(t.get("sni","") for t in summary.get("tls", []) if t.get("sni")))
        out_lines.append(f"Distinct SNI values: {distinct_sni}")
        out_lines.append("")

    # SUSPICIOUS PATTERNS
    susp = summary.get("suspicious", {})
    out_lines.append("##############")
    out_lines.append("SUSPICIOUS PATTERNS")
    out_lines.append("##############")
    out_lines.append(f"DNS TXT records: {susp.get('dns_txt_count',0)}")
    out_lines.append(f"HTTP POSTs without Host: {susp.get('http_post_no_host',0)}")
    out_lines.append(f"TLS handshakes without SNI: {susp.get('tls_no_sni',0)}")
    out_lines.append("")

    # TOP TALKER PAIRS
    if summary.get("top_talkers"):
        out_lines.append("##############")
        out_lines.append("TOP TALKER PAIRS")
        out_lines.append("##############")
        for ent in summary["top_talkers"]:
            out_lines.append(f"{ent['src']}:{ent['sport']} -> {ent['dst']}:{ent['dport']} ({ent['count']})")
        out_lines.append("")

    # FLAGS (only if any)
    flags = summary.get("flag_hits", {})
    if flags.get("ascii_SKY_frames") or flags.get("b64_U0tZ_frames") or flags.get("hex_534b592d_frames"):
        out_lines.append("##############")
        out_lines.append("FLAGS")
        out_lines.append("##############")
        if flags.get("ascii_SKY_frames"):
            out_lines.append("ASCII 'SKY-' in frames: " + ",".join(flags["ascii_SKY_frames"]))
        if flags.get("b64_U0tZ_frames"):
            out_lines.append("Base64 'U0tZ' in frames: " + ",".join(flags["b64_U0tZ_frames"]))
        if flags.get("hex_534b592d_frames"):
            out_lines.append("Hex 53 4B 59 2D ('SKY-') in frames: " + ",".join(flags["hex_534b592d_frames"]))
        out_lines.append("")

    # DATA FOUND IN FRAMES
    data_frames = summary.get("data_frames", [])
    if data_frames:
        out_lines.append("##############")
        out_lines.append("DATA FOUND IN FRAMES")
        out_lines.append("##############")
        out_lines.append(",".join(data_frames))
        out_lines.append("")

    # LARGE FRAMES
    lf = summary.get("size_stats", {}).get("large_frames", [])
    if lf:
        out_lines.append("##############")
        out_lines.append("ANOMALOUS LARGE FRAMES (> mean + 3*stdev)")
        out_lines.append("##############")
        for num, ln in lf:
            out_lines.append(f"Frame {num} - {ln} bytes")
        out_lines.append("")

    # HTTP EXPORT SUMMARY
    if http_export_stats:
        out_lines.append("##############")
        out_lines.append("EXTRACTED HTTP OBJECTS")
        out_lines.append("##############")
        out_lines.append(f"Files: {http_export_stats.get('count',0)}")
        out_lines.append(f"Total size (bytes): {http_export_stats.get('total_size',0)}")
        top5 = http_export_stats.get("top5", [])
        if top5:
            out_lines.append("Top 5 largest:")
            for name, sz in top5:
                out_lines.append(f"  {name} ({sz} bytes)")
        out_lines.append("")

    # ZEEK SUMMARY
    if zeek_stats:
        out_lines.append("##############")
        out_lines.append("ZEEK SUMMARY")
        out_lines.append("##############")
        out_lines.append(f"Total connections (conn.log): {zeek_stats.get('conn_total',0)}")
        if zeek_stats.get('top_services'):
            out_lines.append("Top services: " + ", ".join(f"{s} ({c})" for s,c in zeek_stats['top_services']))
        if zeek_stats.get('conn_states'):
            out_lines.append("Conn states: " + ", ".join(f"{s} ({c})" for s,c in zeek_stats['conn_states']))
        out_lines.append(f"Notices (notice.log): {zeek_stats.get('notices',0)}")
        out_lines.append("")

    # Write out
    txt_path = outdir / f"{prefix}_report.txt"
    txt_path.write_text("\n".join(out_lines), encoding="utf-8")
    return txt_path

def main():
    parser = argparse.ArgumentParser(
        description=(
            "PCAPalyzer: Automated PCAP triage (plain text report). "
            "HTTP object export + Zeek summaries are enabled by default.\n\n"
            "LLM Observation requires Ollama and a local model."
        )
    )
    parser.add_argument("pcap", help="Path to input .pcap/.pcapng")
    parser.add_argument("--model", required=True, help=("Required Ollama model name to use for the Observation.\n"
                                                       "Recommendation: install 'deepseek-r1:8b' via:\n"
                                                       "  ollama run deepseek-r1:8b"))
    args = parser.parse_args()
    ensure_tooling()
    pcap = Path(args.pcap).expanduser().resolve()
    if not pcap.exists():
        print("[!] PCAP not found:", pcap)
        sys.exit(1)
    prefix = pcap.stem
    outdir = OUTDIR / prefix
    outdir.mkdir(parents=True, exist_ok=True)

    # Verify Ollama + model availability (fail with guidance if missing)
    check_ollama_and_model_or_exit(args.model)

    # Summarize with tshark
    summary = tshark_summary(pcap)

    # Zeek (if present): run in temp dir, parse, then clean
    zeek_stats: Dict[str, Any] = {}
    if which("zeek"):
        tmp = Path(tempfile.mkdtemp(prefix="pcapalyzer_zeek_"))
        try:
            run(f"zeek -r {shlex.quote(str(pcap))}", cwd=tmp)
            # parse conn.log
            hdr, rows = parse_zeek_log(tmp / "conn.log")
            if rows and hdr:
                try:
                    idx_service = hdr.index("service") if "service" in hdr else None
                except ValueError:
                    idx_service = None
                try:
                    idx_state = hdr.index("conn_state") if "conn_state" in hdr else None
                except ValueError:
                    idx_state = None
                zeek_stats["conn_total"] = len(rows)
                if idx_service is not None:
                    from collections import Counter as Cnt
                    svc = Cnt(r[idx_service] for r in rows if len(r) > idx_service and r[idx_service])
                    zeek_stats["top_services"] = svc.most_common(10)
                if idx_state is not None:
                    from collections import Counter as Cnt
                    st = Cnt(r[idx_state] for r in rows if len(r) > idx_state and r[idx_state])
                    zeek_stats["conn_states"] = st.most_common(10)
            # parse notice.log
            _, nrows = parse_zeek_log(tmp / "notice.log")
            zeek_stats["notices"] = len(nrows) if nrows else 0
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # Always attempt HTTP export (kept only if non-empty)
    export_path, http_export_stats = export_http_objects_if_any(pcap, outdir)
    if export_path:
        print("  Extracted HTTP objects:", export_path)

    # LLM Observation (required by CLI; we've already validated model presence)
    prompt = build_llm_prompt(prefix, summary)
    observation = query_ollama(args.model, prompt) or ""

    # Render
    txt_path = render_text(prefix, pcap, outdir, summary, http_export_stats, zeek_stats, observation)
    print("[✓] Done.")
    print("  TXT:", txt_path.resolve())
    print("Created by diGi - reach me on discord: 0x3444\n")

if __name__ == "__main__":
    main()
