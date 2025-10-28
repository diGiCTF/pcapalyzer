# 🧠 pcapalyzer

**pcapalyzer** is an automated PCAP triage tool that uses `tshark`, `zeek`, and a local LLM (via [Ollama](https://ollama.com)) to generate detailed, human-readable network traffic reports.  
It’s built for cybersecurity professionals who want rapid insight and AI-assisted analysis directly from packet captures.

---

## 🚀 Features

- ✅ Summarizes traffic protocols, IP talkers, DNS queries, TLS versions, HTTP activity, and suspicious patterns  
- 🧩 Detects potential Indicators of Compromise (IoCs), including DNS TXT leaks, HTTP anomalies, and hidden flags  
- 📦 Automatically extracts HTTP objects (files transferred during capture)  
- 🔍 Integrates with **Zeek** (if installed) for deeper connection summaries  
- 🧠 Uses an LLM (Ollama) to write an **Observation** — a concise, professional analysis of the capture  
- 📄 Outputs a clean text report with all findings neatly organized  

---

## 🧰 Requirements

### Core tools
| Tool | Purpose | Install Command (Debian/Ubuntu/Kali) |
|------|----------|--------------------------------------|
| `tshark` | Packet parsing and extraction | `sudo apt install tshark -y` |
| `zeek` *(optional)* | Deep flow analysis | `sudo apt install zeek -y` |
| `ollama` | Local LLM runner for AI Observations | See below |

---

## 🧠 Ollama Installation

Ollama lets you run open-source models like **DeepSeek**, **Mistral**, and **Llama** locally.

**Option 1: Quick install**

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Option 2: Manual install**

Visit the Linux download page:  
🔗 [https://ollama.com/download/linux](https://ollama.com/download/linux)

After installation, pull the recommended model:
```bash
ollama run deepseek-r1:8b
```

---

## ⚙️ Usage

```bash
python3 pcapalyzer.py <file.pcap> --model <model_name>
```

### Example:
```bash
python3 pcapalyzer.py insider_upload.pcap --model deepseek-r1:8b
```

### Output:
Reports are saved in:
```
autopcap_output/<pcap_name>/<pcap_name>_report.txt
```

Example snippet:
```
##############
ANALYSIS
##############
Total frames: 12784
Capture duration (s): 435.972
Average packets/sec: 29.3
Unique IPs: 46
Observation: This capture shows encrypted web traffic with possible data exfiltration via DNS TXT records. Indicators: 3 TLS handshakes missing SNI; 5 DNS TXT record(s).
```

---

## 🧾 Report Sections

- **ANALYSIS** — Summary metrics, frame count, timing, and AI-generated observation  
- **PROTOCOLS / PORTS / DOMAINS** — Top protocols, ports, and DNS domains seen  
- **HTTP / TLS / ZEEK SUMMARY** — Application-layer traffic details  
- **SUSPICIOUS PATTERNS** — Indicators like DNS TXT leaks, HTTP anomalies, and TLS quirks  
- **FLAGS** — Detects embedded strings like `SKY-`, `U0tZ`, or `534b592d`  
- **EXTRACTED HTTP OBJECTS** — Files retrieved from capture  
- **LARGE FRAMES** — Oversized or anomalous traffic frames  

---

## 🧩 Example Workflow

```bash
# 1. Capture some traffic
sudo tcpdump -i eth0 -w sample.pcap

# 2. Analyze with DeepSeek 8B model
python3 pcapalyzer.py sample.pcap --model deepseek-r1:8b

# 3. View your report
cat autopcap_output/sample/sample_report.txt
```

---

## ⚠️ Troubleshooting

| Issue | Solution |
|--------|-----------|
| `Ollama is not installed` | Follow the install steps above |
| `Model not found locally` | Run `ollama run deepseek-r1:8b` once to pull it |
| `No LLM output` | The model failed to respond — check logs or use a smaller model (`deepseek-r1:8b` or `mistral`) |

---

## 🧑‍💻 Author
Created by **Digi Jeff**  
Cybersecurity Analyst & Developer  
💻 [github.com/digijeff](https://github.com/digijeff)

---

## 📜 License
MIT License © 2025 Digi Jeff
