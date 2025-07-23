import tkinter as tk
from tkinter import filedialog, messagebox
import webbrowser
import os
import threading
import pyshark
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict, Counter
import ipaddress
import subprocess
import sys
import traceback
import hashlib
import base64
import re
import statistics
import math

# --- Global constants & precompiled patterns ---
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b")
TOKEN_RE = re.compile(r"(?:token|api[_-]?key|secret)[=:]?\s*([\w-]{10,})", re.IGNORECASE)

PROTOCOL_PORTS = {
    "HTTP": {80, 8080}, "HTTPS": {443}, "SSH": {22}, "FTP": {21},
    "DNS": {53}, "TELNET": {23}, "SMTP": {25, 587}, "IMAP": {143, 993},
    "POP": {110, 995}, "RDP": {3389}, "SMB": {445, 139}
}
TLD_COMMON = {
    "com","net","org","edu","gov","mil","int","us","uk","ca","de","fr","au","jp","kr","cn"
}
COMMON_AGENTS = {"mozilla","chrome","safari","firefox","edge","opera","curl","wget"}
BORING_MIMES = {
    "text/html","application/json","application/xml","text/javascript",
    "image/png","image/jpeg","image/gif","image/x-icon","font/woff",
    "font/woff2","application/ocsp-response","application/x-x509-ca-cert",
    "application/pkix-crl"
}
MACRO_MIMES = {
    "application/vnd.ms-office",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12"
}
MACRO_EXTS = {".docm",".xlsm",".pptm",".docb",".doc",".dotm"}

# --- Error logging hooks ---
def silent_excepthook(exc_type, value, tb):
    with open("pcap_triage_error.log", "a") as log:
        log.write("UNCAUGHT ERROR:\n" + "".join(traceback.format_exception(exc_type, value, tb)))
sys.excepthook = silent_excepthook

def log_internal_error(msg):
    with open("pcap_triage_error.log", "a") as log:
        log.write(msg + "\n")

# --- Utility functions ---
def fast_packet_count(pcap_path, progress_callback=None):
    for cmd in (['tshark','-r',pcap_path,'-T','fields','-e','frame.number'],
                ['tcpdump','-r',pcap_path]):
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True)
            count = result.stdout.count('\n')
            if count:
                if progress_callback:
                    progress_callback(f"Counting packets: {count} found")
                return count
        except Exception as e:
            log_internal_error(f"{cmd[0]} count error: {e}")
    # fallback to PyShark summary
    count = 0
    for idx, _ in enumerate(pyshark.FileCapture(pcap_path,
                        only_summaries=True, keep_packets=False), 1):
        count = idx
        if progress_callback and idx % 1000 == 0:
            progress_callback(f"Counting packets: {idx}")
    if progress_callback:
        progress_callback(f"Counting packets: {count} found (slow mode)")
    return count

def is_public_ip(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def load_domain_ignorelist(filename="domain_ignore.txt"):
    if not os.path.exists(filename):
        return []
    patterns = []
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line.lower())
    return patterns

def domain_is_ignored(domain, ignore_patterns):
    d = domain.lower()
    for pat in ignore_patterns:
        if pat.startswith("*.") and d.endswith(pat[1:]):
            return True
        if d == pat:
            return True
    return False

# --- Analyzer class to accumulate all metrics in one pass ---
class PcapAnalyzer:
    def __init__(self, ignore_patterns):
        # Prepare storage for each analysis module
        self.ignore_patterns = ignore_patterns
        self.ip_stats = defaultdict(lambda: defaultdict(int))
        self.port_mismatches = []
        self.dns_failed = []
        self.dns_long = []
        self.dns_rare = []
        self.dns_txt = []
        self.dns_entropy = []
        self.http_domains = defaultdict(lambda: {
            "urls": set(), "methods": set(), "user_agents": set(),
            "content_types": set(), "filenames": set(), "bodies": set()
        })
        self.unusual_agents = set()
        self.file_info = []
        self.flow_stats = defaultdict(lambda: {
            "bytes": 0, "pkts": 0, "syn_only": 0,
            "srcs": set(), "syn_srcs": defaultdict(int)
        })
        self.files = []
        self.creds = []
        self.beacon_candidates = defaultdict(list)
        self.weak_ssl = []
        self.odd_proto = []
        self.ip_to_macs = defaultdict(set)
        self.mac_to_ips = defaultdict(set)
        self.gratuitous_arp = []
        self.arp_count = defaultdict(int)

    def process_packet(self, pkt):
        # --- Non-RFC1918 destinations ---
        try:
            if hasattr(pkt, 'ip'):
                dst = pkt.ip.dst
                if is_public_ip(dst):
                    layers = []
                    if pkt.highest_layer:
                        layers.append(pkt.highest_layer)
                    if pkt.transport_layer and pkt.transport_layer != pkt.highest_layer:
                        layers.append(pkt.transport_layer)
                    hierarchy = " > ".join(layers) if layers else "UNKNOWN"
                    self.ip_stats[dst][hierarchy] += 1
        except Exception as e:
            log_internal_error(f"Non-RFC1918 error: {e}")

        # --- Port/proto mismatches ---
        try:
            if hasattr(pkt, 'ip') and hasattr(pkt, 'tcp'):
                dst_port = int(pkt.tcp.dstport)
                proto = pkt.highest_layer
                if proto in PROTOCOL_PORTS and dst_port not in PROTOCOL_PORTS[proto]:
                    self.port_mismatches.append({
                        "src_ip": pkt.ip.src,
                        "dst_ip": pkt.ip.dst,
                        "dst_port": dst_port,
                        "protocol": proto
                    })
        except Exception as e:
            log_internal_error(f"Port/proto mismatch error: {e}")

        # --- DNS anomalies ---
        try:
            if hasattr(pkt, 'dns'):
                d = pkt.dns
                name = getattr(d, 'qry_name', None)
                if name:
                    dom = name.lower()
                    if not domain_is_ignored(dom, self.ignore_patterns):
                        tld = dom.split('.')[-1]
                        if len(dom) > 40:
                            self.dns_long.append(dom)
                        if tld not in TLD_COMMON:
                            self.dns_rare.append(dom)
                        if self._entropy(dom) > 4.0:
                            self.dns_entropy.append(dom)
                        if getattr(d, 'qry_type', None) == '16':
                            self.dns_txt.append(dom)
                if getattr(d, 'flags_rcode', "0") != "0":
                    q = getattr(d, 'qry_name', '(unknown)')
                    if not domain_is_ignored(q, self.ignore_patterns):
                        self.dns_failed.append(q)
        except Exception as e:
            log_internal_error(f"DNS error: {e}")

        # --- HTTP analysis & file-info gather ---
        try:
            if hasattr(pkt, 'http'):
                h = pkt.http
                host = getattr(h, "host", None)
                if host and not domain_is_ignored(host, self.ignore_patterns):
                    url = getattr(h, "request_full_uri", None)
                    if url:
                        self.http_domains[host]["urls"].add(url)
                    method = getattr(h, "request_method", None)
                    if method:
                        self.http_domains[host]["methods"].add(method)
                    ua = getattr(h, "user_agent", None)
                    if ua:
                        self.http_domains[host]["user_agents"].add(ua)
                        if not any(c in ua.lower() for c in COMMON_AGENTS):
                            self.unusual_agents.add(ua)
                    ct = getattr(h, "content_type", None)
                    if ct:
                        self.http_domains[host]["content_types"].add(ct)
                    fn = getattr(h, "file_data", None)
                    if fn:
                        self.http_domains[host]["filenames"].add(fn)
                        self.http_domains[host]["bodies"].add(fn)
                    if ct or fn:
                        self.file_info.append({
                            "domain": host,
                            "url": url or "",
                            "content_type": ct or "",
                            "filename": fn or ""
                        })
        except Exception as e:
            log_internal_error(f"HTTP error: {e}")

        # --- Suspicious flows ---
        try:
            if hasattr(pkt, 'ip') and hasattr(pkt, 'tcp'):
                src = pkt.ip.src
                dst = pkt.ip.dst
                key = (dst, int(pkt.tcp.dstport))
                fs = self.flow_stats[key]
                fs["pkts"] += 1
                fs["srcs"].add(src)
                try:
                    fs["bytes"] += int(pkt.length)
                except Exception:
                    pass
                flags = getattr(pkt.tcp, "flags", "")
                if flags == "0x0002":
                    fs["syn_only"] += 1
                    fs["syn_srcs"][src] += 1
        except Exception as e:
            log_internal_error(f"Flow error: {e}")

        # --- File transfers (initial gather) ---
        try:
            if hasattr(pkt, 'http'):
                h = pkt.http
                host = getattr(h, "host", "")
                if not domain_is_ignored(host, self.ignore_patterns):
                    src = pkt.ip.src if hasattr(pkt, 'ip') else ""
                    dst = pkt.ip.dst if hasattr(pkt, 'ip') else ""
                    fn = getattr(h, "content_disposition_filename", None) or getattr(h, "file_data", None)
                    ct = getattr(h, "content_type", None) or ""
                    payload = getattr(h, "file_data", None)
                    size = getattr(h, "content_length", None) or (str(len(payload)) if payload else "")
                    ext = fn[fn.rfind("."):].lower() if fn and "." in fn else ""
                    sha256 = ""
                    if payload:
                        try:
                            sha256 = hashlib.sha256(payload.encode("utf-8","ignore")).hexdigest()
                        except Exception:
                            pass
                    is_macro = ct in MACRO_MIMES or ext in MACRO_EXTS
                    is_boring = ct in BORING_MIMES
                    # initial gather; final filtering will apply suspicious_ip logic
                    if not is_boring or is_macro:
                        self.files.append({
                            "src_ip": src,
                            "dst_ip": dst,
                            "domain": host,
                            "url": getattr(h, "request_full_uri", "") or "",
                            "filename": fn or "",
                            "content_type": ct,
                            "sha256": sha256,
                            "size": size,
                            "macro_flag": "Yes" if is_macro else ""
                        })
        except Exception as e:
            log_internal_error(f"File transfer error: {e}")

        # --- Credential exposure ---
        try:
            src = pkt.ip.src if hasattr(pkt, 'ip') else ""
            dst = pkt.ip.dst if hasattr(pkt, 'ip') else ""
            if hasattr(pkt, 'http'):
                auth = getattr(pkt.http, "authorization", "")
                if auth.lower().startswith("basic "):
                    try:
                        dec = base64.b64decode(auth.split()[1]).decode(errors="ignore")
                        if ":" in dec:
                            self.creds.append({
                                "type": "HTTP Basic",
                                "protocol": "HTTP",
                                "src_ip": src,
                                "dst_ip": dst,
                                "detail": dec
                            })
                    except Exception:
                        pass
                for field in [getattr(pkt.http, "request_full_uri", ""), getattr(pkt.http, "file_data", None)]:
                    if field:
                        for e in EMAIL_RE.findall(field):
                            self.creds.append({
                                "type": "Email",
                                "protocol": "HTTP",
                                "src_ip": src,
                                "dst_ip": dst,
                                "detail": e
                            })
                        for t in TOKEN_RE.findall(field):
                            self.creds.append({
                                "type": "Token/String",
                                "protocol": "HTTP",
                                "src_ip": src,
                                "dst_ip": dst,
                                "detail": t
                            })
            if hasattr(pkt, 'ftp'):
                cmd = pkt.ftp.request_command.upper()
                arg = getattr(pkt.ftp, "request_arg", "")
                if cmd == "USER":
                    self.creds.append({
                        "type": "FTP USER",
                        "protocol": "FTP",
                        "src_ip": src,
                        "dst_ip": dst,
                        "detail": arg
                    })
                elif cmd == "PASS":
                    self.creds.append({
                        "type": "FTP PASS",
                        "protocol": "FTP",
                        "src_ip": src,
                        "dst_ip": dst,
                        "detail": arg
                    })
            if hasattr(pkt, 'telnet'):
                line = str(pkt.telnet)
                if "login:" in line.lower():
                    self.creds.append({
                        "type": "Telnet Username Prompt",
                        "protocol": "TELNET",
                        "src_ip": src,
                        "dst_ip": dst,
                        "detail": line
                    })
                if "password:" in line.lower():
                    self.creds.append({
                        "type": "Telnet Password Prompt",
                        "protocol": "TELNET",
                        "src_ip": src,
                        "dst_ip": dst,
                        "detail": line
                    })
            if hasattr(pkt, 'smtp'):
                payload = str(pkt.smtp)
                if "AUTH LOGIN" in payload or "AUTH PLAIN" in payload:
                    self.creds.append({
                        "type": "SMTP AUTH",
                        "protocol": "SMTP",
                        "src_ip": src,
                        "dst_ip": dst,
                        "detail": payload
                    })
                for e in EMAIL_RE.findall(payload):
                    self.creds.append({
                        "type": "Email",
                        "protocol": "SMTP",
                        "src_ip": src,
                        "dst_ip": dst,
                        "detail": e
                    })
            if hasattr(pkt, 'snmp'):
                com = getattr(pkt.snmp, "community", None)
                if com:
                    self.creds.append({
                        "type": "SNMP Community",
                        "protocol": "SNMP",
                        "src_ip": src,
                        "dst_ip": dst,
                        "detail": com
                    })
        except Exception as e:
            log_internal_error(f"Creds error: {e}")

        # --- Beaconing ---
        try:
            if hasattr(pkt, 'ip'):
                src = pkt.ip.src
                dst = pkt.ip.dst
                if is_public_ip(dst):
                    ts = float(pkt.sniff_timestamp)
                    if hasattr(pkt, 'http'):
                        host = getattr(pkt.http, "host", None)
                        if host and domain_is_ignored(host, self.ignore_patterns):
                            return
                    self.beacon_candidates[(src, dst)].append(ts)
        except Exception as e:
            log_internal_error(f"Beaconing error: {e}")

        # --- Protocol oddities & ARP/L2 oddities ---
        try:
            if hasattr(pkt, 'ssl'):
                ver = getattr(pkt.ssl, "handshake_version", "") or getattr(pkt.ssl, "record_version", "")
                cip = getattr(pkt.ssl, "handshake_ciphersuite", "")
                src = pkt.ip.src if hasattr(pkt, 'ip') else ""
                dst = pkt.ip.dst if hasattr(pkt, 'ip') else ""
                ts = str(pkt.sniff_time)
                if any(v in ver for v in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")) or any(x in cip for x in ("EXPORT", "NULL", "RC4", "MD5", "DES")):
                    self.weak_ssl.append({
                        "src_ip": src, "dst_ip": dst,
                        "version": ver, "cipher": cip, "timestamp": ts
                    })
            if hasattr(pkt, 'ip'):
                proto_num = int(getattr(pkt.ip, "proto", 0))
                src = pkt.ip.src; dst = pkt.ip.dst; ts = str(pkt.sniff_time)
                if proto_num not in {1, 2, 6, 17, 47}:
                    self.odd_proto.append({"src_ip": src, "dst_ip": dst, "proto_num": proto_num, "timestamp": ts})
                if proto_num == 47 and not hasattr(pkt, 'gre'):
                    self.odd_proto.append({"src_ip": src, "dst_ip": dst, "proto_num": proto_num, "timestamp": ts})
                if proto_num == 1 and hasattr(pkt, 'icmp'):
                    tp = getattr(pkt.icmp, "type", "")
                    if tp not in {"8", "0", ""}:
                        self.odd_proto.append({"src_ip": src, "dst_ip": dst, "proto_num": "ICMP/" + tp, "timestamp": ts})
            if hasattr(pkt, 'arp'):
                a = pkt.arp
                sip = a.src_proto_ipv4; sm = a.src_hw_mac
                tip = a.dst_proto_ipv4; tm = a.dst_hw_mac
                op = a.opcode
                self.arp_count[sip] += 1
                if sip and sm:
                    self.ip_to_macs[sip].add(sm)
                if sm and sip:
                    self.mac_to_ips[sm].add(sip)
                if sip and tip and sip == tip:
                    self.gratuitous_arp.append({
                        "ip": sip, "mac": sm or "-", "opcode": op,
                        "target_mac": tm or "-", "index": len(self.arp_count)
                    })
        except Exception as e:
            log_internal_error(f"Proto/ARP error: {e}")

    @staticmethod
    def _entropy(s):
        if not s:
            return 0.0
        p = Counter(s)
        lns = float(len(s))
        return -sum((c/lns) * math.log2(c/lns) for c in p.values())

    def finalize(self):
        results = {}

        # --- public_dest_ips ---
        entries = [
            (ip, proto, cnt)
            for ip, proto_map in self.ip_stats.items()
            for proto, cnt in proto_map.items()
        ]
        results["public_dest_ips"] = sorted(entries, key=lambda x: x[2], reverse=True)

        # --- port_proto_mismatches ---
        summary = Counter(
            (e["dst_ip"], e["dst_port"], e["protocol"])
            for e in self.port_mismatches
        )
        results["port_proto_mismatches"] = [
            {"dst_ip": ip, "dst_port": port, "protocol": proto, "count": cnt}
            for (ip, port, proto), cnt in summary.most_common()
        ]

        # --- DNS results ---
        results.update({
            "dns_failed": self.dns_failed,
            "dns_long": self.dns_long,
            "dns_rare": self.dns_rare,
            "dns_txt": self.dns_txt,
            "dns_entropy": self.dns_entropy
        })

        # --- HTTP summary ---
        http_summary = []
        for dom, info in self.http_domains.items():
            http_summary.append({
                "domain": dom,
                "methods": ", ".join(sorted(info["methods"])) or "-",
                "user_agents": ", ".join(sorted(info["user_agents"])) or "-",
                "content_types": ", ".join(sorted(info["content_types"])) or "-",
                "url_count": len(info["urls"]),
                "filenames": ", ".join(sorted(info["filenames"])) or "-",
                "request_body": "\n".join(sorted(info["bodies"])) or "-"
            })
        results.update({
            "http_summary": sorted(http_summary, key=lambda x: x["domain"]),
            "http_unusual_agents": sorted(self.unusual_agents),
            "http_file_info": self.file_info
        })

        # --- flow analysis & suspicious_ips set ---
        high, low, many_small, syn_scans, sus_ips = [], [], [], [], set()
        for (dst, port), st in self.flow_stats.items():
            if st["bytes"] > 500000 or st["pkts"] > 1000:
                high.append({"dst": dst, "port": port, "bytes": st["bytes"], "pkts": st["pkts"]})
                sus_ips.add(dst)
            if 0 < st["bytes"] < 100:
                low.append({"dst": dst, "port": port, "bytes": st["bytes"], "pkts": st["pkts"]})
            if st["syn_only"] > 5:
                for src, c in st["syn_srcs"].items():
                    if c > 2:
                        syn_scans.append({"src": src, "dst": dst, "port": port, "syn_count": c, "pkts": st["pkts"]})
                        sus_ips.add(src)
            if len(st["srcs"]) > 10 and st["bytes"] < 1000:
                many_small.append({"dst": dst, "port": port, "unique_srcs": len(st["srcs"]), "bytes": st["bytes"]})
                sus_ips.add(dst)
        results.update({
            "flows_high": sorted(high, key=lambda x: (x["dst"], -x["bytes"], -x["pkts"])),
            "flows_low": sorted(low, key=lambda x: (x["dst"], x["bytes"], x["pkts"])),
            "flows_many_small": sorted(many_small, key=lambda x: x["unique_srcs"], reverse=True),
            "flows_syn_scan": sorted(syn_scans, key=lambda x: x["src"]),
            "suspicious_ips": list(sus_ips)
        })

        # --- file_transfers (post-filtered by suspicious_ips) ---
        filtered_files = []
        for f in self.files:
            src, dst_ip = f["src_ip"], f["dst_ip"]
            is_macro = bool(f["macro_flag"])
            is_boring = f["content_type"] in BORING_MIMES
            if (not is_boring) or is_macro or src in sus_ips or dst_ip in sus_ips:
                filtered_files.append(f)
        results["file_transfers"] = filtered_files

        # --- creds_exposed ---
        results["creds_exposed"] = self.creds

        # --- beacon_patterns ---
        beacons = []
        for (src, dst), times in self.beacon_candidates.items():
            if len(times) < 6:
                continue
            times.sort()
            intervals = [round(times[i+1] - times[i]) for i in range(len(times)-1) if times[i+1] > times[i]]
            if len(intervals) < 5:
                continue
            cnts = Counter(intervals)
            most_int, most_cnt = cnts.most_common(1)[0]
            stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
            if most_cnt >= max(5, len(intervals)//2) and most_int >= 10 and (stdev < 10 or most_cnt/len(intervals) > 0.65):
                beacons.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "count": len(times),
                    "interval": most_int,
                    "interval_variance": round(stdev, 2),
                    "interval_counts": dict(cnts),
                    "sample_times": [str(int(t)) for t in times[:6]]
                })
        results["beacon_patterns"] = sorted(beacons, key=lambda x: (-x["count"], x["interval"]))

        # --- protocol & ARP/L2 oddities ---
        results.update({
            "weak_ssl": self.weak_ssl,
            "odd_proto": self.odd_proto,
            "gratuitous_arp": self.gratuitous_arp,
            "duplicate_ip": [{"ip": ip, "macs": list(macs)} for ip, macs in self.ip_to_macs.items() if len(macs) > 1],
            "duplicate_mac": [{"mac": mac, "ips": list(ips)} for mac, ips in self.mac_to_ips.items() if len(ips) > 1],
            "noisy_arp": [{"ip": ip, "count": cnt} for ip, cnt in self.arp_count.items() if cnt > 20]
        })

        return results

# --- Main analysis entrypoint ---
def main_analysis(pcap_path, progress_callback=None):
    total = fast_packet_count(pcap_path, progress_callback)
    ignore_patterns = load_domain_ignorelist()
    analyzer = PcapAnalyzer(ignore_patterns)
    try:
        cap = pyshark.FileCapture(pcap_path, keep_packets=False, only_summaries=False)
    except Exception as e:
        log_internal_error(f"PyShark open error: {e}")
        raise RuntimeError("Could not open PCAP for analysis.")
    for idx, pkt in enumerate(cap, 1):
        analyzer.process_packet(pkt)
        if progress_callback and (idx % 1000 == 0 or idx == total):
            progress_callback(f"Processed {idx} of {total} packets")
    cap.close()
    return analyzer.finalize()

# --- Report generation ---
def generate_report(results, template_path="templates/report.html"):
    env = Environment(loader=FileSystemLoader(os.path.dirname(template_path)))
    tpl = env.get_template(os.path.basename(template_path))
    html = tpl.render(results=results)
    path = os.path.abspath("pcap_report.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path

# --- GUI unchanged ---
class PcapTriageGUI:
    def __init__(self, root):
        self.root = root
        root.title("PCAP Triage Tool")
        root.geometry("1200x460")
        frm = tk.Frame(root, padx=20, pady=20)
        frm.pack(expand=True)
        btn = tk.Button(frm, text="Select PCAP File",
                        command=self.browse_and_analyze, height=3, width=20)
        btn.pack(pady=5)
        self.status = tk.Label(frm, text="", fg="navy", font=("Arial",11))
        self.status.pack(pady=10)
        self.progress = tk.Label(frm, text="", fg="green", font=("Arial",11))
        self.progress.pack(pady=2)

    def update_progress(self, msg):
        self.progress.config(text=msg)
        self.root.update_idletasks()

    def analyze_in_thread(self, pcap_path):
        try:
            self.status.config(text="Counting packets")
            self.progress.config(text="")
            self.root.update_idletasks()
            results = main_analysis(pcap_path, self.update_progress)
            self.status.config(text="Analysis complete! Opening report")
            rpt = generate_report(results)
            webbrowser.open('file://' + rpt)
            self.status.config(text="Done. You can select another file.")
            self.progress.config(text="")
        except Exception as e:
            log_internal_error(f"GUI error: {e}")
            self.status.config(text="Error during analysis.")
            self.progress.config(text="")
            messagebox.showerror("Error", str(e))

    def browse_and_analyze(self):
        file_path = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=[("PCAP files","*.pcap *.pcapng"),("All files","*.*")]
        )
        if file_path:
            self.status.config(text="Preparing analysis")
            self.progress.config(text="")
            threading.Thread(target=self.analyze_in_thread,
                args=(file_path,), daemon=True).start()

def main():
    root = tk.Tk()
    PcapTriageGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
