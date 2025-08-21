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

THEME = {
    "bg": "#282A36",
    "fg": "#F8F8F2",
    "comment": "#6272A4",
    "pink": "#FF79C6",
    "purple": "#BD93F9",
    "yellow": "#F1FA8C",
    "green": "#50FA7B",
    "cyan": "#8BE9FD",
    "red": "#FF5555",
    "orange": "#FFB86C",
    "border": "#44475A",
    "heading_bg": "#44475A",
    "heading_fg": "#BD93F9",
    "link": "#8BE9FD",
    "arrow": "#FF79C6",
    "table_head_bg": "#44475A",
    "table_head_fg": "#BD93F9",
    "table_row_even_bg": "#3D3F50",
    "table_row_odd_bg": "#282A36",
    "table_cell_border": "#44475A"
}

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b")
TOKEN_RE = re.compile(r"(?:token|api[_-]?key|secret)[=:]?\s*([\w-]{10,})", re.IGNORECASE)

PROTOCOL_PORTS = {
    "HTTP": {80, 8080}, "HTTPS": {443}, "SSH": {22}, "FTP": {21},
    "DNS": {53}, "TELNET": {23}, "SMTP": {25, 587}, "IMAP": {143, 993},
    "POP": {110, 995}, "RDP": {3389}, "SMB": {445, 139}
}
TLD_COMMON = {"com","net","org","edu","gov","mil","int","us","uk","ca","de","fr","au","jp","kr","cn"}
COMMON_AGENTS = {"mozilla","chrome","safari","firefox","edge","opera","curl","wget"}
BORING_MIMES = {
    "text/html","application/json","application/xml","text/javascript","image/png","image/jpeg",
    "image/gif","image/x-icon","font/woff","font/woff2","application/ocsp-response",
    "application/x-x509-ca-cert","application/pkix-crl"
}
MACRO_MIMES = {
    "application/vnd.ms-office",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12"
}
MACRO_EXTS = {".docm",".xlsm",".pptm",".docb",".doc",".dotm"}
QUERY_BROWSE_GAP = 60.0

def silent_excepthook(exc_type, value, tb):
    with open("pcap_triage_error.log", "a") as log:
        log.write("UNCAUGHT ERROR:\n" + "".join(traceback.format_exception(exc_type, value, tb)))
sys.excepthook = silent_excepthook

def log_internal_error(msg):
    with open("pcap_triage_error.log", "a") as log:
        log.write(msg + "\n")

def fast_packet_count(pcap_path, progress_callback=None):
    for cmd in (['tshark','-r',pcap_path,'-T','fields','-e','frame.number'],
                ['tcpdump','-r',pcap_path]):
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            count = result.stdout.count('\n')
            if count:
                if progress_callback:
                    progress_callback(f"Counting packets: {count} found")
                return count
        except Exception as e:
            log_internal_error(f"{cmd[0]} count error: {e}")
    count = 0
    for idx, _ in enumerate(pyshark.FileCapture(pcap_path, only_summaries=True, keep_packets=False), 1):
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

def normalize_domain(name):
    if not name:
        return ""
    s = str(name).strip().lower()
    # remove :port if present
    if ":" in s:
        s = s.split(":", 1)[0]
    return s.rstrip(".")

def domain_is_ignored(domain, ignore_patterns):
    d = normalize_domain(domain)
    if not d:
        return False
    for raw in ignore_patterns:
        p = normalize_domain(raw)
        if not p:
            continue
        # Support: example.com | .example.com | *.example.com | *example.com
        if p.startswith("*."):
            suf = p[2:]
        elif p.startswith("*"):
            suf = p[1:].lstrip(".")
        elif p.startswith("."):
            suf = p[1:]
        else:
            suf = p
        if d == suf or d.endswith("." + suf):
            return True
    return False


def get_ip_src(pkt):
    if hasattr(pkt, 'ip'):
        return pkt.ip.src
    if hasattr(pkt, 'ipv6'):
        return pkt.ipv6.src
    return None

def get_ip_dst(pkt):
    if hasattr(pkt, 'ip'):
        return pkt.ip.dst
    if hasattr(pkt, 'ipv6'):
        return pkt.ipv6.dst
    return None

def get_pkt_len(pkt):
    try:
        return int(getattr(pkt.frame_info, 'len', 0))
    except Exception:
        try:
            return int(getattr(pkt, 'length', 0))
        except Exception:
            return 0

class PcapAnalyzer:
    def __init__(self, ignore_patterns):
        self.ignore_patterns = ignore_patterns
        self.ip_stats = defaultdict(lambda: defaultdict(int))
        self.port_mismatches = []
        self.dns_failed = []
        self.dns_long = []
        self.dns_rare = []
        self.dns_txt = []
        self.dns_entropy = []
        self.http_domains = defaultdict(lambda: {"urls": set(), "methods": set(), "user_agents": set(), "content_types": set(), "filenames": set(), "bodies": set()})
        self.unusual_agents = set()
        self.file_info = []
        self.flow_stats = defaultdict(lambda: {"bytes": 0, "pkts": 0, "syn_only": 0, "srcs": set(), "syn_srcs": defaultdict(int)})
        self.files = []
        self.creds = []
        self.beacon_candidates = defaultdict(list)
        self.weak_ssl = []
        self.odd_proto = []
        self.ip_to_macs = defaultdict(set)
        self.mac_to_ips = defaultdict(set)
        self.gratuitous_arp = []
        self.arp_count = defaultdict(int)
        self.pending_dns = {}
        self.domain_events = []

    def process_packet(self, pkt):
        try:
            dst = get_ip_dst(pkt)
            if dst and is_public_ip(dst):
                layers = []
                if getattr(pkt, "highest_layer", None):
                    layers.append(pkt.highest_layer)
                if getattr(pkt, "transport_layer", None) and pkt.transport_layer != pkt.highest_layer:
                    layers.append(pkt.transport_layer)
                self.ip_stats[dst][" > ".join(layers) if layers else "UNKNOWN"] += 1
        except Exception as e:
            log_internal_error(f"Non-RFC1918 error: {e}")

        try:
            if hasattr(pkt, 'tcp'):
                dst_port = int(pkt.tcp.dstport)
                proto = pkt.highest_layer
                if proto in PROTOCOL_PORTS and dst_port not in PROTOCOL_PORTS[proto]:
                    self.port_mismatches.append({"src_ip": get_ip_src(pkt), "dst_ip": get_ip_dst(pkt), "dst_port": dst_port, "protocol": proto})
        except Exception as e:
            log_internal_error(f"Port/proto mismatch error: {e}")

        try:
            if hasattr(pkt, 'dns'):
                d = pkt.dns
                name = getattr(d, 'qry_name', None)
                if name:
                    dom = normalize_domain(name)
                    if not domain_is_ignored(dom, self.ignore_patterns):
                        tld = dom.split('.')[-1]
                        if len(dom) > 40:
                            self.dns_long.append(dom)
                        if tld not in TLD_COMMON:
                            self.dns_rare.append(dom)
                        if self._entropy(dom) > 4.0:
                            self.dns_entropy.append(dom)
                        if str(getattr(d, 'qry_type', '')).upper() in ('16', 'TXT'):
                            self.dns_txt.append(dom)
                if getattr(d, 'flags_rcode', "0") != "0":
                    q = normalize_domain(getattr(d, 'qry_name', '(unknown)'))
                    if not domain_is_ignored(q, self.ignore_patterns):
                        self.dns_failed.append(q)
        except Exception as e:
            log_internal_error(f"DNS error: {e}")

        try:
            if hasattr(pkt, 'dns'):
                d = pkt.dns
                ts = float(pkt.sniff_timestamp)
                trans_id = getattr(d, 'id', None)
                client_ip = get_ip_src(pkt)
                dns_server = get_ip_dst(pkt)
                if trans_id:
                    if str(getattr(d, 'flags_response', '0')) in ('0', 'False', 'false'):
                        qtype = str(getattr(d, 'qry_type', '')).upper()
                        name = normalize_domain(getattr(d, 'qry_name', None))
                        if name and qtype in ('1', '28', 'A', 'AAAA') and not domain_is_ignored(name, self.ignore_patterns):
                            key = (trans_id, client_ip, dns_server)
                            event = {"domain": name, "query_time": ts, "client_ip": client_ip, "dns_server": dns_server,
                                     "resolved_ips": set(), "browsed": False, "responded": False,
                                     "potential_client_bytes": 0, "potential_server_bytes": 0, "first_browse_time": None}
                            self.pending_dns[key] = event
                            self.domain_events.append(event)
                    else:
                        key = (trans_id, get_ip_dst(pkt), get_ip_src(pkt))
                        if getattr(d, 'flags_rcode', '0') == '0' and key in self.pending_dns:
                            event = self.pending_dns.pop(key)
                            resp_name = normalize_domain(getattr(d, 'resp_name', getattr(d, 'qry_name', None)))
                            if resp_name:
                                event['domain'] = event['domain'] or resp_name
                            try:
                                if getattr(d, 'a', None):
                                    for ip in str(d.a).split(','):
                                        ip = ip.strip()
                                        if ip:
                                            event['resolved_ips'].add(ip)
                            except Exception:
                                pass
                            try:
                                if getattr(d, 'aaaa', None):
                                    for ip in str(d.aaaa).split(','):
                                        ip = ip.strip()
                                        if ip:
                                            event['resolved_ips'].add(ip)
                            except Exception:
                                pass
        except Exception as e:
            log_internal_error(f"DQV DNS error: {e}")

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
                        self.file_info.append({"domain": host, "url": url or "", "content_type": ct or "", "filename": fn or ""})
        except Exception as e:
            log_internal_error(f"HTTP error: {e}")

        try:
            if hasattr(pkt, 'tcp'):
                src = get_ip_src(pkt); dst = get_ip_dst(pkt)
                if src and dst:
                    key = (dst, int(pkt.tcp.dstport))
                    fs = self.flow_stats[key]
                    fs["pkts"] += 1
                    fs["srcs"].add(src)
                    try:
                        fs["bytes"] += get_pkt_len(pkt)
                    except Exception:
                        pass
                    if getattr(pkt.tcp, "flags", "") == "0x0002":
                        fs["syn_only"] += 1
                        fs["syn_srcs"][src] += 1
        except Exception as e:
            log_internal_error(f"Flow error: {e}")

        try:
            if hasattr(pkt, 'http'):
                h = pkt.http
                host = getattr(h, "host", "")
                if not domain_is_ignored(host, self.ignore_patterns):
                    src = get_ip_src(pkt); dst = get_ip_dst(pkt)
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
                    if not is_boring or is_macro:
                        self.files.append({"src_ip": src, "dst_ip": dst, "domain": host,
                                           "url": getattr(h, "request_full_uri", "") or "", "filename": fn or "",
                                           "content_type": ct, "sha256": sha256, "size": size,
                                           "macro_flag": "Yes" if is_macro else ""})
        except Exception as e:
            log_internal_error(f"File transfer error: {e}")

        try:
            src = get_ip_src(pkt); dst = get_ip_dst(pkt)
            if hasattr(pkt, 'http'):
                auth = getattr(pkt.http, "authorization", "")
                if auth.lower().startswith("basic "):
                    try:
                        dec = base64.b64decode(auth.split()[1]).decode(errors="ignore")
                        if ":" in dec:
                            self.creds.append({"type": "HTTP Basic", "protocol": "HTTP", "src_ip": src, "dst_ip": dst, "detail": dec})
                    except Exception:
                        pass
                for field in [getattr(pkt.http, "request_full_uri", ""), getattr(pkt.http, "file_data", None)]:
                    if field:
                        for e in EMAIL_RE.findall(field):
                            self.creds.append({"type": "Email", "protocol": "HTTP", "src_ip": src, "dst_ip": dst, "detail": e})
                        for t in TOKEN_RE.findall(field):
                            self.creds.append({"type": "Token/String", "protocol": "HTTP", "src_ip": src, "dst_ip": dst, "detail": t})
            if hasattr(pkt, 'ftp'):
                cmd = pkt.ftp.request_command.upper()
                arg = getattr(pkt.ftp, "request_arg", "")
                if cmd == "USER":
                    self.creds.append({"type": "FTP USER", "protocol": "FTP", "src_ip": src, "dst_ip": dst, "detail": arg})
                elif cmd == "PASS":
                    self.creds.append({"type": "FTP PASS", "protocol": "FTP", "src_ip": src, "dst_ip": dst, "detail": arg})
            if hasattr(pkt, 'telnet'):
                line = str(pkt.telnet)
                if "login:" in line.lower():
                    self.creds.append({"type": "Telnet Username Prompt", "protocol": "TELNET", "src_ip": src, "dst_ip": dst, "detail": line})
                if "password:" in line.lower():
                    self.creds.append({"type": "Telnet Password Prompt", "protocol": "TELNET", "src_ip": src, "dst_ip": dst, "detail": line})
            if hasattr(pkt, 'smtp'):
                payload = str(pkt.smtp)
                if "AUTH LOGIN" in payload or "AUTH PLAIN" in payload:
                    self.creds.append({"type": "SMTP AUTH", "protocol": "SMTP", "src_ip": src, "dst_ip": dst, "detail": payload})
                for e in EMAIL_RE.findall(payload):
                    self.creds.append({"type": "Email", "protocol": "SMTP", "src_ip": src, "dst_ip": dst, "detail": e})
            if hasattr(pkt, 'snmp'):
                com = getattr(pkt.snmp, "community", None)
                if com:
                    self.creds.append({"type": "SNMP Community", "protocol": "SNMP", "src_ip": src, "dst_ip": dst, "detail": com})
        except Exception as e:
            log_internal_error(f"Creds error: {e}")

        try:
            src = get_ip_src(pkt); dst = get_ip_dst(pkt)
            if src and dst and is_public_ip(dst):
                ts = float(pkt.sniff_timestamp)
                if hasattr(pkt, 'http'):
                    host = getattr(pkt.http, "host", None)
                    if host and domain_is_ignored(host, self.ignore_patterns):
                        return
                self.beacon_candidates[(src, dst)].append(ts)
        except Exception as e:
            log_internal_error(f"Beaconing error: {e}")

        try:
            proto_num = None
            if hasattr(pkt, 'ip'):
                proto_num = int(getattr(pkt.ip, "proto", 0))
            elif hasattr(pkt, 'ipv6'):
                proto_num = int(getattr(pkt.ipv6, "nxt", 0))
            if proto_num is not None:
                src = get_ip_src(pkt); dst = get_ip_dst(pkt); ts = str(pkt.sniff_time)
                if proto_num not in {1, 2, 6, 17, 47, 58}:
                    self.odd_proto.append({"src_ip": src, "dst_ip": dst, "proto_num": proto_num, "timestamp": ts})
                if proto_num == 47 and not hasattr(pkt, 'gre'):
                    self.odd_proto.append({"src_ip": src, "dst_ip": dst, "proto_num": proto_num, "timestamp": ts})
                if proto_num == 1 and hasattr(pkt, 'icmp'):
                    tp = getattr(pkt.icmp, "type", "")
                    if tp not in {"8", "0", ""}:
                        self.odd_proto.append({"src_ip": src, "dst_ip": dst, "proto_num": "ICMP/" + tp, "timestamp": ts})
                if proto_num == 58 and hasattr(pkt, 'icmpv6'):
                    tp = getattr(pkt.icmpv6, "type", "")
                    if tp not in {"128", "129", ""}:
                        self.odd_proto.append({"src_ip": src, "dst_ip": dst, "proto_num": "ICMPv6/" + tp, "timestamp": ts})
            if hasattr(pkt, 'arp'):
                a = pkt.arp
                sip = a.src_proto_ipv4; sm = a.src_hw_mac
                tip = a.dst_proto_ipv4; tm = a.dst_hw_mac
                op = a.opcode
                self.arp_count[sip] += 1
                if sip and sm: self.ip_to_macs[sip].add(sm)
                if sm and sip: self.mac_to_ips[sm].add(sip)
                if sip and tip and sip == tip:
                    self.gratuitous_arp.append({"ip": sip, "mac": sm or "-", "opcode": op, "target_mac": tm or "-", "index": len(self.arp_count)})
        except Exception as e:
            log_internal_error(f"Proto/ARP error: {e}")

        try:
            src = get_ip_src(pkt); dst = get_ip_dst(pkt)
            if src and dst:
                ts = float(pkt.sniff_timestamp)
                pkt_bytes = get_pkt_len(pkt)
                for event in self.domain_events:
                    if event['resolved_ips'] and ts > event['query_time']:
                        if src == event['client_ip'] and dst in event['resolved_ips']:
                            event['potential_client_bytes'] += pkt_bytes
                            if ts - event['query_time'] < QUERY_BROWSE_GAP and not event['browsed']:
                                event['browsed'] = True; event['first_browse_time'] = ts
                        elif src in event['resolved_ips'] and dst == event['client_ip']:
                            event['potential_server_bytes'] += pkt_bytes
                            if event['browsed'] and not event['responded'] and event['first_browse_time'] and ts - event['first_browse_time'] < 1.0:
                                event['responded'] = True
        except Exception as e:
            log_internal_error(f"DQV browse error: {e}")

    @staticmethod
    def _entropy(s):
        if not s: return 0.0
        p = Counter(s); lns = float(len(s))
        return -sum((c/lns) * math.log2(c/lns) for c in p.values())

    def finalize(self):
        results = {}
        entries = [(ip, proto, cnt) for ip, proto_map in self.ip_stats.items() for proto, cnt in proto_map.items()]
        results["public_dest_ips"] = sorted(entries, key=lambda x: x[2], reverse=True)
        summary = Counter((e["dst_ip"], e["dst_port"], e["protocol"]) for e in self.port_mismatches)
        results["port_proto_mismatches"] = [{"dst_ip": ip, "dst_port": port, "protocol": proto, "count": cnt} for (ip, port, proto), cnt in summary.most_common()]
        results.update({"dns_failed": self.dns_failed, "dns_long": self.dns_long, "dns_rare": self.dns_rare, "dns_txt": self.dns_txt, "dns_entropy": self.dns_entropy})
        http_summary = []
        for dom, info in self.http_domains.items():
            http_summary.append({"domain": dom, "methods": ", ".join(sorted(info["methods"])) or "-", "user_agents": ", ".join(sorted(info["user_agents"])) or "-", "content_types": ", ".join(sorted(info["content_types"])) or "-", "url_count": len(info["urls"]), "filenames": ", ".join(sorted(info["filenames"])) or "-", "request_body": "\n".join(sorted(info["bodies"])) or "-"})
        results.update({"http_summary": sorted(http_summary, key=lambda x: x["domain"]), "http_unusual_agents": sorted(self.unusual_agents), "http_file_info": self.file_info})
        high, low, many_small, syn_scans, sus_ips = [], [], [], [], set()
        for (dst, port), st in self.flow_stats.items():
            if st["bytes"] > 500000 or st["pkts"] > 1000:
                high.append({"dst": dst, "port": port, "bytes": st["bytes"], "pkts": st["pkts"]}); sus_ips.add(dst)
            if 0 < st["bytes"] < 100:
                low.append({"dst": dst, "port": port, "bytes": st["bytes"], "pkts": st["pkts"]})
            if st["syn_only"] > 5:
                for src, c in st["syn_srcs"].items():
                    if c > 2:
                        syn_scans.append({"src": src, "dst": dst, "port": port, "syn_count": c, "pkts": st["pkts"]}); sus_ips.add(src)
            if len(st["srcs"]) > 10 and st["bytes"] < 1000:
                many_small.append({"dst": dst, "port": port, "unique_srcs": len(st["srcs"]), "bytes": st["bytes"]}); sus_ips.add(dst)
        results.update({"flows_high": sorted(high, key=lambda x: (x["dst"], -x["bytes"], -x["pkts"])), "flows_low": sorted(low, key=lambda x: (x["dst"], x["bytes"], x["pkts"])), "flows_many_small": sorted(many_small, key=lambda x: x["unique_srcs"], reverse=True), "flows_syn_scan": sorted(syn_scans, key=lambda x: x["src"]), "suspicious_ips": list(sus_ips)})

        filtered_files = []
        for f in self.files:
            src, dst_ip = f["src_ip"], f["dst_ip"]
            is_macro = bool(f["macro_flag"]); is_boring = f["content_type"] in BORING_MIMES
            if (not is_boring) or is_macro or src in sus_ips or dst_ip in sus_ips:
                filtered_files.append(f)
        results["file_transfers"] = filtered_files
        results["creds_exposed"] = self.creds

        beacons = []
        for (src, dst), times in self.beacon_candidates.items():
            if len(times) < 6: continue
            times.sort()
            intervals = [round(times[i+1] - times[i]) for i in range(len(times)-1) if times[i+1] > times[i]]
            if len(intervals) < 5: continue
            cnts = Counter(intervals); most_int, most_cnt = cnts.most_common(1)[0]
            stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
            if most_cnt >= max(5, len(intervals)//2) and most_int >= 10 and (stdev < 10 or most_cnt/len(intervals) > 0.65):
                beacons.append({"src_ip": src, "dst_ip": dst, "count": len(times), "interval": most_int, "interval_variance": round(stdev, 2), "interval_counts": dict(cnts), "sample_times": [str(int(t)) for t in times[:6]]})
        results["beacon_patterns"] = sorted(beacons, key=lambda x: (-x["count"], x["interval"]))

        results.update({"weak_ssl": self.weak_ssl, "odd_proto": self.odd_proto, "gratuitous_arp": self.gratuitous_arp,
                        "duplicate_ip": [{"ip": ip, "macs": list(macs)} for ip, macs in self.ip_to_macs.items() if len(macs) > 1],
                        "duplicate_mac": [{"mac": mac, "ips": list(ips)} for mac, ips in self.mac_to_ips.items() if len(ips) > 1],
                        "noisy_arp": [{"ip": ip, "count": cnt} for ip, cnt in self.arp_count.items() if cnt > 20]})

        d_qv = []
        for e in self.domain_events:
            client_bytes = e['potential_client_bytes'] if e['browsed'] else 0
            server_bytes = e['potential_server_bytes'] if e['browsed'] else 0
            d_qv.append({"domain": e['domain'], "queried": "Y" if e.get('query_time') else "N", "browsed": "Y" if e['browsed'] else "N",
                         "responded": "Y" if e['responded'] else "N", "client_data_bytes": client_bytes, "server_data_bytes": server_bytes})
        results["domains_queried_visited"] = d_qv
        results["domains_queried_and_visited"] = d_qv

        # ---------- FINAL DOMAIN-IGNORE FILTERS ----------
        def _not_ignored(s):
            try:
                return bool(s) and not domain_is_ignored(s, self.ignore_patterns)
            except Exception:
                return True

        for key in ("dns_failed","dns_long","dns_rare","dns_txt","dns_entropy"):
            if key in results and isinstance(results[key], list):
                results[key] = [d for d in results[key] if _not_ignored(normalize_domain(d))]

        if "http_summary" in results:
            results["http_summary"] = [row for row in results["http_summary"] if _not_ignored(normalize_domain(row.get("domain","")))]

        if "http_file_info" in results:
            results["http_file_info"] = [row for row in results["http_file_info"] if _not_ignored(normalize_domain(row.get("domain","")))]

        if "file_transfers" in results:
            results["file_transfers"] = [row for row in results["file_transfers"] if _not_ignored(normalize_domain(row.get("domain","")))]

        if "domains_queried_visited" in results:
            results["domains_queried_visited"] = [row for row in results["domains_queried_visited"] if _not_ignored(normalize_domain(row.get("domain","")))]

        # Also provide the alias with the filtered set
        results["domains_queried_and_visited"] = results.get("domains_queried_visited", [])

        return results

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

def _build_dracula_css(t):
    return f"""
<style id="dracula-theme">
:root{{--gap:14px}}
html,body{{background:{t['bg']};color:{t['fg']};font-family:system-ui,-apple-system,'Segoe UI',Roboto,Ubuntu,'Helvetica Neue',Arial,'Noto Sans',sans-serif;font-size:19px;line-height:1.65;margin:0}}
/* Title (no bar/border) */
h1{{
  color:{t['fg']};
  background:transparent;
  border:none;
  padding:0 16px;
  margin:calc(var(--gap) + 2px) var(--gap) var(--gap);
  font-size:2.6rem;
  font-weight:800;
  letter-spacing:0.3px;
}}
a{{color:{t['link']}}}

/* Top-level collapsible sections */
details{{border:1px solid {t['border']};border-radius:10px;margin:var(--gap);background:rgba(255,255,255,0.02)}}
details>summary{{
  cursor:pointer;list-style:none;
  padding:12px 16px 12px 36px;
  background:{t['heading_bg']};color:{t['heading_fg']};
  font-weight:700;font-size:1.40rem;border-radius:10px;position:relative;margin:0
}}
details>summary::-webkit-details-marker{{display:none}}
details>summary::marker{{content:""}}
details>summary::before{{content:"▸";color:{t['arrow']};position:absolute;left:12px;top:10px}}
details[open]>summary::before{{content:"▾"}}

/* Subheadings (nested details inside a section) */
details details{{margin:calc(var(--gap) - 6px) var(--gap);border-color:{t['border']}}}
details details>summary{{
  font-size:1.20rem;               /* smaller than top-level */
  color:{t['green']};              /* Dracula green */
  background:{t['heading_bg']};
}}
details details>summary::before{{color:{t['green']};top:9px}}

/* Fallback if a template uses raw h2/h3/h4 for subheads */
h2,h3,h4{{display:block;padding:12px 16px 12px 36px;background:{t['heading_bg']};border-radius:10px;margin:var(--gap);font-weight:700}}
h2{{color:{t['heading_fg']};font-size:1.40rem}}
h3,h4{{color:{t['green']};font-size:1.20rem}}

/* Tables */
table{{width:calc(100% - 2*var(--gap));border-collapse:collapse;margin:8px var(--gap) 14px}}
table th,table td{{border:1px solid {t['table_cell_border']};padding:8px 10px;text-align:left;font-size:1.02rem}}
table th{{background:{t['table_head_bg']};color:{t['table_head_fg']}}}
table td{{background:{t['table_row_odd_bg']};color:{t['fg']}}}
table tr:nth-child(even) td{{background:{t['table_row_even_bg']};color:{t['fg']}}}
hr{{display:none}}
</style>
"""



def _inject_theme_and_normalize(html, theme):
    css = _build_dracula_css(theme)
    if "</head>" in html:
        html = html.replace("</head>", css + "</head>", 1)
    else:
        html = css + html

    normalize_js = """
<script>
document.addEventListener('DOMContentLoaded',function(){
  var ARROWS=/[\\u25B8\\u25BA\\u25B6\\u25BE\\u203A\\u00BB\\u2023\\u2022\\u25B7\\u25BD]+$/;

  // Clean any trailing arrow glyphs the template may inject
  document.querySelectorAll('details>summary').forEach(function(s){
    s.textContent = (s.textContent||'').replace(ARROWS,'').trim();
  });

  // Wrap H2/H3/H4 headings into their own <details> so sub-sections collapse
  var heads = Array.from(document.querySelectorAll('h2, h3, h4'));
  heads.forEach(function(h){
    // If the next element is already a <details>, do nothing
    var first = h.nextElementSibling;
    if(!first) return;

    // If heading already converted on this page, skip
    if(h.getAttribute('data-autowrapped') === '1') return;

    // Build a details block and move all following siblings up to the next H2/H3/H4 or <details>
    var det = document.createElement('details');
    var sum = document.createElement('summary');
    sum.textContent = (h.textContent||'').replace(ARROWS,'').trim();
    det.appendChild(sum);

    var node = first;
    while(node && !/^H[2-4]$/i.test(node.tagName) && node.tagName.toLowerCase()!=='details'){
      var next = node.nextElementSibling;
      det.appendChild(node);
      node = next;
    }
    h.setAttribute('data-autowrapped','1');
    h.replaceWith(det);
  });
});
</script>"""

    if "</body>" in html:
        html = html.replace("</body>", normalize_js + "</body>", 1)
    else:
        html = html + normalize_js
    return html


def _render_domains_section(rows):
    if rows:
        body = "".join(
            f"<tr><td>{r['domain']}</td><td>{r['queried']}</td>"
            f"<td>{r['browsed']}</td><td>{r['responded']}</td>"
            f"<td>{r['client_data_bytes']}</td><td>{r['server_data_bytes']}</td></tr>"
            for r in rows
        )
        table = ("<table><thead><tr>"
                 "<th>Domain</th><th>Queried</th><th>Browsed</th><th>Responded</th>"
                 "<th>Client Bytes</th><th>Server Bytes</th>"
                 "</tr></thead><tbody>"+body+"</tbody></table>")
    else:
        table = "<p>(no DNS→browse pairs found)</p>"
    return "<details id='domains-queried-visited'><summary>Domains Queried &amp; Visited</summary>"+table+"</details>"

def _place_domains_after_external(html, domains_html):
    html = re.sub(r"<details[^>]*id=[\"']domains-queried-visited[\"'][\s\S]*?</details>", "", html, flags=re.I)
    m = re.search(r"<summary[^>]*>\s*External\s*\(Non[-\s]*RFC1918\)\s*Destination\s*IPs\s*</summary>", html, flags=re.I)
    if m:
        close_idx = html.find("</details>", m.end())
        if close_idx != -1:
            insert_at = close_idx + len("</details>")
            return html[:insert_at] + domains_html + html[insert_at:]
    m2 = re.search(r"</h1>", html, flags=re.I)
    return (html[:m2.end()] + domains_html + html[m2.end():]) if m2 else (domains_html + html)

def generate_report(results, template_path="templates/report.html"):
    env = Environment(loader=FileSystemLoader(os.path.dirname(template_path)))
    tpl = env.get_template(os.path.basename(template_path))
    html = tpl.render(results=results)
    html = _inject_theme_and_normalize(html, THEME)
    domains_html = _render_domains_section(results.get("domains_queried_visited", []))
    html = _place_domains_after_external(html, domains_html)
    path = os.path.abspath("pcap_report.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path

class PcapTriageGUI:
    def __init__(self, root):
        self.root = root
        root.title("PCAP Triage Tool")
        root.geometry("1200x460")
        frm = tk.Frame(root, padx=20, pady=20)
        frm.pack(expand=True)
        tk.Button(frm, text="Select PCAP File", command=self.browse_and_analyze, height=3, width=20).pack(pady=5)
        self.status = tk.Label(frm, text="", fg="navy", font=("Arial",11)); self.status.pack(pady=10)
        self.progress = tk.Label(frm, text="", fg="green", font=("Arial",11)); self.progress.pack(pady=2)

    def update_progress(self, msg):
        self.progress.config(text=msg); self.root.update_idletasks()

    def analyze_in_thread(self, pcap_path):
        try:
            self.status.config(text="Counting packets"); self.progress.config(text=""); self.root.update_idletasks()
            results = main_analysis(pcap_path, self.update_progress)
            self.status.config(text="Analysis complete! Opening report")
            rpt = generate_report(results)
            webbrowser.open('file://' + rpt)
            self.status.config(text="Done. You can select another file."); self.progress.config(text="")
        except Exception as e:
            log_internal_error(f"GUI error: {e}")
            self.status.config(text="Error during analysis."); self.progress.config(text="")
            messagebox.showerror("Error", str(e))

    def browse_and_analyze(self):
        file_path = filedialog.askopenfilename(title="Select PCAP file", filetypes=[("PCAP files","*.pcap *.pcapng"),("All files","*.*")])
        if file_path:
            self.status.config(text="Preparing analysis"); self.progress.config(text="")
            threading.Thread(target=self.analyze_in_thread, args=(file_path,), daemon=True).start()

def main():
    root = tk.Tk()
    PcapTriageGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
