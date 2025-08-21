Short answer: the very first line `markdown starts a **code fence**, so everything until the next closing ` is treated as literal text (no Markdown rendering). Later you accidentally “close” it when you open another fence (`sh), so the **bottom** resumes rendering. You also left that `sh block unclosed.

Fix = remove the stray \`\`\`markdown and close every code block you *do* want. Here’s your file cleaned up so the whole thing renders as Markdown:

````markdown
# PCAP Triage Tool

A fast, flexible, GUI-driven Python tool for **automated triage and anomaly reporting** from PCAP files.  
Network defenders, threat hunters, and incident responders: get everything you need in one browser-ready report.

---

## Features

- **One-Pass Analysis:** Scans the PCAP in a single pass for maximum speed (handles multi-GB PCAPs easily)
- **Modern, Customizable GUI:** Select PCAP files, see progress, get a browser-based report—no command line needed
- **Exportable HTML Reports:** Collapsible, structured, and readable—ideal for briefings, audits, and hunt docs
- **Wide Module Coverage**:
  - External (non-RFC1918) destination IPs and protocol hierarchy
  - Domain Events Timeline that shows DNS Queries and whether the domain was browsed and responded, including client/server payload bytes (no header bytes)
  - Port/protocol mismatches (e.g., HTTP on non-standard ports)
  - DNS anomalies (failed lookups, long/random/rare domains, tunneling indicators)
  - HTTP(S) summaries (domains, methods, agents, files, content types, request bodies)
  - Suspicious flows (long, short, many small, scans, beacons)
  - File transfers (SHA256, macro-enabled docs, rare MIME types, sender/receiver IPs)
  - Credentials and sensitive data exposure (HTTP, FTP, SMTP, SNMP, Telnet)
  - Beaconing/timing patterns (periodic C2, RAT callbacks)
  - Protocol oddities (weak SSL/TLS, unknown transport/tunnels)
  - ARP and Layer 2 oddities (gratuitous ARP, spoofing, duplicate MAC/IP, noisy ARP hosts)
- **Customizable Ignore Lists:** Use `domain_ignore.txt` for noisy/known-safe domains (supports `*example.com` wildcards)
- **Error-Resilient:** All errors logged to `pcap_triage_error.log`
- **Easy Extensibility:** Add modules in the `PcapAnalyzer` class

---

## Screenshots

**GUI: Select a PCAP File**

![GUI Select File](screenshots/gui-select-file.png)

**Sample Report: Triage Overview in Browser**

![HTML Report](screenshots/triage-report.png)

*(Screenshots above are released under [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).)*

---

## Installation

**Requirements**
- Python 3.8+ (recommend 3.10+)
- [PyShark](https://github.com/KimiNewt/pyshark)
- [Jinja2](https://palletsprojects.com/p/jinja/)
- (Optional for speed) [tshark](https://www.wireshark.org/docs/man-pages/tshark.html), [tcpdump](https://www.tcpdump.org/)

**Install dependencies**
```sh
pip install pyshark jinja2
# For Ubuntu/Debian (and to get the file-select GUI):
sudo apt install tshark tcpdump python3-tk
````

**Clone and run**

```sh
git clone https://github.com/Pb-22/pcap-triage-tool.git
cd pcap-triage-tool
python pcap_triage.py
```

## Usage

1. Run: `python pcap_triage.py`
2. Select a PCAP file in the GUI.
3. Watch the progress.
4. The report opens automatically in your browser (`pcap_report.html`).

## Output

Clean, collapsible, browser-based report ready to archive, print, or copy to tickets.

---

## Customization

### Ignore Known Domains

* Place `domain_ignore.txt` in the script directory.
* Add one domain per line (e.g., `adobe.io`, `*.localdomain`, `*microsoft.com`).
* Wildcards are supported.

### Add New Detection Modules

* Extend `PcapAnalyzer.process_packet()` and `finalize()`.

---

## Troubleshooting

* No report or browser error? Check `pcap_triage_error.log`.
* GUI not starting? Install Tkinter (`sudo apt install python3-tk` on Ubuntu/Debian).
* PyShark complains about `tshark`? Install Wireshark/tshark (`sudo apt install tshark`).

---

## FAQ

**Q: Does this modify my PCAP?**
A: No. Analysis is read-only.

**Q: Large PCAPs?**
A: Yes—single-pass, memory-light, with progress.

**Q: CSV/JSON export?**
A: Default is HTML; CSV is easy via browser. PRs welcome for JSON.

**Q: Safe for confidential material?**
A: Processing is local. Review the code to confirm.

---

## License

Released under **CC0 1.0 Universal (Public Domain)**. Use, share, remix, or commercialize freely. Attribution appreciated.

## Credits

Written by **Pb-22**, founder and CEO of BriMerica.
PRs and feedback welcome—open an issue or contact me directly.

````


