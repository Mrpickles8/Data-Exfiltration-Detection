# Data-Exfiltration-Detection

## Objective
Detect and investigate unauthorized data exfiltration across DNS tunneling,
FTP, HTTP, and ICMP using Wireshark and Splunk.

### Skills Learned
- DNS tunneling detection — suspicious domain, query volume, source IP
- FTP analysis — credential-based exfiltration (guest/root accounts),
  file identification, largest payload detection
- FTP TCP stream following — hidden flag extraction from CSV transfer
- HTTP exfiltration — Splunk traffic spike correlation per source IP
- HTTP payload inspection — hidden flag extraction
- ICMP exfiltration — payload size anomaly detection, flag extraction
- Multi-protocol IOC pivoting across four exfil channels

### Tools Used
- Wireshark (display filters, TCP stream follow, sort by packet length)
- Splunk SIEM (URI analysis, traffic volume graphing)

## Steps
DNS: suspicious tunneling domain identified, query count and source IP
(max requests) determined. FTP: `ftp contains "guest"` → 5 connections.
`ftp contains "root"` → `customer_data.xlsx` exfiltrated. Sort by length
→ `192.168.1.105` largest payload. CSV stream → flag `THM{ftp_exfil_hidden_flag}`.
HTTP: Splunk traffic spike → `192.168.1.103` compromised host. Stream inspection
→ flag `THM{http_raw_3xf1ltr4t10n_succ3ss}`. ICMP: payload inspection →
flag `THM{1cmp_3ch0_3xf1ltr4t10n_succ3ss}`.

*Ref 1: Wireshark FTP — root account exfil + 192.168.1.105 largest payload*
*Ref 2: Splunk traffic spike graph identifying 192.168.1.103 HTTP exfil host*
