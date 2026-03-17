<div align="center">

```
  ██╗  ██╗██╗  ██╗
  ██║  ██║╚██╗██╔╝
  ███████║ ╚███╔╝
  ██╔══██║ ██╔██╗
  ██║  ██║██╔╝ ██╗
  ╚═╝  ╚═╝╚═╝  ╚═╝
```

# hx

### *Advanced HTTP Probe Tool*

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux%20amd64-lightgrey?style=flat-square&logo=linux)](.)
[![Version](https://img.shields.io/badge/Version-1.0.0-blueviolet?style=flat-square)](.)
[![0xAscension](https://img.shields.io/badge/0xAscension-red?style=flat-square)](https://github.com/0xAscension)

> Fast HTTP probing with **tech stack detection**, **WAF fingerprinting**, **TLS security grading**, **favicon hashing**, and smart result filtering — purpose-built for large-scale recon.


</div>

---

##  Why hx?

| Feature |  |  | **hx** |
|---------|-------|----------|--------|
| Tech detection |   |  | ✅ 50+ signatures |
| WAF detection |  |  | ✅ 14 WAFs |
| TLS grade |  |  | ✅ A+/A/B/C/F |
| Favicon hash |  |  | ✅ + app match |
| Title filter |  |  | ✅ |
| Word/line filter |  |  | ✅ |
| `>>` redirect |  |  | ✅ |
| Proxy support |  |  | ✅ |

---

##  Features

-  **Tech Detection** — 50+ signatures (CMS, frameworks, JS libs, analytics, APIs)
-  **WAF Detection** — 14 WAF/Firewall fingerprints
-  **TLS Grading** — full cert info + security grade (A+/A/B/C/F)
-  **Favicon Hash** — Shodan-compatible mmh3 hash + known app matching
-  **Smart Filters** — filter/match by status, size, words, title
-  **Fast** — 50 concurrent threads default, fully configurable
-  **Pipe Friendly** — stdout/stderr split, stdin support, `>>` works
-  **Output Formats** — TXT · JSON · JSONL

---

##  WAF Detection (14 signatures)

`Cloudflare` · `AWS WAF` · `Akamai` · `Sucuri` · `Imperva` · `ModSecurity` · `F5 BIG-IP` · `Fortinet` · `Barracuda` · `DDoS-Guard` · `Wordfence` · `Reblaze` · `Wallarm` · `Fastly WAF`

---

##  Flags

```
INPUT
  -u <url>             Single URL target
  -l <file>            File of URLs (one per line)
  stdin                Pipe: cat urls.txt | hx

PROBES
  -td                  Tech stack detection (50+ signatures)
  -waf                 WAF / Firewall detection (14 WAFs)
  -tls                 TLS info + security grade (A+ / A / B / C / F)
  -fav                 Favicon hash — Shodan compatible

FILTER
  -mc <200,403>        Match HTTP status codes
  -fc <404,500>        Filter out status codes
  -ms <bytes>          Match content length (exact bytes)
  -fs <bytes>          Filter content length
  -mt <string>         Match page title contains
  -ft <string>         Filter page title contains
  -er                  Exclude errors / unreachable hosts

CONFIG
  -c <int>             Concurrent threads             (default: 50)
  -timeout <sec>       Request timeout seconds        (default: 10)
  -p <url>             Proxy URL (http:// or socks5://)
  -H <key:value>       Custom header (repeatable)

OUTPUT
  -o <file>            Save as TXT
  -oj <file>           Save as JSON
  -ojl <file>          Save as JSONL
  -silent              URLs only to stdout — pipe friendly
  -version             Print version
  --install-license    Activate license on this machine
```

---

##  Examples

```bash
# Basic probe
hx -u https://example.com

# Full probe — all features
hx -u https://example.com -td -waf -tls -fav

# Bulk from file
hx -l hosts.txt -td -waf

# Pipe from stdin
cat subs.txt | hx -c 100

# Only show 200s and 403s
hx -l hosts.txt -mc 200,403

# Find admin panels
hx -l hosts.txt -mc 200 -mt admin -silent

# Find all WAFs
hx -l hosts.txt -waf -oj wafs.json

# TLS security audit
hx -l hosts.txt -tls -ojl tls_audit.jsonl

# Exclude unreachable hosts
cat subs.txt | hx -c 200 -mc 200,403 -er

# Through Burp proxy
hx -u https://target.com -p http://127.0.0.1:8080

# Custom session cookie
hx -u https://target.com -H 'Cookie: session=abc123'

# Save alive URLs
hx -l hosts.txt -mc 200,403 -silent | tee alive.txt

# Append to file
hx -l hosts.txt -mc 200 -silent >> alive.txt

# Full pipeline with xue
xue -d target.com -silent | hx -td -waf -mc 200,403 -er
```

---

##  Output

```
  [200]  https://example.com                                   24.3KB  342w  89l   Example Domain
         ↳ [nginx 1.24.0]  [jQuery, Bootstrap]
         ↳ TLS A+  TLS 1.3  exp:2026-03-01 (365d)

  [403]  https://example.com/admin                             0B      0w    0l
         ↳ [nginx 1.24.0]  🔥 WAF: Cloudflare

  [200]  https://api.example.com                               8.1KB   120w  22l   API v2
         ↳ [nginx]  [React, GraphQL]

  ──────────────────────────────────────────────────────
  [✓]  3 urls  1.2s  2xx:2  3xx:0  4xx:1  5xx:0  err:0
```

---

## 🔧 Installation

```bash
# Build
unzip hx-v1.zip -d hx && cd hx
bash build.sh

# Install
sudo dpkg -i hx_1.0.0_amd64.deb

# Or manual
sudo mv hx /usr/local/bin/
sudo hx --install-license

# Verify
hx -version
```

> **Requirements:** Go 1.21+ · Linux amd64

---

##  Disclaimer

> For authorized security testing and educational purposes only.
> Use only on systems you have explicit permission to test.

---

<div align="center">

*hx v1.0 — by 0xWITHEROOM 「0xホワイトルーム」*

**[0xwhiteroom](https://github.com/0xwhiteroom)** · *We don't hack systems. We ascend them.*

</div>
