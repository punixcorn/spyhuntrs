![Img](./spyhunt_logo_cropped.png)

# Spyhuntrs ALPHA RELEASE!

Everything in **Spyhunt** but with a better save feature and written (poorly) in rust! <br/>
This release is very unstable, I doubt it works.

Spyhunt is comprehensive network scanning and vulnerability assessment tool. This tool is designed for security professionals and penetration testers to perform comprehensive reconnaissance and vulnerability assessment on target networks and web applications. It combines multiple scanning techniques and integrates various external tools to provide a wide range of information about the target.
<br/>
For the original project : [spyhunt](https://github.com/gotr00t0day/spyhunt)<br/>

## Here's a high-level overview of its functionality

1. It imports various libraries for network operations, web scraping, and parallel processing.

2. The script defines a colorful banner and sets up command-line argument parsing for different scanning options.

3. It includes multiple scanning functions for different purposes:
   - Subdomain enumeration
   - Technology detection
   - DNS record scanning
   - Web crawling and URL extraction
   - Favicon hash calculation
   - Host header injection testing
   - Security header analysis
   - Network vulnerability analysis
   - Wayback machine URL retrieval
   - JavaScript file discovery
   - Broken link checking
   - HTTP request smuggling detection
   - IP address extraction
   - Domain information gathering
   - API endpoint fuzzing
   - Shodan integration for additional recon
   - 403 Forbidden bypass attempts
   - Directory and file brute-forcing
   - Local File Inclusion (LFI) scanning with Nuclei
   - Google dorking
   - Directory Traversal
   - SQL Injection
   - XSS
   - Subdomain Takeover
   - Web Server Detection
   - JavaScript file scanning for sensitive info
   - Auto Recon
   - Port Scanning
   - CIDR Notation Scanning
   - Custom Headers
   - API Fuzzing
   - AWS S3 Bucket Enumeration
   - JSON Web Token Scanning

# INSTALLATION

```
git clone https://github.com/punixcorn/spyhuntrs
cd spyhuntrs
cargo build --release  # to build binary
cargo install --path .  # to build & install, make cargo/bin is in path
git clone https://github.com/punixcorn/spyhuntrs-deps ~/.spyhuntrs-deps # for needed files
```

# EXAMPLE

Scan for subdomains and save the output to a file.

```
 spyhuntrs -s yahoo.com --save filename.txt
```

Scan for subdomains but also extract subdomains from shodan

```
 spyhuntrs -s yahoo.com --shodan yahoo.com --shodan_api API_KEY --save filename.txt
```

Scan for javascript files

```
 spyhuntrs -j yahoo.com --save jsfiles.txt
```

Scan for dns records

```
 spyhuntrs -d domains.txt
```

Scan for FavIcon hashes

```
 spyhuntrs --fi domain.com
```

Web Crawler

```
 spyhuntrs --wc https://www.domain.com
```

Broken Links

```
 spyhuntrs -b https://www.domain.com
```

Cors Misconfiguration Scan

```
 spyhuntrs --co domains.txt
```

Host Header Injection

```
 spyhuntrs --hh domains.txt
```

Host Header Injection With proxy

```
 spyhuntrs --hh domains.txt --proxy http://proxy.com:8080
```

Directory Brute Forcing

```
 spyhuntrs --directorybrute domain.com --wordlist list.txt  //-e php,txt,html -x 404,403
```

Directory Brute Forcing with no extensions

```
 spyhuntrs --directorybrute domain.com --wordlist list.txt // -x 404,403
```

Scanning a subnet

```
 spyhuntrs --cidr_notation IP/24 --ports 80,443
```

Directory Traversal

```
 spyhuntrs --ph domain.com?id=
```

sql injection

```
 spyhuntrs --sqli domain.com?id=1
```

xss

```
 spyhuntrs --xss domain.com?id=1
```

JavaScript file scanning for sensitive info

```
 spyhuntrs --javascript domain.com
```

Javascript endpoint fuzzing

```
 spyhuntrs --javascript_endpoint domains.txt  --save filename.txt
```

Modify the headers of the request

```
 spyhuntrs -ch domain.com
```

Parameter bruteforcing

```
 spyhuntrs -pf domain.com
```

Open Redirect

```
 spyhuntrs -or domain.com -v -c 50
```

---

Haveibeenpwned [`NOT INCLUDED YET`]

```
 spyhuntrs -hibp password
```

Subdomain Takeover [`NOT INCLUDED YET`]

```
 spyhuntrs -st domains.txt --save vuln_subs.txt -c 50
```

Auto Recon [`NOT INCLUDED YET`]

```
 spyhuntrs -ar domain.com
```

JSON Web Token [`NOT INCLUDED YET`]

```
 spyhuntrs -jwt Token
```

JSON Web Token Modification [`NOT INCLUDED YET`]

```
 spyhuntrs -jwt-modify Token
```

AWS S3 Bucket Enumeration [`NOT INCLUDED YET`]

```
 spyhuntrs --s3-scan bucket.com
```

Heap Dump Analysis [`NOT INCLUDED YET`]

```
 spyhuntrs --heapdump heapdump_file
```

Sprint Boot Actuator Scan [`NOT INCLUDED YET`]

```
 spyhuntrs --heapds domains.txt
```

# DEV NOTES

# Important stuff to do

- [x] Tests [not Completed]
- [] better error handling (for requests)
- [] Documentation
- [x] ~~rename files~~ meh, it works
- [] better error handling for tests capture
- [x] Make Readme Image
- [x] Install Script (thinking about just using his .py script and running it)

# Spyhunt.py Porting List

- [x] cli handling

# Main file

functions in the file [ WORKING 45/52 ]

- [x] ~~update~~ won't do it
- [x] save/s
- [x] reverseip
- [x] reverseipmulti
- [x] webcrawler
- [x] statuscode
- [x] favicon
- [x] enumratedomain
- [x] faviconmulti
- [x] corsmisconfig
- [x] hostheaderinjection
- [x] securityheaders
- [x] networkanalyzer
- [x] waybackurls
- [x] javascript
- [x] dns
- [x] probe
- [x] redirects
- [x] brokenlinks
- [x] tech
- [x] ip addresses
- [x] domain info
- [x] important subdomains
- [x] not found
- [x] paramspider
- [x] pathhunt
- [x] nmap
- [x] api fuzzer
- [x] shodan
- [x] forbiddenpass
- [x] directorybrute
- [x] nuclei lfi
- [x] google
- [x] cidr notation
- [x] print all ips
- [x] xss scan
- [x] sqli scan
- [x] webserver scan
- [x] javascript scan
- [x] javascript enpoints
- [x] param miner
- [x] custom headers
- [x] open redirect
- [x] automoussystemnumber
- [x] ~~have i been pwned~~ Non trusted Website
- [x] ~~auto recon~~ Just gonna do a bunch of funtions
- [] subdomain takeover

# Add Later Feature

- [] smuggler
- [] jwt scan
- [] jwt modify
- [] s3 scan
- [] heapdump
- [] heapdump scan

# Scripts

- [x] copy all script

# Paylods

- [x] copy all payloads

# Modules

- [x] user_agents.py
  - [x] fetching useragents from website
  - [x] saving all kinds of files
  - [x] pathhunter
- [] heapdump_scan.py
- [] heap_dump.py
- [x] favicon.py
- [] jwt_analyzer.py
- [] letslog.py
- [] ss3sec.py
- [] ssl_sec.py
- [] sub_ouput.py

# Tools

- [] smuggler
- [] whatwaf
- [x] ~~assetfinder??? ( It's a mac os copy for macos)~~
- [] f5bigip_scanner.py
- [x] pathhunt.py

# Async Benchmark Test

Using 2 `tokio::spawn` and `rayon::par_iter`

- tokio::spawn : runs the async function in tasks
- rayon::per_iter : makes the async, sync with blocking and runs parallelism on it

#### Trade offs

- tokio - faster by `approx 40%`, but is slower on poor internet by `approx >=50%` and `fails` sometimes.
- rayon - slower but consistent.

#### Benchmark results for a list of domains

```bash
λ cookedpotato [~/spyhuntrs/src] → for i in $(ls); do ; ../target/debug/spyhunt --statuscode test | grep TIME; echo "=======================" ; done
```

| Tokio::spawn       | rayon::par_iter           |
| ------------------ | ------------------------- |
| TIME : 3.663566559 | TIME : 5.752224591        |
| TIME : 3.402748856 | TIME : 5.2967847169999995 |
| TIME : 3.510505289 | TIME : 6.966605254        |
| TIME : 3.68178911  | TIME : 6.068205533        |
| TIME : 3.134102605 | TIME : 5.928900023        |
| TIME : 3.492261965 | TIME : 5.425285007        |
| TIME : 3.396847444 | TIME : 6.007485342        |
| TIME : 3.327187843 | TIME : 5.41876072         |
| TIME : 8.793370181 | TIME : 6.6859621879999995 |
| TIME : 3.905401925 | TIME : 6.036668491        |
| TIME : 3.764345439 | TIME : 6.014918595        |
| TIME : 3.44568258  | TIME : 5.665416095        |
| TIME : 3.513112026 | TIME : 6.5360846          |
| TIME : 3.562984792 | TIME : 6.598054599        |
| TIME : 4.295627432 | TIME : 7.067796471        |
| TIME : 3.91060994  | TIME : 5.816363504        |
| TIME : 3.900246705 | TIME : 6.521269384        |
| TIME : 3.028592963 | TIME : 5.686620852        |
| TIME : 3.563177913 | TIME : 5.896828077        |
| TIME : 3.424093208 | TIME : 5.264936503        |
| TIME : 3.494048375 | TIME : 5.782055718        |
