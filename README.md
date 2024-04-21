# Open Source Intelligents and Tools
This is the list of workable and online tools and OSINT to support penetration testing. All of this can work within web browser so that it should be cross-platform. Moreover, it also hide your IP that the target will see the incoming request from the OSINT web instead. I try to categorized them with Cyber Kill Chain. (You can issue or address to me if anything is mistake.)
* Hide your IP
* Free as possible
* Cross Platform (Web Browser)
* No Installation
* Last Investigate: April 2024
The description of Cyber Kill Chain is [Here](https://darktrace.com/cyber-ai-glossary/cyber-kill-chain)
<!-- End of Description Section -->
# Reconnaissance
The first stage of the Cyber Kill Chain is “Reconnaissance." This stage involves the attacker gathering information about the target, such as identifying potential vulnerabilities, key personnel, network configurations, and security measures in place. This phase can include passive techniques like open-source intelligence (OSINT) gathering or active scanning and probing of the target’s system.
## Statistics
| **Name** | **Features** |
|:--------|:------------|
| [DailyChanges](https://dailychanges.domaintools.com/) | Nameserver and Web Hosting Activity |
| [TLDpedia](https://research.domaintools.com/statistics/tldpedia/) | `Details of TLD` (Registeration, IP, etc.)|
| [Internet Statistics](https://research.domaintools.com/statistics/)| TLD, IP Address, Mail Server Statistics |
| [All Country IP](https://suip.biz/?act=all-country-ip)| List of IPs classified by continents |
| [IP Country](https://suip.biz/?act=ipcountry)| List of IPs classified by contries |
| [IP Locality](https://suip.biz/?act=iploc)| List of IPs classified by city/region |
| [All ISP IP](https://suip.biz/?act=all-isp)| List of IPs classified by ISP |

## Network Test
| **Name** | **Features** |
|:--------|:------------|
| [Chinese Firewall Test](https://viewdns.info/chinesefirewall) | Check if site is `accessible from China` |
| [Iran Firewall Test](https://viewdns.info/iranfirewall/) | Check if site is `accessible from Iran` |
| [DNS Propagation Checker](https://viewdns.info/propagation) | Check if some `root DNS servers` can resolved the sites/domains |
| [Check DNS](https://check-host.net/check-dns) | Check DNS resolve from various regions |
| [Is My Site Down](https://viewdns.info/ismysitedown) | DNS resolve + ping + port 80,443 + site title check |
| [Zone Transfer Test](https://hackertarget.com/zone-transfer/) | `Zone Transfer/AXFR Query` Test |
| [Hackertarget traceroute](https://hackertarget.com/online-traceroute/) | Online `Traceroute` command|
| [ViewDNS.info Traceroute](https://viewdns.info/traceroute) | Online `Traceroute` (Simple)|
| [Trace Route Online](https://traceroute-online.com/) | Online `Traceroute` (Advanced)|
| [Trace Route Me](https://suip.biz/?act=traceroute-me) | Online `Traceroute` with customized protocols (Advanced)|
| [Hackertarget Ping](https://hackertarget.com/test-ping/) | Online `ping` command |
| [Ping Test](https://viewdns.info/ping) | Measure `Latency` using ping from various regions |
| [Check ping](https://check-host.net/check-ping) | Measure `Latency` using ping from various regions |
| [ViewDNS.info DNSSEC](https://viewdns.info/dnssec) | Test `DNSSEC` (Basic) |
| [DNSSec Debugger](https://dnssec-debugger.verisignlabs.com/) | Test `DNSSEC` (Advacned) |
| [Check HTTP](https://check-host.net/check-http) | Test `HTTP GET` from various regions |
| [HTTP Header Check](https://hackertarget.com/http-header-check/) | HTTP GET Response |
| [Reqbin](https://reqbin.com/) | Test HTTP Request, Body, Method similar to Postman |
| [Rest Ninja](https://restninja.io/) | Test HTTP Request, Body, Method similar to Postman |
| [Find Out My IP](https://suip.biz/?act=myip) | Find your public IP/Hostname and Location |
| [My User Agent](https://suip.biz/?act=my-user-agent) | Check your exposed user-agent |
| [Proxy Checker](http://suip.biz:8080/?act=proxy-checker) | Check if your proxy leaked your real IP + HTTP request check |
| [Check My IPv6](https://suip.biz/?act=ipv6-enabled) | Check if you are using IPv6 |
| [Request Site via TOR](https://suip.biz/?act=request-site-via-tor) | Check if site accessible by TOR network |
| [Is Cloudflare](https://suip.biz/?act=iscloudflare) | Check if site is behind CloudFlare |
| [WAF Bypass](https://suip.biz/?act=bypass-waf) | Determine WAF |
| [Tor relay check](https://metrics.torproject.org/exonerator.html) | Check if provided host a TOR relay |
| [SMTPer](https://www.smtper.net/) | Test SMTP server |
| [Mail Server Health Check](https://mxtoolbox.com/diagnostic.aspx) | Test health of mail server by domain or email address |
| [Local Browser](https://www.locabrowser.com/) | Browse Website from Different Region |
| [Thumnail Grabber](https://10015.io/tools/youtube-thumbnail-grabber) | Youtube and Vimeo Thumbnail Grabber |

## Network Reconnaissance
| **Name** | **Features** |
|:--------|:------------|
| [Domain DB](https://domainsdb.info/) | Check registered domain  |
| [OSRFramework Domain](https://suip.biz/?act=domainfy) | Check all possible `TLD of provided domains`  |
| [Urlscan.io](https://urlscan.io/) | Advanced IP/Domain Check and Scan (no port scan)  |
| [IP Info](https://check-host.net/ip-info) | `CIDR + Geolocation` Check  |
| [MX Lookup](https://mxtoolbox.com/MXLookup.aspx) | Find mail server of domain |
| [Reverse MX Lookup](https://viewdns.info/reversemx) | Find domain that has the `provided MX records` |
| [DMARC](https://mxtoolbox.com/dmarc.aspx) | Find DMARC policy of mail server |
| [WhoIs.is](https://who.is/) |WhoIs Query (fast) |
| [WhoIs.com](https://www.whois.com/whois) | WhoIs Query (fast) |
| [ICANN Lookup](https://lookup.icann.org/) | Structured Whois + `RDAP Query` (fast)  |
| [WhoIs DomainTools](https://whois.domaintools.com/) | Whois Query + Summary (slow)  |
| [Reverse WhoIs](https://viewdns.info/reversewhois/) | Find sites by `registrar name/email` |
| [Reverse NS Lookup](https://viewdns.info/reversens/) | Find domain that has the `provided NS records` |
| [IP History](https://viewdns.info/iphistory) | `IP History` of site/domain |
| [Reverse IP](https://viewdns.info/reverseip) | Most Accurated Reverse IP Lookup `with Last Resolved Date` |
| [intoDNS beta](https://intodns.com/) | Structured NSLookup (Simple)  |
| [Nslookup.io](https://www.nslookup.io/) | Structured NSLookup (Advanced)  |
| [DNSDumpster](https://dnsdumpster.com/) | Structured and Aggressive NSLookup (Advanced)  |
| [Reverse IP Lookup](https://viewdns.info/reverseip/) | Identify `Sites on the same Host/IP` (1 result can infer to a self-hosted site)|
| [Admin Toolbox Dig](https://toolbox.googleapps.com/apps/dig/) | Interfaced Dig Query (Simple)  |
| [Dig GUI](https://www.diggui.com/) | Interfaced Dig Query (Advanced) |
| [Threat Intelligence Platform](https://threatintelligenceplatform.com/) | All in one DNS query, whois, subdomain lister and more  |
| [Web Archive Search](https://suip.biz/?act=web-arhive) | Search specified site from various archiver  |
| [Wayback Machine](https://web.archive.org/) | Search of cached/archived of any site |
| [Synapsint](https://synapsint.com/) | Search IP/Domain, PII, Bitcoin Address, and CVE |

## Scanner
| **Name** | **Features** |
|:--------|:------------|
| [ViewDNS.info Port Scan](https://viewdns.info/portscan) | TCP Port Scanner `(13 ports only)` |
| [HackerTarget TCP Port Scan](https://hackertarget.com/nmap-online-port-scanner/) | Nmap TCP Port Scanner `(10 ports only)` |
| [HackerTarget UDP Port Scan](https://hackertarget.com/udp-port-scan/) | Nmap UDP Port Scanner `(7 ports only)` |
| [Check TCP](https://check-host.net/check-tcp) | `TCP Port connection` check from various regions |
| [Check UCP](https://check-host.net/check-udp) | `UCP Port connection` check from various regions |
| [Nmap Online](https://suip.biz/?act=nmap) | Online Nmap IPv4 port scanner `(any ports)` |
| [Nmap Online](https://suip.biz/?act=nmap-online) | Online Nmap IPv4 port scanner `(any ports)` (advanced)|
| [Nmap Online](https://suip.biz/?act=nmap-ipv6) | Online Nmap IPv6 port scanner `(any ports)`|
| [NetBIOS SMB SAMBA Scanner](https://suip.biz/?act=netbios-smb) | Check NetBIOS, SMB, and Samba Service (Aggresive) |
| [WPScan Online](https://w-e-b.site/?act=wpscan) | Online and Simple wordpress website scanner |
| [SQLmap Online](https://suip.biz/?act=sqlmap) | Online and Simple SQL injection scanner |
| [DroopeScan Online](https://suip.biz/?act=droopescan) | Online Drupal and SilverStripe Vulnerability Scanner |
| [Nikto Online](https://suip.biz/?act=nikto) | Online Nikto Web Scanner |
| [HTTP Security Scanner](https://suip.biz/?act=hsecscan) | Scan HTTP Security from HTTP Response |
| [WafW00f Online](https://suip.biz/?act=wafw00f) | Scan Web Application Firewall |

## Brute Force/Lister
| **Name** | **Features** |
|:--------|:------------|
| [Hackertarget find subdomains](https://hackertarget.com/find-dns-host-records/) | `Find subdomains` using `DNS query` |
| [SubdomainFinder](https://subdomainfinder.c99.nl/) | `Find subdomains` using `DNS query and history` |
| [SubdomainFinder](https://suip.biz/?act=findomain) | `Find subdomains` using `secret method` |
| [SubdomainFinder](https://suip.biz/?act=subfinder) | `Find subdomains` using `every OSINT` |
| [Threat Intelligence Platform](https://threatintelligenceplatform.com/) | All in one DNS query, whois, subdomain lister and more  |
| [Certificate Search](https://crt.sh/) | Search site certificate (potentially exposes subdomains)  |
| [Urlscan.io](https://urlscan.io/) | Domain information (potentially exposes subdomains)  |
| [Extract Links](https://hackertarget.com/extract-links/) | Extract all links found in `href` from site  |
| [Bypass Social Locker](https://suip.biz/?act=social-locker-cracker) | Extract Blocked Content Download Link  |
| [Cloud Fail](https://suip.biz/?act=cloudfail) | Search Cloud Fail + 2000+ Subdomains BruteForce  |

## Search Platform
| **Name** | **Features** |
|:--------|:------------|
| [Advanced Google Search](https://suip.biz/?act=google-search) | Generate Google Advanced Search Query |
| [Google Hacking](https://pentest-tools.com/information-gathering/google-hacking) | Generate Google Advanced Search Query |
| [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) | List of useful and specified Google Search Query |
| [The Master List](https://themasterlist.org/) | List of things made by an Israeli guy |
| [Censys](https://search.censys.io/) | Search of openned port, IP and more about any host |
| [Zoom Eye](https://www.zoomeye.hk/) | Search of openned port, IP and more about any host |
| [Shodan](https://www.shodan.io/) | Search of openned port, IP and more about any host (especially IoT) |
| [GreyNoise](https://viz.greynoise.io/) | Search for CVE, IP, and more |
| [Ahmia](https://ahmia.fi/) | Search for TOR hidden website |
| [Open FTP Index](https://www.mmnt.net/) | List of existing FTP index by Mamont |
| [Leak Monitor](https://psbdmp.ws/) | Dump of text file (especially from paste.bin) |
| [Public Bucket Search](https://buckets.grayhatwarfare.com/) | Search public cloud directory such as  AWS, Azure, GCP and more|

## Identity and Social Media Reconnaissance
| **Name** | **Features** |
|:--------|:------------|
| [World Social Platforms](https://www.osintcombine.com/free-osint-tools/world-social-media-platforms) | Search social media usage by country |
|[Alt Social Media](https://www.osintcombine.com/free-osint-tools/alt-tech-social-search) | Search non-mainstream social media list |
| [Free Email Check](https://viewdns.info/freeemail) | Check if provided email address is free email |
| [OSRFramework Email](https://suip.biz/?act=mailfy) | Email Checker using OSRFramework |
| [OSRFramework Username](https://suip.biz/?act=usufy) | Username Checker using OSRFramework |
| [Synapsint](https://synapsint.com/) | Search IP/Domain, PII, Bitcoin Address, and CVE |
| [Epieos](https://epieos.com/) | Search email and phone |
| [AeroLeads](https://aeroleads.com/) | Search exposed PII |
| [Signal Hire](https://www.signalhire.com/) | Search exposed PII |
| [Huner.io](https://hunter.io/) | Search exposed PII |
| [Tomba](https://tomba.io/) | Email Finder |
| [Rocket Reach](https://rocketreach.co/) | Email Finder |
| [Social Seacher](https://www.social-searcher.com/) | Seach exposed PII |
| [Whats My Name](https://whatsmyname.app/) | Seach social account |
| [Predicta](https://predictasearch.com/) | Seach social account |
| [User Search](https://www.usersearch.org/) | Search social account |
| [People Search Engine](https://webmii.com/) | Seach exposed PII, news, and social account |
| [Social Geo Lens](https://www.osintcombine.com/free-osint-tools/social-geo-lens) | Conduct geo-searching on social media platforms |
| [Who post what? Facebook](https://whopostedwhat.com/) | Search Facebook Post |
| [Have I been zuckered](https://haveibeenzuckered.com/) | Check if identity used to leak from Facebook |
| [Facebook Ads Library](https://www.facebook.com/ads/library/?active_status=all&ad_type=political_and_issue_ads&country=TH&media_type=all) | Search Facebook Ads |
| [Lookup-id](https://lookup-id.com/) | Facebook UserID, GroupID, PageID Lookup |
| [Find Instragram ID](https://randomtools.io/find-instagram-id/) | Find Instragram ID by name |
| [Instragram Explorer](https://www.osintcombine.com/free-osint-tools/instagram-explorer) | Search Image on Instragram |
| [Who post what? Twitter](https://whopostedwhat.com/twitter.php) | Search Twitter Post |
| [Find Twitter ID](https://randomtools.io/find-my-twitter-id/) | Find Twitter ID by name |
| [Twitter Shadowban](https://shadowban.yuzurisa.com/) | Check if Twitter acount is banned or muted |
| [Twitter Advanced Search](https://twitter.com/search-advanced) | Twitter Advanced Search |
| [Twitter Advanced Search](https://github.com/igorbrigadir/twitter-advanced-search) | Twitter Advanced Search |
| [Linkedin Timestamp Extractor](https://ollie-boyd.github.io/Linkedin-post-timestamp-extractor/) | Find LinkedIn Post Timestamp |
| [Tiktok Quick Search](https://www.osintcombine.com/free-osint-tools/tiktok-quick-search) | Search Tiktok by name, hashtag, or keyword |
| [Reddit Post Analyzer](https://www.osintcombine.com/free-osint-tools/reddit-post-analyser) | Analyze Reddit Post |
| [Have I been pwned?](https://haveibeenpwned.com/) | Check if email address appeared on data leakage event |

## File Reconnaissance
| **Name** | **Features** |
|:--------|:------------|
| [Geotagging](https://suip.biz/?act=locatepicture) | Check if geotagging is embeded in file |
| [List all Metadata](https://suip.biz/?act=mat) | List all the harmful metadata of a file |
| [Compression Quality](https://suip.biz/?act=show-image-compression-quality) | Show the quality level of JPG images |
| [OSRFramework Fullname](https://suip.biz/?act=searchfy) | Fullname Checker using OSRFramework |
| [Email Info Extractor](https://suip.biz/?act=email) | Extract Information from Email Header |
| [Email Header Analyze](https://mxtoolbox.com/EmailHeaders.aspx) | Extract Information from Email Header |
| [Determine File Type](https://suip.biz/?act=file-type) | Determine File Type `without extension` |
| [Extract string from file](https://suip.biz/?act=rabin2) | Extract printable string from file|
| [Exe Information](https://suip.biz/?act=rabin2i) | Extract information from binary file|
| [DSStore Extract](https://suip.biz/?act=dsstore) | Extract information from .DS_Store file|
| [Data Visualization Tools](https://osintcombine.tools/) | Provide basic data visulization on CSV file |
| [Virus total](https://www.virustotal.com/gui/) | checkethe maliciousness of file |

## Log Analysis
| **Name** | **Features** |
|:--------|:------------|
| [Online Apache Log Analysis](https://suip.biz/?act=goaccess) | Analyze Apache Log with various format |
<!-- End of Reconnaissance Section -->
# Weaponization
“Weaponization” is the stage where the attacker creates or obtains a malicious payload, such as malware or a weaponized document. The payload is prepared to exploit specific vulnerabilities, which could have been discovered during the Reconnaissance stage, and achieve the attacker’s objectives when delivered to the target.
## Metadata Modification
| **Name** | **Features** |
|:--------|:------------|
| [Metadata Cleaner Photo](https://suip.biz/?act=metadata-cleaner) | Remove all metadata of image file |
| [Metadata Cleaner](https://suip.biz/?act=file-metadata-cleaner) | Remove all metadata of various files |

## File Converter
| **Name** | **Features** |
|:--------|:------------|
| [Any Image](https://suip.biz/?act=convert-any-image) | Universal Image File Converter |
| [Online Converter](https://www.online-convert.com/) | Universal File Converter |
| [PDF to JPG](https://suip.biz/?act=convert-pdf-to-jpg) | PDF to JPG converter |
| [JPG to PDF](https://suip.biz/?act=convert-jpg-to-pdf) | JPG to PDF converter |
| [Ezyzip](https://www.ezyzip.com/) | Compress and Uncompress file online|

## Cryptanalysis Cryptography and Text Tool
| **Name** | **Features** |
|:--------|:------------|
| [Online Hash Finder](https://suip.biz/?act=hashtag) | Identify Hash Type |
| [NTLM Hash Generator](https://suip.biz/?act=ntlm-hash-generator) | Generate NTLM hash with your password |
| [CyberChef](https://gchq.github.io/CyberChef/) | Platform to perform cryptography |
| [FactorDB](http://factordb.com/) | Prime Number Factor Database |
| [Prime List](http://compoasso.free.fr/primelistweb/page/prime/liste_online_en.php) | List of Prime Number |
| [JWT Rock](https://jwt.rocks/) | JWT Editor |
| [Case Converter](https://10015.io/tools/case-converter) | Case Converter (including mixed and inversed) |
| [Letter Counter](https://10015.io/tools/letter-counter) | Letter Count with Social Media Limits Test |
| [Text to Handwriting](https://10015.io/tools/text-to-handwriting-converter) | convert digital text to handwritting text |
| [Hash Encrypt/Decrypt](https://10015.io/tools/md5-encrypt-decrypt) | Encrypt and Decrypt Hash |
| [Aperisolve](https://www.aperisolve.com/) | Stegnalysis Online |

## Code Maker
| **Name** | **Features** |
|:--------|:------------|
| [Reverse Shell Generator](https://www.revshells.com/) | Quick Reverse Shell Command |
| [Vscode](https://vscode.dev/) | Online VSCode IDE |
| [Online Python](https://www.online-python.com/) | Online Python IDE |
| [Programiz](https://www.programiz.com/c-programming/online-compiler/) | Universal IDE |
| [Invicti](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/) | SQL Injection Cheat Sheet |
| [Digicert](https://www.digicert.com/easy-csr/openssl.htm) | OpenSSL Certificate Generator |
| [QR Code Generator](https://10015.io/tools/qr-code-generator) | QR Code Generator for any URL|
| [BarCode Generator](https://10015.io/tools/barcode-generator) | BarCode Generator for any URL|

## Image Tool
| [Imagte tools](https://10015.io/tools/image-cropper) | Cropper, Filter, Resizer, and more |

## Malware Sample
| **Name** | **Features** |
|:--------|:------------|
| [Malware Bazaar](https://bazaar.abuse.ch/) | Malware Sample |

## Identity Generator
| **Name** | **Features** |
|:--------|:------------|
| [10 minute mail](https://10minutemail.com/) | 10 Minutes Expired Email Address |
| [NFT Generator](https://www.20minutemail.com/NFTCreator) | Generate NFT Image |
| [Minute In Box](https://www.minuteinbox.com/) | 10 Minutes Expired Email Address |
| [Temp-mail](https://temp-mail.org/en/) | Temporary Email Address |
| [Random Password Generator](tps://www.avast.com/random-password-generator) | Password Generator with some customization |
| [Fake Name Generator](https://www.fakenamegenerator.com/) | Identity Generator |
| [Namelix](https://namelix.com/) | Business Brand Name with Logo Generator |
| [NightCafe Studio](https://creator.nightcafe.studio/ai-face-generator) | AI Face Generator |
| [Generated Photo](https://generated.photos/) | AI human face,body generator (more realistic) |
| [Art Guru](https://www.artguru.ai/) | AI Art Generator |
| [Hootsuite](https://www.hootsuite.com/social-media-tools/bio-generator) | Social Media Bio Generator |
| [Social Media Post Generator](https://10015.io/tools/instagram-post-generator) | Social Media Post Generator |

<!-- End of Weaponization Section -->
# Delivery
The “Delivery” stage is where the attacker transmits a malicious payload to the target. This can occur through various means, including phishing emails, infected attachments, or compromised websites. Successful delivery is crucial for the attack to progress to the next stages.
## Phishing/Reputation Check
| **Name** | **Features** |
|:--------|:------------|
| [Phishing URL](https://easydmarc.com/tools/phishing-url) | Phishing URL Checker |
| [Check Phishing](https://suip.biz/?act=urlcrazy) | Check for typo squatting, URL hijacking, and phishing |
| [URL Hopper](https://suip.biz/?act=hoper) | Hop to deeper directory until end (good with shortened URL) |
| [Blacklists](https://mxtoolbox.com/blacklists.aspx) | Check if provied `Mail Server` appeared on blacklist  |
| [IP Spam Lookup](https://viewdns.info/spamdblookup) | Check if provied `Mail Server` appeared on spam databases  |
| [IP Reputation Check](https://www.ipqualityscore.com/ip-reputation-check) | Check IP Reputation  |
| [Cisco Talos](https://talosintelligence.com/reputation_center/) | Check IP and Domain Reputation  |
| [Can I Phish](https://caniphish.com/email-phishing-simulator) | Phishing Simulator  |

## File Hosting Service
| **Name** | **Features** |
|:--------|:------------|
| [PasteBin](https://pastebin.com/) | Online Text Editor (with public link that you can retrieve or exfiltrate)|
| [Text.is](https://text.is/) | Online Text Editor (with public link that you can retrieve or exfiltrate)|
| [Filetransfer.io](https://filetransfer.io/) | Temporary host your file online with access URL|
| [File.io](https://www.file.io/) | Temporary host your file online with access URL|
| [File Bin](https://filebin.net/) | Temporary host your file online with access URL|
| [PGP Upload](https://8gwifi.org/pgp-upload.jsp) | Share file via email and PGP Encryption|

## Service Hosting Service
| **Name** | **Features** |
|:--------|:------------|
| [Tiiny](https://tiiny.host/) | Temporary Web Site Hosting|
| [SFTP Cloud](https://sftpcloud.io/tools/free-ftp-server) | Temporary FTP Hosting|
| [Anonymous Email](https://anonymousemail.me/) | Send anonymous email (most of it is marked as spam)|


<!-- End of Delivery Section -->
# Exploitation
“Exploitation” involves taking advantage of vulnerabilities identified during reconnaissance, to execute the malicious payload delivered in the previous stage. This could include exploitation software vulnerabilities, weak configurations, or human errors to gain control over the target system.
## Vulnerability Database
| **Name** | **Features** |
|:--------|:------------|
| [VulDB](https://vuldb.com/) | vulnerability database (CVE, Product, Vendor, and more) |
| [ExploitDB](https://www.exploit-db.com/) | vulnerability and explotiation database |
| [Snyk](https://security.snyk.io/) | Synk vulnerability database |
| [Rapid7](https://www.rapid7.com/db/) | Rapid7 vulnerability database |
| [CVE details](https://www.cvedetails.com/) | vulnerability database with visualization |
| [GO vulnerability](https://vuln.go.dev/) | Go language vulnerability database |
| [NIST](https://nvd.nist.gov/vuln/search) | NIST Vulnerability Database |
| [MITRE](https://cve.mitre.org/cve/search_cve_list.html) | MITRE Vulnerability Database |

## Password Database
| **Name** | **Features** |
|:--------|:------------|
| [Default Password](https://cirt.net/passwords) | Default Password Database by Vendor |
| [PasswordDB](https://redoracle.com/PasswordDB/) | Default Password and Policy by Vendor |
| [default-password](https://default-password.info/) | Default Password by Vendor |
| [default password](https://www.defaultpassword.com/) | Default Password by Vendor with protocol |
| [Tools DPW](https://www.fortypoundhead.com/tools_dpw.asp) | Default Password by Vendor |
| [Router Password](https://www.routerpasswords.com/) | Default Router Password|

## Proof of Concept
| **Name** | **Features** |
|:--------|:------------|
| Link of PoC repo | Coming Soon|

## Reverse Engineer
| **Name** | **Features** |
|:--------|:------------|
| [Beautifier.io](https://beautifier.io/) | JavaScript,HTML,CSS beautify and deobfuscation|
| [DogBolt](https://dogbolt.org/) | Decompiler Explorer|
| [OneCompiler](https://onecompiler.com/assembly) | Assembly Executor|
| [Assembler Simulator](https://exuanbo.xyz/assembler-simulator) | Assembly simulator with register and memory|
| [Assembly x86 simulator](https://carlosrafaelgn.com.br/Asm86/) | Assembly simulator with register and memory and more|
| [Ezyzip](https://www.ezyzip.com/) | Compress and Uncompress file online|
| [Unpac.me](https://www.unpac.me/) | Unpack binary file online|
| [SISIK](https://sisik.eu/elf) | ELF Analyze Online|
| [ELFY.io](https://elfy.io/) | ELF Analyze and Editor Online|
| [Hexed](https://hexed.it/) | Hex Editor Online|
| [Ezyzip](https://www.ezyzip.com/extract-apk-files.html) | Extract APK File|
| [Ezyzip](https://www.ezyzip.com/extract-files-online.html) | Universal File Extractor|
<!-- End of Exploit Section -->
# Installation
Attack vector is installed on the victim’s system.
## Command Generator
| **Name** | **Features** |
|:--------|:------------|
| [Crontab Generator](https://crontab-generator.org/) | Generatr Crontab command with ease of use |
| [Powershell Gallery](https://www.powershellgallery.com/) | Library of public powershell script |
| [8gwifi](https://8gwifi.org/sshfunctions.jsp) | SSH Key generator |
<!-- End of Installation Section -->
# Command and Control
“Command and Control” (C2) is the stage where the attacker establishes communication with the compromised system or network. This communication allows the attacker to maintain control, deliver commands, and receive data from the compromised systems. It is a critical stage as it enables ongoing interaction and control over the target.
## Virtual Machine
| **Name** | **Features** |
|:--------|:------------|
| [Check-Host.net Terminal](https://check-host.net/terminal) | Quick VNC/Linux Terminal (15 minutes limited) |
| [SSH Easy](https://ssheasy.com/) | Online SSH Client |
| [WebSSH](https://webssh.de/) | Online SSH Client |
| [WebSSH](https://www.filestash.app/online-ftp-client.html) | Online FTP Client |
| [Net2FTP](https://www.net2ftp.com/index.php) | Online FTP and SSH Client |
| [Onworks](https://www.onworks.net/programs/smbclient-online) | Online SMB Client |
| [AntCommander](https://www.antcommander.com/online/samba-client.html) | Online Sambda Client |
| [PHPMyadminOnline](https://www.phpmyadminonline.com/index.php) | Online MySQL Client |
<!-- End of Command and Control Section -->
# Action on Objectives

## Attack Procedure 
The “Actions on Objective” stage is the final step in the Cyber Kill Chain, representing the attacker’s ultimate goal, which could include data theft, system disruption, or other malicious activities. It signifies the completion of the attack’s primary objective.
| **Name** | **Features** |
|:--------|:------------|
| [MITRE ATT&CK](https://attack.mitre.org/) | Knowledge-based of adversary |
| [DVWA](https://pentest-ground.com:4280/) | Vulnerable Website to test hacking skils |
| [DV GraphQL Application](https://pentest-ground.com:5013/) | Vulnerable GraphQL Website to test hacking skils |
| [RestFlaw](https://pentest-ground.com:9000/) | Vulnerable API to test hacking skills |
| [Guardian Leaks](https://pentest-ground.com:81/) | Vulnerable Website to test hacking skils |

<!-- End of Attack on Objectives Section -->

# Thai Exclusive OSINT
Coming soon ...