# pihole

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 6.4.1](https://img.shields.io/badge/AppVersion-6.4.1-informational?style=flat-square)

A Helm chart for deploying Pi-hole, a network-wide ad blocker, on Kubernetes.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| adlists[0] | string | `"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"` |  |
| config.database | object | `{"dbImport":true,"dbInterval":60,"maxDBdays":91,"network":{"expire":91,"parseARPcache":true},"useWAL":true}` | Database and query history configuration |
| config.database.dbImport | bool | `true` | Load query history from database on startup |
| config.database.dbInterval | int | `60` | How often to store queries in database (in seconds) |
| config.database.maxDBdays | int | `91` | How long to store queries in database (in days) |
| config.database.network.expire | int | `91` | How long to keep IP addresses in network table (in days) |
| config.database.network.parseARPcache | bool | `true` | Analyze local ARP cache for client identification |
| config.database.useWAL | bool | `true` | Enable Write-Ahead Logging (WAL) for better database performance |
| config.debug | object | `{"aliasclients":false,"all":false,"api":false,"arp":false,"caps":false,"clients":false,"config":false,"database":false,"dnssec":false,"edns0":false,"events":false,"extra":false,"flags":false,"gc":false,"helper":false,"inotify":false,"locks":false,"netlink":false,"networking":false,"ntp":false,"overtime":false,"queries":false,"regex":false,"resolver":false,"shmem":false,"status":false,"timing":false,"tls":false,"vectors":false,"webserver":false}` | Debug logging configuration (normally all disabled) |
| config.debug.aliasclients | bool | `false` | Debug alias-client processing |
| config.debug.all | bool | `false` | Enable all debug flags at once |
| config.debug.api | bool | `false` | Debug API calls and authentication |
| config.debug.arp | bool | `false` | Debug ARP table processing |
| config.debug.caps | bool | `false` | Debug process capabilities |
| config.debug.clients | bool | `false` | Debug client events and group assignments |
| config.debug.config | bool | `false` | Debug config parsing |
| config.debug.database | bool | `false` | Debug database SQL statements and performance |
| config.debug.dnssec | bool | `false` | Debug DNSSEC activity |
| config.debug.edns0 | bool | `false` | Debug EDNS(0) data |
| config.debug.events | bool | `false` | Debug event handling queue |
| config.debug.extra | bool | `false` | Temporary debug flag for investigations |
| config.debug.flags | bool | `false` | Debug DNS query flags |
| config.debug.gc | bool | `false` | Debug garbage collection operations |
| config.debug.helper | bool | `false` | Debug script helpers |
| config.debug.inotify | bool | `false` | Debug /etc/pihole filesystem monitoring |
| config.debug.locks | bool | `false` | Debug shared memory locks |
| config.debug.netlink | bool | `false` | Debug netlink communication |
| config.debug.networking | bool | `false` | Debug detected network interfaces |
| config.debug.ntp | bool | `false` | NTP synchronization debugging |
| config.debug.overtime | bool | `false` | Debug overTime memory operations |
| config.debug.queries | bool | `false` | Debug DNS queries and replies |
| config.debug.regex | bool | `false` | Debug regex matching |
| config.debug.resolver | bool | `false` | Debug hostname resolution |
| config.debug.shmem | bool | `false` | Debug shared memory buffers |
| config.debug.status | bool | `false` | Debug query status changes |
| config.debug.timing | bool | `false` | Debug timing information |
| config.debug.tls | bool | `false` | Debug TLS connections |
| config.debug.vectors | bool | `false` | Debug dynamic vector operations |
| config.debug.webserver | bool | `false` | Debug web server (CivetWeb) events |
| config.dhcp | object | `{"active":false,"end":"","hosts":[],"ignoreUnknownClients":false,"ipv6":false,"leaseTime":"","logging":false,"multiDNS":false,"netmask":"","rapidCommit":false,"router":"","start":""}` | DHCP server configuration |
| config.dhcp.active | bool | `false` | Enable Pi-hole's embedded DHCP server |
| config.dhcp.end | string | `""` | End address of DHCP address pool |
| config.dhcp.hosts | list | `[]` | Static DHCP leases and per-host parameters |
| config.dhcp.ignoreUnknownClients | bool | `false` | Ignore DHCP clients not explicitly configured in dhcp.hosts |
| config.dhcp.ipv6 | bool | `false` | Enable IPv6 DHCP support |
| config.dhcp.leaseTime | string | `""` | DHCP lease time (e.g., "45m", "1h", "2d", "1w", "infinite") |
| config.dhcp.logging | bool | `false` | Log all DHCP-related activity |
| config.dhcp.multiDNS | bool | `false` | Advertise Pi-hole DNS server multiple times to prevent client overrides |
| config.dhcp.netmask | string | `""` | Network netmask for DHCP. Leave empty for auto-detection on directly connected networks |
| config.dhcp.rapidCommit | bool | `false` | Enable DHCPv4 Rapid Commit Option (RFC 4039) |
| config.dhcp.router | string | `""` | Gateway address for DHCP clients (typically your router) |
| config.dhcp.start | string | `""` | Start address of DHCP address pool |
| config.dns | object | `{"analyzeOnlyAandAAAA":false,"blockESNI":true,"blockTTL":2,"blocking":{"active":true,"edns":"TEXT","mode":"NULL"},"bogusPriv":true,"cache":{"optimizer":3600,"size":10000,"upstreamBlockedTTL":86400},"cnameDeepInspect":true,"cnameRecords":[],"dnssec":false,"domain":{"local":true,"name":"lan"},"domainNeeded":true,"edns0ECS":true,"expandHosts":true,"hostRecord":"","hosts":[],"ignoreLocalhost":false,"interface":"eth0","listeningMode":"LOCAL","localise":true,"piholePTR":"PI.HOLE","port":53,"queryLogging":true,"rateLimit":{"count":1000,"interval":60},"reply":{"blocking":{"force4":false,"force6":false,"ipv4":"","ipv6":""},"host":{"force4":false,"force6":false,"ipv4":"","ipv6":""}},"replyWhenBusy":"ALLOW","revServers":[],"showDNSSEC":true,"specialDomains":{"designatedResolver":true,"iCloudPrivateRelay":true,"mozillaCanary":true},"upstreams":["8.8.8.8","8.8.4.4"]}` | DNS configuration settings |
| config.dns.analyzeOnlyAandAAAA | bool | `false` | Only analyze A and AAAA DNS queries |
| config.dns.blockESNI | bool | `true` | Block _esni. subdomains to enhance privacy by preventing Encrypted Server Name Indication abuse |
| config.dns.blockTTL | int | `2` | TTL (in seconds) for blocked queries |
| config.dns.blocking.active | bool | `true` | Enable DNS query blocking |
| config.dns.blocking.edns | string | `"TEXT"` | Enrich blocked replies with EDNS0 information. Options: "NONE", "CODE", "TEXT" |
| config.dns.blocking.mode | string | `"NULL"` | Reply mode for blocked queries. Options: "NULL", "IP_NODATA_AAAA", "IP", "NX", "NODATA" |
| config.dns.bogusPriv | bool | `true` | Answer with NXDOMAIN for reverse lookups of private IP ranges not found locally |
| config.dns.cache.optimizer | int | `3600` | Query cache optimizer: serve stale cache data for recently expired entries to improve DNS query delays |
| config.dns.cache.size | int | `10000` | DNS cache size in entries |
| config.dns.cache.upstreamBlockedTTL | int | `86400` | TTL (in seconds) for queries blocked upstream before checking again |
| config.dns.cnameDeepInspect | bool | `true` | Enable deep CNAME inspection for enhanced DNS resolution |
| config.dns.cnameRecords | list | `[]` | Custom CNAME records, in HOSTNAME ALIAS format like: "alias.domain.com original.domain.com" |
| config.dns.dnssec | bool | `false` | Validate DNS replies using DNSSEC |
| config.dns.domain.local | bool | `true` | Treat configured domain as local and never forward upstream |
| config.dns.domain.name | string | `"lan"` | Local DNS domain used by Pi-hole |
| config.dns.domainNeeded | bool | `true` | Never forward plain names (without dots) to upstream nameservers |
| config.dns.edns0ECS | bool | `true` | Allow Pi-hole to obtain client IPs behind NAT using EDNS0 client subnet (ECS) information |
| config.dns.expandHosts | bool | `true` | Add domain suffix to simple names in /etc/hosts |
| config.dns.hostRecord | string | `""` | Hostname record to add to DNS with associated A, AAAA and PTR records |
| config.dns.hosts | list | `[]` | Custom DNS records in hosts format (IP HOSTNAME) like: 192.168.1.100 pihole.example.com |
| config.dns.ignoreLocalhost | bool | `false` | Hide queries made by localhost from logging |
| config.dns.interface | string | `"eth0"` | Network interface to use for DNS and DHCP. Leave empty for auto-detection |
| config.dns.listeningMode | string | `"LOCAL"` | DNS listening mode. Options: "LOCAL", "SINGLE", "BIND", "ALL", "NONE" |
| config.dns.localise | bool | `true` | Localize queries to return all possible values for local DNS records |
| config.dns.piholePTR | string | `"PI.HOLE"` | How Pi-hole responds to PTR requests for local interface addresses. Options: "NONE", "HOSTNAME", "HOSTNAMEFQDN", "PI.HOLE" |
| config.dns.port | int | `53` | Port used by the DNS server |
| config.dns.queryLogging | bool | `true` | Log DNS queries and replies |
| config.dns.rateLimit.count | int | `1000` | Maximum number of DNS queries allowed per client within the interval |
| config.dns.rateLimit.interval | int | `60` | Time interval (in seconds) for rate limiting |
| config.dns.reply.blocking.force4 | bool | `false` | Force a specific IPv4 address in IP blocking mode |
| config.dns.reply.blocking.force6 | bool | `false` | Force a specific IPv6 address in IP blocking mode |
| config.dns.reply.blocking.ipv4 | string | `""` | Custom IPv4 address for IP blocking mode (leave empty for auto) |
| config.dns.reply.blocking.ipv6 | string | `""` | Custom IPv6 address for IP blocking mode (leave empty for auto) |
| config.dns.reply.host.force4 | bool | `false` | Force a specific IPv4 address for pi.hole and hostname responses |
| config.dns.reply.host.force6 | bool | `false` | Force a specific IPv6 address for pi.hole and hostname responses |
| config.dns.reply.host.ipv4 | string | `""` | Custom IPv4 address for Pi-hole host (leave empty for auto) |
| config.dns.reply.host.ipv6 | string | `""` | Custom IPv6 address for Pi-hole host (leave empty for auto) |
| config.dns.replyWhenBusy | string | `"ALLOW"` | How to handle queries when the gravity database is unavailable. Options: "BLOCK", "ALLOW", "REFUSE", "DROP" |
| config.dns.revServers | list | `[]` | Reverse servers (conditional forwarding) for local network domain resolution |
| config.dns.showDNSSEC | bool | `true` | Show internally generated DNSSEC queries in analytics |
| config.dns.specialDomains.designatedResolver | bool | `true` | Block resolver.arpa to prevent Discovery of Designated Resolvers bypass |
| config.dns.specialDomains.iCloudPrivateRelay | bool | `true` | Block iCloud Private Relay domains to prevent Apple devices from bypassing Pi-hole |
| config.dns.specialDomains.mozillaCanary | bool | `true` | Block use-application-dns.net to disable Firefox DNS-over-HTTP |
| config.dns.upstreams | list | `["8.8.8.8","8.8.4.4"]` | Upstream DNS servers to be used by Pi-hole for resolving non-local queries |
| config.files | object | `{"database":"/etc/pihole/pihole-FTL.db","gravity":"/etc/pihole/gravity.db","gravityTmp":"/tmp","log":{"dnsmasq":"/var/log/pihole/pihole.log","ftl":"/var/log/pihole/FTL.log","webserver":"/var/log/pihole/webserver.log"},"macvendor":"/etc/pihole/macvendor.db","pcap":"","pid":"/run/pihole-FTL.pid"}` | File paths configuration |
| config.files.database | string | `"/etc/pihole/pihole-FTL.db"` | Path to FTL's long-term database |
| config.files.gravity | string | `"/etc/pihole/gravity.db"` | Path to Pi-hole's gravity database |
| config.files.gravityTmp | string | `"/tmp"` | Temporary directory for gravity updates (must be world-writable) |
| config.files.log.dnsmasq | string | `"/var/log/pihole/pihole.log"` | Path to dnsmasq DNS server log file |
| config.files.log.ftl | string | `"/var/log/pihole/FTL.log"` | Path to FTL log file |
| config.files.log.webserver | string | `"/var/log/pihole/webserver.log"` | Path to web server log file |
| config.files.macvendor | string | `"/etc/pihole/macvendor.db"` | Path to MAC vendor information database |
| config.files.pcap | string | `""` | Optional PCAP file for debugging network traffic (empty to disable) |
| config.files.pid | string | `"/run/pihole-FTL.pid"` | Path to Pi-hole FTL PID file |
| config.misc | object | `{"addr2line":true,"check":{"disk":90,"load":true,"shmem":90},"delayStartup":0,"dnsmasqLines":["address=/local.rubenclaessens.nl/192.168.1.2"],"etcDnsmasqD":false,"extraLogging":false,"hideDnsmasqWarn":false,"nice":-10,"normalizeCPU":true,"privacyLevel":0,"readOnly":false}` | Miscellaneous settings |
| config.misc.addr2line | bool | `true` | Translate stack addresses to code lines during bug backtrace |
| config.misc.check.disk | int | `90` | Warn if disk usage exceeds percentage threshold (0 to disable) |
| config.misc.check.load | bool | `true` | Check system load and warn if it exceeds number of cores |
| config.misc.check.shmem | int | `90` | Warn if shared memory usage exceeds percentage threshold (0 to disable) |
| config.misc.delayStartup | int | `0` | Delay startup to allow late network interfaces to initialize (in seconds, 0-300) |
| config.misc.dnsmasqLines | list | `["address=/local.rubenclaessens.nl/192.168.1.2"]` | Additional dnsmasq configuration lines to inject |
| config.misc.etcDnsmasqD | bool | `false` | Load additional dnsmasq configuration from /etc/dnsmasq.d/ (use with caution) |
| config.misc.extraLogging | bool | `false` | Log extra information about queries and replies |
| config.misc.hideDnsmasqWarn | bool | `false` | Hide warnings from dnsmasq |
| config.misc.nice | int | `-10` | Process niceness for CPU scheduler (-20 to 19, or -999 to disable) |
| config.misc.normalizeCPU | bool | `true` | Normalize CPU usage by number of cores for more intuitive percentage values |
| config.misc.privacyLevel | int | `0` | Privacy level for statistics. 0=all, 1=hide domains, 2=hide domains+clients, 3=anonymize everything |
| config.misc.readOnly | bool | `false` | Put configuration into read-only mode (prevent changes via API/CLI) |
| config.ntp | object | `{"ipv4":{"active":true,"address":""},"ipv6":{"active":true,"address":""},"sync":{"active":true,"count":8,"interval":3600,"rtc":{"device":"","set":false,"utc":true},"server":"pool.ntp.org"}}` | NTP (Network Time Protocol) server configuration |
| config.ntp.ipv4.active | bool | `true` | Enable NTP server for IPv4 |
| config.ntp.ipv4.address | string | `""` | IPv4 address to listen on for NTP requests (empty for wildcard 0.0.0.0) |
| config.ntp.ipv6.active | bool | `true` | Enable NTP server for IPv6 |
| config.ntp.ipv6.address | string | `""` | IPv6 address to listen on for NTP requests (empty for wildcard ::) |
| config.ntp.sync.active | bool | `true` | Enable NTP time synchronization with upstream NTP server |
| config.ntp.sync.count | int | `8` | Number of NTP syncs to average before updating system time |
| config.ntp.sync.interval | int | `3600` | Interval (in seconds) between NTP synchronization attempts (0 to disable) |
| config.ntp.sync.rtc.device | string | `""` | Path to RTC device (empty for auto-discovery) |
| config.ntp.sync.rtc.set | bool | `false` | Update system's real-time clock (RTC) if available |
| config.ntp.sync.rtc.utc | bool | `true` | Set RTC to UTC timezone |
| config.ntp.sync.server | string | `"pool.ntp.org"` | Upstream NTP server to synchronize with |
| config.resolver | object | `{"networkNames":true,"refreshNames":"IPV4_ONLY","resolveIPv4":true,"resolveIPv6":true}` | Hostname and IP resolution configuration |
| config.resolver.networkNames | bool | `true` | Use fallback to network table for client name resolution |
| config.resolver.refreshNames | string | `"IPV4_ONLY"` | Frequency of PTR lookups for hostname refresh. Options: "IPV4_ONLY", "ALL", "UNKNOWN", "NONE" |
| config.resolver.resolveIPv4 | bool | `true` | Resolve IPv4 addresses to hostnames |
| config.resolver.resolveIPv6 | bool | `true` | Resolve IPv6 addresses to hostnames |
| config.webserver | object | `{"acl":"","advancedOpts":[],"api":{"allowDestructive":true,"appPwhash":"","appSudo":false,"cliPw":true,"clientHistoryGlobalMax":true,"excludeClients":[],"excludeDomains":[],"maxClients":10,"maxHistory":86400,"maxSessions":16,"prettyJSON":false,"pwhash":"","temp":{"limit":60,"unit":"C"},"totpSecret":""},"domain":"pi.hole","headers":["X-DNS-Prefetch-Control: off","Content-Security-Policy: default-src 'self' 'unsafe-inline';","X-Frame-Options: DENY","X-XSS-Protection: 0","X-Content-Type-Options: nosniff","Referrer-Policy: strict-origin-when-cross-origin"],"interface":{"boxed":true,"theme":"default-auto"},"paths":{"prefix":"","webhome":"/admin/","webroot":"/var/www/html"},"port":"80o,443os,[::]:80o,[::]:443os","serveAll":false,"session":{"restore":true,"timeout":1800},"threads":50,"tls":{"cert":"/etc/pihole/tls.pem","validity":47}}` | Web server and API configuration |
| config.webserver.acl | string | `""` | Web server ACL for IP address restrictions (empty = allow all) |
| config.webserver.advancedOpts | list | `[]` | Advanced CivetWeb options passed directly to web server |
| config.webserver.api.allowDestructive | bool | `true` | Allow destructive API calls (restart, flush logs, etc.) |
| config.webserver.api.appPwhash | string | `""` | Application password hash for services that don't support 2FA |
| config.webserver.api.appSudo | bool | `false` | Allow app passwords to modify configuration settings |
| config.webserver.api.cliPw | bool | `true` | Create temporary CLI password for authentication |
| config.webserver.api.clientHistoryGlobalMax | bool | `true` | Compute most active clients globally vs per time slot |
| config.webserver.api.excludeClients | list | `[]` | Regex array of clients excluded from API responses (Query Log, Top Clients) |
| config.webserver.api.excludeDomains | list | `[]` | Regex array of domains excluded from API responses (Query Log, Top Domains) |
| config.webserver.api.maxClients | int | `10` | Maximum number of clients to return in activity graph endpoint |
| config.webserver.api.maxHistory | int | `86400` | History duration to import from database and return by API (in seconds, max 86400) |
| config.webserver.api.maxSessions | int | `16` | Maximum number of concurrent API sessions |
| config.webserver.api.prettyJSON | bool | `false` | Prettify API JSON output with extra spacing and indentation |
| config.webserver.api.pwhash | string | `""` | API password hash |
| config.webserver.api.temp.limit | float | `60` | Upper temperature limit before showing as "hot" |
| config.webserver.api.temp.unit | string | `"C"` | Temperature unit. Options: "C" (Celsius), "F" (Fahrenheit), "K" (Kelvin) |
| config.webserver.api.totpSecret | string | `""` | 2FA TOTP secret (20 Bytes Base32). Setting this enables 2FA for API and web interface |
| config.webserver.domain | string | `"pi.hole"` | Domain on which the web interface is served |
| config.webserver.headers | list | `["X-DNS-Prefetch-Control: off","Content-Security-Policy: default-src 'self' 'unsafe-inline';","X-Frame-Options: DENY","X-XSS-Protection: 0","X-Content-Type-Options: nosniff","Referrer-Policy: strict-origin-when-cross-origin"]` | Additional HTTP headers added to web server responses |
| config.webserver.interface.boxed | bool | `true` | Use boxed layout for web interface |
| config.webserver.interface.theme | string | `"default-auto"` | Web interface theme. Options: "default-auto", "default-light", "default-dark", "default-darker", "high-contrast", "high-contrast-dark", "lcars" |
| config.webserver.paths.prefix | string | `""` | URL prefix for reverse proxy (e.g., "/pihole" for http://<ip>/pihole/admin/) |
| config.webserver.paths.webhome | string | `"/admin/"` | Sub-directory containing the web interface (requires leading and trailing slashes) |
| config.webserver.paths.webroot | string | `"/var/www/html"` | Server root directory |
| config.webserver.port | string | `"80o,443os,[::]:80o,[::]:443os"` | Ports to listen on (e.g., "80,443s,[::]:80,[::]:443s"). Append 's' for SSL, 'r' for redirect, 'o' for optional |
| config.webserver.serveAll | bool | `false` | Serve all files in webroot directory (vs only webhome and API) |
| config.webserver.session.restore | bool | `true` | Backup and restore sessions from database across restarts |
| config.webserver.session.timeout | int | `1800` | Session timeout in seconds |
| config.webserver.threads | int | `50` | Maximum number of concurrent worker threads |
| config.webserver.tls.cert | string | `"/etc/pihole/tls.pem"` | Path to TLS certificate file in PEM format |
| config.webserver.tls.validity | int | `47` | Validity period for auto-generated self-signed TLS certificates (in days) |
| image | object | `{"repository":"pihole/pihole","tag":"2025.11.1"}` | A list of additional adlists to be included fetched by pi-hole. |
| replicaCount | int | `1` |  |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
