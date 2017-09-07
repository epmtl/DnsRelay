# DNS Relay
---

## Context

- Sometimes you need full DNS resolution (both Internal and external to a company).
- Unfortunately, security rules usually prevent external resolution (e.g. x.y.example.com can be resolved but not example2.com).  
- In parallel, you usually have an HTTP proxy that filters internet access but allow major websites (e.g. www.google.com).

Thus, one solution is to use the later to cover the external domains with the help of google DNS API.


## Installation

- Clone the repository on your system (in /opt/dnsrelay for example)
- Change the settings at the top of the dns_relay.py according to your environment:

>     # SYSTEM SPECIFIC
>     local_dns_port = 10053
>     local_dns_address = ""  # "" by default = "0.0.0.0"
>     # ENVIRONMENT SPECIFIC
>     external_https_proxy_address = "proxy.example.com"
>     external_https_proxy_port = 8080
>     internal_dns_port = 53
>     internal_dns_address = "10.0.0.1"
>     internal_honeypot = "10.0.0.2"
    
- To install it as a service on Ubuntu:
    - change the parameters as you want in dns_relay.service (file is setup to start in /opt/dnsrelay/)
    - as root, put dns_relay.service in /etc/systemd/system/dns_relay.service.
    - you can do the following commands to install the service:
>     # sudo systemctl enable dns_relay.service
>     # sudo systemctl daemon-reload
>     # sudo systemctl start dns_relay.service


## Compatibility
This app has been tested with the following :
- Ubuntu 16.04
- Python v3.5
- dnslib 0.9.7

## Limitations
No support yet for:
- DNS answer with CNAME, MX, NS, SOA, TXT from google
- Reverse resolution

## Thanks
- to samuelcolvin (https://github.com/samuelcolvin/dnserver) for his implementation that helped me start.