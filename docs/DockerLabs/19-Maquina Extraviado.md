Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #base64 #password-reuse #riddle

![](assets/Pasted%20image%2020251111230145.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=2.44 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 2.441/2.441/2.441/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> nmap -p- --open -sS -n -Pn --min-rate 5000 172.17.0.2
---------------------------------------------------------
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 3A:DD:05:B2:4F:BB (Unknown)
```

- Puertos 22 y 80 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo más profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> nmap -p 80,22 -sS -sC -sV -Pn -n --min-rate 5000 172.17.0.2 -oN target.txt
-------------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 cc:d2:9b:60:14:16:27:b3:b9:f8:79:10:df:a1:f3:24 (ECDSA)
|_  256 37:a2:b2:b2:26:f2:07:d1:83:7a:ff:98:8d:91:77:37 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 3A:DD:05:B2:4F:BB (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH OpenSSH 9.6p1 Ubuntu 3ubuntu13.5
- Puerto 80 HTTP Apache httpd 2.4.58

## Enumeración

### Puerto 80 HTTP

La página principal muestra la página por defecto de Apache2. Al final de la página encuentro una cadena codificada.

```
#.........................................................................................................ZGFuaWVsYQ== : Zm9jYXJvamE=
```

![](assets/Pasted%20image%2020251111223116.png)

La cadena parece estar codificada en Base64. Utilizo Burp Suite para decodificarla.

![](assets/Pasted%20image%2020251111223301.png)

- Credenciales decodificadas: `daniela:focaroja`

### Acceso SSH

Me conecto por SSH con las credenciales encontradas.

```bash
> ssh daniela@172.17.0.2
daniela@172.17.0.2's password: focaroja
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.12.32-amd64 x86_64)

daniela@dockerlabs:~$ whoami
daniela
daniela@dockerlabs:~$ id
uid=1000(daniela) gid=1000(daniela) groups=1000(daniela)
```

![](assets/Pasted%20image%2020251111223633.png)

## Escalada de Privilegios

### Migración al usuario diego

Dentro del sistema enumero el contenido del directorio home.

```bash
> daniela@dockerlabs:~$ ls -la
total 12
drwxr-x--- 1 daniela daniela   12 Nov 11 21:34 .
drwxr-xr-x 1 root    root      14 Jan  9  2025 ..
-rw-r--r-- 1 daniela daniela  220 Jan  9  2025 .bash_logout
-rw-r--r-- 1 daniela daniela 3771 Jan  9  2025 .bashrc
drwx------ 1 daniela daniela   40 Nov 11 21:34 .cache
drwxrwxr-x 1 daniela daniela   10 Jan  9  2025 .local
-rw-r--r-- 1 daniela daniela  807 Jan  9  2025 .profile
drwxrwxr-x 1 daniela daniela   18 Jan  9  2025 .secreto
drwxrwxr-x 1 daniela daniela    8 Jan  9  2025 Desktop
```

- Encuentro un directorio oculto `.secreto`

Dentro del directorio encuentro un archivo llamado `passdiego`.

![](assets/Pasted%20image%2020251111223755.png)

La contraseña parece estar codificada en Base64. La decodifico.

```bash
> echo "YmFsbGVuYW5lZ3Jh" | base64 -d; echo
----------------------------------------------
ballenanegra
```

- Credenciales: `diego:ballenanegra`

Migro al usuario `diego`.

```bash
> daniela@dockerlabs:~$ su diego
Password: ballenanegra
diego@dockerlabs:/home/daniela$ whoami
diego
```

### Escalada a Root gracias a chat gpt

Después de explorar el sistema como `diego`, encuentro un archivo llamado `.-` en el directorio `~/.local/share`.

```bash
> diego@dockerlabs:~/.local/share$ ls -la
--------------------------------------------------
total 4
-rw-r--r-- 1 root  root  319 Jan 11  2025 .-
------------------------------------------------------
diego@dockerlabs:~/.local/share$ cat .-
----------------------------------------------------------
password de root

En un mundo de hielo, me muevo sin prisa,
con un pelaje que brilla, como la brisa.
No soy un rey, pero en cuentos soy fiel,
de un color inusual, como el cielo y el mar
tambien.
Soy amigo de los niños, en historias de
ensueño.
Quien soy, que en el frio encuentro mi dueño?
```

El archivo es un acertijo y, como honestamente no tenía idea de la respuesta, decidí preguntarle a ChatGPT a qué animal podría referirse.

ChatGPT me indico que se trataba de un "oso polar azul" por lo cual simplemente intente variaciones y finalmente di con `osoazul`



```bash
> diego@dockerlabs:~/.local/share$ su root
Password: osoazul
root@dockerlabs:/home/diego/.local/share# whoami
root
root@dockerlabs:/home/diego/.local/share# id
uid=0(root) gid=0(root) groups=0(root)
```

![](assets/Pasted%20image%2020251111225700.png)

***PWNED***