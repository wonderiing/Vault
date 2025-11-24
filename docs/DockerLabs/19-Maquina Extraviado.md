Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #dockerlabs #ssh #chatgpt

![](../assets/Pasted image 20251111230145.png)
## Reconocimiento

Comienzo con un ping para comprobar conectividad:
```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=2.44 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 2.441/2.441/2.441/0.000 ms
```

Realizo un escaneo con nmap para ver que puertos están abiertos:
```bash
> nmap -p- --open -sS -n -Pn --min-rate 5000 172.17.0.2
---------------------------------------------------------
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 3A:DD:05:B2:4F:BB (Unknown)
```
- Puerto 80 HTTP y 22 SSH.

Realizo un segundo escaneo sobre los puertos abiertos para ver que versiones y servicios están corriendo.
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
- Puerto 22 SSH: OpenSSH 9.6p1 Ubuntu 3ubuntu13.5
- Puerto 80 HTTP: Apache httpd 2.4.58

## Enumeración

**Puerto 80 HTTP**
- Pagina default de apache2. Al final de la pagina esta esta cadena:
` #.........................................................................................................ZGFuaWVsYQ== : Zm9jYXJvamE= `

![](../assets/Pasted image 20251111223116.png)


Al Parecer es una cadena codificada en base64, por lo cual procedo a decodificarla con burpsuite
![](../assets/Pasted image 20251111223301.png)
- Al parecer son credenciales, supongo que para el ssh daniela:focaroja

Me conecto por SSH
```
> ssh daniela@172.17.0.2
```

![](../assets/Pasted image 20251111223633.png)

## Escalada de Privilegios

Dentro del sistema lo primero que hago es listar los recursos
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
- Aquí es donde veo la carpeta .secreto

En esta carpeta se encuentra un archivo llamado _passdiego_ que supongo que serán las credenciales para el usuario diego
![](../assets/Pasted image 20251111223755.png)

La contraseña al parecer esta codificada en base64 por lo cual procedo a decodificarla

```bash
> echo "YmFsbGVuYW5lZ3Jh" | base64 -d; echo
----------------------------------------------
ballenanegra
```
- Credenciales son diego:ballenanegra

Al migrar al usuario diego y después de buscar bastante me encuentro con este archivo llamado ".-" en la carpeta /.local/share :
- Al parecer es un acertijo del cual no tengo ni idea
```bash
>diego@dockerlabs:~/.local/share$ ls -la
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
Soy amigo de los ni~nos, en historias de
ensue~no.
Quien soy, que en el frio encuentro mi due~no?

```

Después de preguntarle a mi mejor amigo chatgpt que piensa el me dice esto:
_Mi lectura: **un oso polar (más concretamente: un oso de peluche polar azul)**._

Después de varios intentos logro logarme con la contraseña osoazul

![](../assets/Pasted image 20251111225700.png)

***PWNED**